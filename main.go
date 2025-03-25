package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

// CiliumClusterwideNetworkPolicy represents the Cilium policy
type CiliumClusterwideNetworkPolicy struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Description  string                 `yaml:"description,omitempty"`
		NodeSelector map[string]interface{} `yaml:"nodeSelector,omitempty"`
		Ingress      []IngressRule          `yaml:"ingress,omitempty"`
		Egress       []EgressRule           `yaml:"egress,omitempty"`
		IngressDeny  []IngressRule          `yaml:"ingressDeny,omitempty"`
		EgressDeny   []EgressRule           `yaml:"egressDeny,omitempty"`
	} `yaml:"spec"`
}

// IngressRule represents a Cilium ingress rule
type IngressRule struct {
	FromEntities []string   `yaml:"fromEntities,omitempty"`
	FromCIDRs    []string   `yaml:"fromCIDRs,omitempty"`
	ToPorts      []PortRule `yaml:"toPorts,omitempty"`
	ICMPs        []ICMPRule `yaml:"icmps,omitempty"`
}

// EgressRule represents a Cilium egress rule
type EgressRule struct {
	ToEntities []string   `yaml:"toEntities,omitempty"`
	ToCIDRs    []string   `yaml:"toCIDRs,omitempty"`
	ToPorts    []PortRule `yaml:"toPorts,omitempty"`
	ICMPs      []ICMPRule `yaml:"icmps,omitempty"`
}

// PortRule represents allowed ports
type PortRule struct {
	Ports []PortProtocol `yaml:"ports,omitempty"`
}

// PortProtocol represents a port and protocol combination
type PortProtocol struct {
	Port     string `yaml:"port"`
	Protocol string `yaml:"protocol"`
}

// ICMPRule represents an ICMP rule
type ICMPRule struct {
	Type int `yaml:"type"`
}

// IPTablesRule represents a parsed iptables rule
type IPTablesRule struct {
	Chain       string
	Action      string
	Protocol    string
	SrcIP       string
	DstIP       string
	Interface   string
	DstPort     string
	SrcPort     string
	ICMPType    int
	Established bool
}

var (
	defaultDrop     = map[string]bool{}
	includePolicies = map[string]bool{
		"ssh":            true,
		"kubernetes-api": true,
		"dns":            true,
		"etcd":           true,
		"kubelet":        true,
	}
)

func printUsage() {
	fmt.Println(`iptables-to-cilium - Convert iptables rules to Cilium Host Firewall Policies

USAGE:
  iptables-to-cilium [options]

OPTIONS:`)
	flag.PrintDefaults()
	fmt.Printf(`
EXAMPLES:
  # Convert rules from iptables-save output
  iptables-save | iptables-to-cilium > cilium-policy.yaml

  # Use a saved iptables file
  iptables-to-cilium --input iptables-rules.txt --output cilium-policy.yaml

  # Specify a node selector to apply policy only to certain nodes
  iptables-to-cilium --node-selector kubernetes.io/hostname=worker1 --input iptables-rules.txt

  # Include only specific essential policies
  iptables-to-cilium --include-policy ssh,dns --input iptables-rules.txt
`)
}

func main() {
	inputFile := flag.String("input", "", "Input file path (iptables-save output). If not provided, reads from stdin.")
	outputFile := flag.String("output", "", "Output file path. If not provided, outputs to stdout.")
	policyName := flag.String("name", "host-firewall-policy", "Name for the Cilium policy.")
	nodeSelectorLabel := flag.String("node-selector", "", "Node selector label (format: key=value). If not provided, policy applies to all nodes.")
	includePolicyFlags := flag.String("include-policy", "ssh,kubernetes-api,dns", "Comma-separated list of essential policies to include: ssh,kubernetes-api,dns,etcd,kubelet")
	skipEssential := flag.Bool("skip-essential", false, "Skip adding essential policies even if INPUT is DROP")
	verbose := flag.Bool("verbose", false, "Enable verbose output for debugging")
	helpFlag := flag.Bool("help", false, "Show help")

	flag.Parse()

	if *helpFlag {
		printUsage()
		return
	}

	// Parse includePolicyFlags
	if *includePolicyFlags != "" {
		includePolicies = map[string]bool{}
		for _, policy := range strings.Split(*includePolicyFlags, ",") {
			includePolicies[strings.TrimSpace(policy)] = true
		}
	}

	if *verbose {
		fmt.Fprintf(os.Stderr, "Include policies: %v\n", includePolicies)
	}

	var input io.Reader
	if *inputFile == "" {
		// Try to execute iptables-save if no input file
		cmd := exec.Command("iptables-save")
		output, err := cmd.StdoutPipe()
		if err == nil {
			err = cmd.Start()
			if err == nil {
				input = output
				if *verbose {
					fmt.Fprintf(os.Stderr, "Successfully launched iptables-save\n")
				}
			} else {
				fmt.Fprintf(os.Stderr, "Error running iptables-save: %v\n", err)
				input = os.Stdin
				fmt.Println("Please provide iptables-save output via stdin:")
			}
		} else {
			fmt.Fprintf(os.Stderr, "Error setting up iptables-save: %v\n", err)
			input = os.Stdin
			fmt.Println("Please provide iptables-save output via stdin:")
		}
	} else {
		file, err := os.Open(*inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening input file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		input = file
	}

	rules, err := parseIPTablesRules(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing iptables rules: %v\n", err)
		os.Exit(1)
	}

	if *verbose {
		fmt.Fprintf(os.Stderr, "Parsed %d iptables rules\n", len(rules))

		// Print default policies
		fmt.Fprintf(os.Stderr, "Default policies:\n")
		for chain, isDrop := range defaultDrop {
			fmt.Fprintf(os.Stderr, "  %s: %s\n", chain, map[bool]string{true: "DROP", false: "ACCEPT"}[isDrop])
		}
	}

	policy := createCiliumPolicy(rules, *policyName, *nodeSelectorLabel)

	// Add essential policies
	if !defaultDrop["INPUT"] {
		// If the INPUT chain isn't set to DROP in iptables, we don't need to add essential ingress policies
		// since the default in Cilium without any rules would also be ACCEPT
		fmt.Fprintln(os.Stderr, "Note: INPUT chain is not set to DROP, skipping essential ingress policies")
	} else if !*skipEssential {
		addEssentialPolicies(&policy)
	} else {
		fmt.Fprintln(os.Stderr, "Warning: Skipping essential policies due to --skip-essential flag")
	}

	// Convert to YAML
	yamlData, err := yaml.Marshal(policy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling YAML: %v\n", err)
		os.Exit(1)
	}

	// Add comments for skipped rules
	output := fmt.Sprintf("# Generated by iptables-to-cilium on %s\n# Default policies: INPUT=%v, OUTPUT=%v\n# Warning: Always review this policy before applying it to production clusters\n%s",
		time.Now().Format("2006-01-02 15:04:05"),
		getDefaultPolicyStr("INPUT"), getDefaultPolicyStr("OUTPUT"), yamlData)

	// Output
	if *outputFile == "" {
		fmt.Print(output)
	} else {
		err = os.WriteFile(*outputFile, []byte(output), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Policy written to %s\n", *outputFile)
	}
}

func getDefaultPolicyStr(chain string) string {
	if defaultDrop[chain] {
		return "DROP"
	}
	return "ACCEPT"
}

func parseIPTablesRules(r io.Reader) ([]IPTablesRule, error) {
	var rules []IPTablesRule
	scanner := bufio.NewScanner(r)
	inFilterTable := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Track when we enter/exit the filter table
		if line == "*filter" {
			inFilterTable = true
			continue
		} else if strings.HasPrefix(line, "*") {
			inFilterTable = false
			continue
		} else if strings.HasPrefix(line, "COMMIT") {
			inFilterTable = false
			continue
		}

		// Only process the filter table
		if !inFilterTable {
			continue
		}

		// Check if line defines default policy
		if strings.HasPrefix(line, ":") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				chainName := strings.TrimPrefix(parts[0], ":")
				policy := parts[1]
				if policy == "DROP" {
					defaultDrop[chainName] = true
				}
			}
			continue
		}

		// Parse rule
		if strings.HasPrefix(line, "-A ") {
			rule, err := parseRule(line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Could not parse rule %s: %v\n", line, err)
				continue
			}
			if rule != nil {
				rules = append(rules, *rule)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return rules, nil
}

func parseRule(line string) (*IPTablesRule, error) {
	rule := &IPTablesRule{}

	// Debug log line for troubleshooting
	// fmt.Fprintf(os.Stderr, "Parsing rule: %s\n", line)

	// Example: -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
	parts := strings.Fields(line)
	if len(parts) < 4 {
		return nil, fmt.Errorf("rule too short")
	}

	// Get chain
	if parts[0] == "-A" {
		rule.Chain = parts[1]
	} else {
		return nil, fmt.Errorf("expected -A, got %s", parts[0])
	}

	// Only process INPUT and OUTPUT chains
	if rule.Chain != "INPUT" && rule.Chain != "OUTPUT" {
		return nil, nil
	}

	// Get action (last part)
	for i := 0; i < len(parts); i++ {
		if parts[i] == "-j" && i+1 < len(parts) {
			rule.Action = parts[i+1]
			break
		}
	}

	// Get protocol
	for i := 0; i < len(parts); i++ {
		if parts[i] == "-p" && i+1 < len(parts) {
			rule.Protocol = parts[i+1]
		}
	}

	// Get source IP
	for i := 0; i < len(parts); i++ {
		if parts[i] == "-s" && i+1 < len(parts) {
			rule.SrcIP = parts[i+1]
		}
	}

	// Get destination IP
	for i := 0; i < len(parts); i++ {
		if parts[i] == "-d" && i+1 < len(parts) {
			rule.DstIP = parts[i+1]
		}
	}

	// Get interface
	for i := 0; i < len(parts); i++ {
		if (parts[i] == "-i" || parts[i] == "-o") && i+1 < len(parts) {
			rule.Interface = parts[i+1]
		}
	}

	// Get destination port
	for i := 0; i < len(parts); i++ {
		if i+1 < len(parts) {
			if parts[i] == "--dport" || (parts[i] == "--destination-port") {
				rule.DstPort = parts[i+1]
			} else if strings.Contains(line, "--dports") && parts[i] == "--dports" {
				rule.DstPort = parts[i+1] // Handle multi-port
			}
		}
	}

	// Get source port
	for i := 0; i < len(parts); i++ {
		if i+1 < len(parts) {
			if parts[i] == "--sport" || (parts[i] == "--source-port") {
				rule.SrcPort = parts[i+1]
			}
		}
	}

	// Check for ICMP type
	if rule.Protocol == "icmp" {
		for i := 0; i < len(parts); i++ {
			if parts[i] == "--icmp-type" && i+1 < len(parts) {
				icmpType, err := strconv.Atoi(parts[i+1])
				if err == nil {
					rule.ICMPType = icmpType
				}
			}
		}
	}

	// Check for established connections
	if strings.Contains(line, "ESTABLISHED") || strings.Contains(line, "RELATED") {
		rule.Established = true
	}

	return rule, nil
}

func createCiliumPolicy(rules []IPTablesRule, name string, nodeSelector string) CiliumClusterwideNetworkPolicy {
	policy := CiliumClusterwideNetworkPolicy{
		APIVersion: "cilium.io/v2",
		Kind:       "CiliumClusterwideNetworkPolicy",
	}

	policy.Metadata.Name = name

	// Add a description for better clarity
	policy.Spec.Description = "Generated by iptables-to-cilium from iptables rules"

	// Set node selector if provided
	policy.Spec.NodeSelector = map[string]interface{}{}
	if nodeSelector != "" {
		parts := strings.Split(nodeSelector, "=")
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			policy.Spec.NodeSelector = map[string]interface{}{
				"matchLabels": map[string]string{
					key: value,
				},
			}
		}
	}

	// Process rules for INPUT chain (ingress)
	processIngressRules(rules, &policy)

	// Process rules for OUTPUT chain (egress)
	processEgressRules(rules, &policy)

	return policy
}

func processIngressRules(rules []IPTablesRule, policy *CiliumClusterwideNetworkPolicy) {
	// Add ingressRules for accept actions
	var ingressRules []IngressRule
	var ingressDenyRules []IngressRule

	acceptPorts := make(map[string]map[string]bool) // protocol -> port -> true
	denyPorts := make(map[string]map[string]bool)   // protocol -> port -> true

	acceptCIDRs := make(map[string]bool) // cidr -> true
	denyCIDRs := make(map[string]bool)   // cidr -> true

	icmpTypes := make(map[int]bool)     // icmpType -> true
	denyICMPTypes := make(map[int]bool) // icmpType -> true

	// First, organize all the allowed and denied ports, CIDRs, and ICMP types
	for _, rule := range rules {
		if rule.Chain != "INPUT" {
			continue
		}

		// Established connections are handled automatically by Cilium's stateful firewall
		if rule.Established {
			continue
		}

		// Process the rule based on action
		if rule.Action == "ACCEPT" {
			// Allow loopback interface (handled separately)
			if rule.Interface == "lo" {
				continue // Loopback is handled automatically in Cilium
			}

			// Handle ICMP
			if rule.Protocol == "icmp" {
				if rule.ICMPType != 0 {
					icmpTypes[rule.ICMPType] = true
				} else {
					// Allow all ICMP types if not specified
					icmpTypes[-1] = true // -1 means all types
				}
				continue
			}

			// Handle source CIDRs
			if rule.SrcIP != "" {
				acceptCIDRs[rule.SrcIP] = true
			}

			// Handle port rules
			if rule.Protocol == "tcp" || rule.Protocol == "udp" {
				if rule.DstPort != "" {
					if _, ok := acceptPorts[rule.Protocol]; !ok {
						acceptPorts[rule.Protocol] = make(map[string]bool)
					}
					if strings.Contains(rule.DstPort, ",") {
						// Handle multi-port
						for _, port := range strings.Split(rule.DstPort, ",") {
							acceptPorts[rule.Protocol][port] = true
						}
					} else if strings.Contains(rule.DstPort, ":") {
						// Handle port range, e.g., 1000:2000
						parts := strings.Split(rule.DstPort, ":")
						if len(parts) == 2 {
							start, err1 := strconv.Atoi(parts[0])
							end, err2 := strconv.Atoi(parts[1])
							if err1 == nil && err2 == nil && start <= end {
								// Convert range to individual ports
								// For simplicity, we'll convert small ranges to individual ports
								if end-start < 100 {
									for i := start; i <= end; i++ {
										acceptPorts[rule.Protocol][strconv.Itoa(i)] = true
									}
								} else {
									// For large ranges, use the range format directly
									acceptPorts[rule.Protocol][rule.DstPort] = true
								}
							}
						}
					} else {
						acceptPorts[rule.Protocol][rule.DstPort] = true
					}
				} else {
					// Allow all ports for this protocol
					if _, ok := acceptPorts[rule.Protocol]; !ok {
						acceptPorts[rule.Protocol] = make(map[string]bool)
					}
					acceptPorts[rule.Protocol][""] = true // Empty string means all ports
				}
			}
		} else if rule.Action == "DROP" || rule.Action == "REJECT" {
			// Handle ICMP
			if rule.Protocol == "icmp" {
				if rule.ICMPType != 0 {
					denyICMPTypes[rule.ICMPType] = true
				} else {
					// Deny all ICMP types if not specified
					denyICMPTypes[-1] = true
				}
				continue
			}

			// Handle source CIDRs
			if rule.SrcIP != "" {
				denyCIDRs[rule.SrcIP] = true
			}

			// Handle port rules for deny
			if rule.Protocol == "tcp" || rule.Protocol == "udp" {
				if rule.DstPort != "" {
					if _, ok := denyPorts[rule.Protocol]; !ok {
						denyPorts[rule.Protocol] = make(map[string]bool)
					}
					if strings.Contains(rule.DstPort, ",") {
						// Handle multi-port
						for _, port := range strings.Split(rule.DstPort, ",") {
							denyPorts[rule.Protocol][port] = true
						}
					} else if strings.Contains(rule.DstPort, ":") {
						// Handle port range
						denyPorts[rule.Protocol][rule.DstPort] = true
					} else {
						denyPorts[rule.Protocol][rule.DstPort] = true
					}
				} else {
					// Deny all ports for this protocol
					if _, ok := denyPorts[rule.Protocol]; !ok {
						denyPorts[rule.Protocol] = make(map[string]bool)
					}
					denyPorts[rule.Protocol][""] = true
				}
			}
		}
	}

	// Create port rules for allowed ports
	if len(acceptPorts) > 0 {
		ingressRule := IngressRule{}
		for protocol, ports := range acceptPorts {
			portRule := PortRule{}
			if _, allPorts := ports[""]; allPorts {
				// Allow all ports for this protocol
				portRule.Ports = append(portRule.Ports, PortProtocol{
					Port:     "",
					Protocol: protocol,
				})
			} else {
				// Allow specific ports
				for port := range ports {
					portRule.Ports = append(portRule.Ports, PortProtocol{
						Port:     port,
						Protocol: protocol,
					})
				}
			}
			if len(portRule.Ports) > 0 {
				ingressRule.ToPorts = append(ingressRule.ToPorts, portRule)
			}
		}
		// Add the rule only if it has ports
		if len(ingressRule.ToPorts) > 0 {
			ingressRules = append(ingressRules, ingressRule)
		}
	}

	// Create CIDR rules for allowed CIDRs
	if len(acceptCIDRs) > 0 {
		ingressRule := IngressRule{}
		for cidr := range acceptCIDRs {
			ingressRule.FromCIDRs = append(ingressRule.FromCIDRs, cidr)
		}
		// Add only if there are CIDRs
		if len(ingressRule.FromCIDRs) > 0 {
			ingressRules = append(ingressRules, ingressRule)
		}
	}

	// Create ICMP rules
	if len(icmpTypes) > 0 {
		ingressRule := IngressRule{}
		if _, allTypes := icmpTypes[-1]; allTypes {
			// Allow all ICMP types
			ingressRule.ICMPs = append(ingressRule.ICMPs, ICMPRule{Type: 8}) // Echo Request (ping)
			ingressRule.ICMPs = append(ingressRule.ICMPs, ICMPRule{Type: 0}) // Echo Reply
		} else {
			// Allow specific ICMP types
			for icmpType := range icmpTypes {
				ingressRule.ICMPs = append(ingressRule.ICMPs, ICMPRule{Type: icmpType})
			}
		}
		// Add only if there are ICMP types
		if len(ingressRule.ICMPs) > 0 {
			ingressRules = append(ingressRules, ingressRule)
		}
	}

	// Create deny port rules
	if len(denyPorts) > 0 {
		denyRule := IngressRule{}
		for protocol, ports := range denyPorts {
			portRule := PortRule{}
			if _, allPorts := ports[""]; allPorts {
				// Deny all ports for this protocol
				portRule.Ports = append(portRule.Ports, PortProtocol{
					Port:     "",
					Protocol: protocol,
				})
			} else {
				// Deny specific ports
				for port := range ports {
					portRule.Ports = append(portRule.Ports, PortProtocol{
						Port:     port,
						Protocol: protocol,
					})
				}
			}
			if len(portRule.Ports) > 0 {
				denyRule.ToPorts = append(denyRule.ToPorts, portRule)
			}
		}
		// Add the rule only if it has ports
		if len(denyRule.ToPorts) > 0 {
			ingressDenyRules = append(ingressDenyRules, denyRule)
		}
	}

	// Create CIDR deny rules
	if len(denyCIDRs) > 0 {
		denyRule := IngressRule{}
		for cidr := range denyCIDRs {
			denyRule.FromCIDRs = append(denyRule.FromCIDRs, cidr)
		}
		// Add only if there are CIDRs
		if len(denyRule.FromCIDRs) > 0 {
			ingressDenyRules = append(ingressDenyRules, denyRule)
		}
	}

	// Create ICMP deny rules
	if len(denyICMPTypes) > 0 {
		denyRule := IngressRule{}
		if _, allTypes := denyICMPTypes[-1]; allTypes {
			// Deny all ICMP types
			for i := 0; i < 40; i++ { // Cover most common ICMP types
				denyRule.ICMPs = append(denyRule.ICMPs, ICMPRule{Type: i})
			}
		} else {
			// Deny specific ICMP types
			for icmpType := range denyICMPTypes {
				denyRule.ICMPs = append(denyRule.ICMPs, ICMPRule{Type: icmpType})
			}
		}
		// Add only if there are ICMP types
		if len(denyRule.ICMPs) > 0 {
			ingressDenyRules = append(ingressDenyRules, denyRule)
		}
	}

	// Set the ingress rules in the policy
	policy.Spec.Ingress = ingressRules
	policy.Spec.IngressDeny = ingressDenyRules
}

func processEgressRules(rules []IPTablesRule, policy *CiliumClusterwideNetworkPolicy) {
	// Similar to processIngressRules but for OUTPUT chain (egress)
	var egressRules []EgressRule
	var egressDenyRules []EgressRule

	acceptPorts := make(map[string]map[string]bool) // protocol -> port -> true
	denyPorts := make(map[string]map[string]bool)   // protocol -> port -> true

	acceptCIDRs := make(map[string]bool) // cidr -> true
	denyCIDRs := make(map[string]bool)   // cidr -> true

	icmpTypes := make(map[int]bool)     // icmpType -> true
	denyICMPTypes := make(map[int]bool) // icmpType -> true

	// First, organize all the allowed and denied ports, CIDRs, and ICMP types
	for _, rule := range rules {
		if rule.Chain != "OUTPUT" {
			continue
		}

		// Established connections are handled automatically by Cilium's stateful firewall
		if rule.Established {
			continue
		}

		// Process the rule based on action
		if rule.Action == "ACCEPT" {
			// Allow loopback interface (handled separately)
			if rule.Interface == "lo" {
				continue // Loopback is handled automatically in Cilium
			}

			// Handle ICMP
			if rule.Protocol == "icmp" {
				if rule.ICMPType != 0 {
					icmpTypes[rule.ICMPType] = true
				} else {
					// Allow all ICMP types if not specified
					icmpTypes[-1] = true // -1 means all types
				}
				continue
			}

			// Handle destination CIDRs
			if rule.DstIP != "" {
				acceptCIDRs[rule.DstIP] = true
			}

			// Handle port rules
			if rule.Protocol == "tcp" || rule.Protocol == "udp" {
				if rule.DstPort != "" {
					if _, ok := acceptPorts[rule.Protocol]; !ok {
						acceptPorts[rule.Protocol] = make(map[string]bool)
					}
					if strings.Contains(rule.DstPort, ",") {
						// Handle multi-port
						for _, port := range strings.Split(rule.DstPort, ",") {
							acceptPorts[rule.Protocol][port] = true
						}
					} else if strings.Contains(rule.DstPort, ":") {
						// Handle port range
						acceptPorts[rule.Protocol][rule.DstPort] = true
					} else {
						acceptPorts[rule.Protocol][rule.DstPort] = true
					}
				} else {
					// Allow all ports for this protocol
					if _, ok := acceptPorts[rule.Protocol]; !ok {
						acceptPorts[rule.Protocol] = make(map[string]bool)
					}
					acceptPorts[rule.Protocol][""] = true // Empty string means all ports
				}
			}
		} else if rule.Action == "DROP" || rule.Action == "REJECT" {
			// Handle ICMP
			if rule.Protocol == "icmp" {
				if rule.ICMPType != 0 {
					denyICMPTypes[rule.ICMPType] = true
				} else {
					// Deny all ICMP types if not specified
					denyICMPTypes[-1] = true
				}
				continue
			}

			// Handle destination CIDRs
			if rule.DstIP != "" {
				denyCIDRs[rule.DstIP] = true
			}

			// Handle port rules for deny
			if rule.Protocol == "tcp" || rule.Protocol == "udp" {
				if rule.DstPort != "" {
					if _, ok := denyPorts[rule.Protocol]; !ok {
						denyPorts[rule.Protocol] = make(map[string]bool)
					}
					if strings.Contains(rule.DstPort, ",") {
						// Handle multi-port
						for _, port := range strings.Split(rule.DstPort, ",") {
							denyPorts[rule.Protocol][port] = true
						}
					} else if strings.Contains(rule.DstPort, ":") {
						// Handle port range
						denyPorts[rule.Protocol][rule.DstPort] = true
					} else {
						denyPorts[rule.Protocol][rule.DstPort] = true
					}
				} else {
					// Deny all ports for this protocol
					if _, ok := denyPorts[rule.Protocol]; !ok {
						denyPorts[rule.Protocol] = make(map[string]bool)
					}
					denyPorts[rule.Protocol][""] = true
				}
			}
		}
	}

	// Create port rules for allowed ports
	if len(acceptPorts) > 0 {
		egressRule := EgressRule{}
		for protocol, ports := range acceptPorts {
			portRule := PortRule{}
			if _, allPorts := ports[""]; allPorts {
				// Allow all ports for this protocol
				portRule.Ports = append(portRule.Ports, PortProtocol{
					Port:     "",
					Protocol: protocol,
				})
			} else {
				// Allow specific ports
				for port := range ports {
					portRule.Ports = append(portRule.Ports, PortProtocol{
						Port:     port,
						Protocol: protocol,
					})
				}
			}
			if len(portRule.Ports) > 0 {
				egressRule.ToPorts = append(egressRule.ToPorts, portRule)
			}
		}
		// Add the rule only if it has ports
		if len(egressRule.ToPorts) > 0 {
			egressRules = append(egressRules, egressRule)
		}
	}

	// Create CIDR rules for allowed CIDRs
	if len(acceptCIDRs) > 0 {
		egressRule := EgressRule{}
		for cidr := range acceptCIDRs {
			egressRule.ToCIDRs = append(egressRule.ToCIDRs, cidr)
		}
		// Add only if there are CIDRs
		if len(egressRule.ToCIDRs) > 0 {
			egressRules = append(egressRules, egressRule)
		}
	}

	// Create ICMP rules
	if len(icmpTypes) > 0 {
		egressRule := EgressRule{}
		if _, allTypes := icmpTypes[-1]; allTypes {
			// Allow all ICMP types
			egressRule.ICMPs = append(egressRule.ICMPs, ICMPRule{Type: 8}) // Echo Request (ping)
			egressRule.ICMPs = append(egressRule.ICMPs, ICMPRule{Type: 0}) // Echo Reply
		} else {
			// Allow specific ICMP types
			for icmpType := range icmpTypes {
				egressRule.ICMPs = append(egressRule.ICMPs, ICMPRule{Type: icmpType})
			}
		}
		// Add only if there are ICMP types
		if len(egressRule.ICMPs) > 0 {
			egressRules = append(egressRules, egressRule)
		}
	}

	// Create deny port rules
	if len(denyPorts) > 0 {
		denyRule := EgressRule{}
		for protocol, ports := range denyPorts {
			portRule := PortRule{}
			if _, allPorts := ports[""]; allPorts {
				// Deny all ports for this protocol
				portRule.Ports = append(portRule.Ports, PortProtocol{
					Port:     "",
					Protocol: protocol,
				})
			} else {
				// Deny specific ports
				for port := range ports {
					portRule.Ports = append(portRule.Ports, PortProtocol{
						Port:     port,
						Protocol: protocol,
					})
				}
			}
			if len(portRule.Ports) > 0 {
				denyRule.ToPorts = append(denyRule.ToPorts, portRule)
			}
		}
		// Add the rule only if it has ports
		if len(denyRule.ToPorts) > 0 {
			egressDenyRules = append(egressDenyRules, denyRule)
		}
	}

	// Create CIDR deny rules
	if len(denyCIDRs) > 0 {
		denyRule := EgressRule{}
		for cidr := range denyCIDRs {
			denyRule.ToCIDRs = append(denyRule.ToCIDRs, cidr)
		}
		// Add only if there are CIDRs
		if len(denyRule.ToCIDRs) > 0 {
			egressDenyRules = append(egressDenyRules, denyRule)
		}
	}

	// Create ICMP deny rules
	if len(denyICMPTypes) > 0 {
		denyRule := EgressRule{}
		if _, allTypes := denyICMPTypes[-1]; allTypes {
			// Deny all ICMP types
			for i := 0; i < 40; i++ { // Cover most common ICMP types
				denyRule.ICMPs = append(denyRule.ICMPs, ICMPRule{Type: i})
			}
		} else {
			// Deny specific ICMP types
			for icmpType := range denyICMPTypes {
				denyRule.ICMPs = append(denyRule.ICMPs, ICMPRule{Type: icmpType})
			}
		}
		// Add only if there are ICMP types
		if len(denyRule.ICMPs) > 0 {
			egressDenyRules = append(egressDenyRules, denyRule)
		}
	}

	// Set the egress rules in the policy
	policy.Spec.Egress = egressRules
	policy.Spec.EgressDeny = egressDenyRules
}

// addEssentialPolicies adds common required policies for a functioning node
func addEssentialPolicies(policy *CiliumClusterwideNetworkPolicy) {
	// Define essential ingress services based on includePolicies map

	// Add SSH access (port 22)
	if includePolicies["ssh"] {
		sshRule := IngressRule{
			ToPorts: []PortRule{
				{
					Ports: []PortProtocol{
						{
							Port:     "22",
							Protocol: "TCP",
						},
					},
				},
			},
		}

		// Add from world (or could be more restrictive with specific IPs)
		sshRule.FromEntities = []string{"world"}

		policy.Spec.Ingress = append(policy.Spec.Ingress, sshRule)
	}

	// Add Kubernetes API server access
	if includePolicies["kubernetes-api"] {
		k8sRule := IngressRule{
			FromEntities: []string{"remote-node", "host"},
		}

		// Kube API server ports
		apiServerRule := IngressRule{
			ToPorts: []PortRule{
				{
					Ports: []PortProtocol{
						{
							Port:     "6443",
							Protocol: "TCP",
						},
						{
							Port:     "443",
							Protocol: "TCP",
						},
					},
				},
			},
			FromEntities: []string{"remote-node", "host"},
		}

		policy.Spec.Ingress = append(policy.Spec.Ingress, k8sRule)
		policy.Spec.Ingress = append(policy.Spec.Ingress, apiServerRule)

		// Allow egress to API server
		apiServerEgressRule := EgressRule{
			ToEntities: []string{"kube-apiserver"},
			ToPorts: []PortRule{
				{
					Ports: []PortProtocol{
						{
							Port:     "6443",
							Protocol: "TCP",
						},
						{
							Port:     "443",
							Protocol: "TCP",
						},
					},
				},
			},
		}

		policy.Spec.Egress = append(policy.Spec.Egress, apiServerEgressRule)
	}

	// Add kubelet access
	if includePolicies["kubelet"] {
		kubeletRule := IngressRule{
			ToPorts: []PortRule{
				{
					Ports: []PortProtocol{
						{
							Port:     "10250",
							Protocol: "TCP",
						},
					},
				},
			},
			FromEntities: []string{"remote-node", "host"},
		}

		policy.Spec.Ingress = append(policy.Spec.Ingress, kubeletRule)
	}

	// Add DNS access (typically needed for node operations)
	if includePolicies["dns"] {
		dnsEgressRule := EgressRule{
			ToPorts: []PortRule{
				{
					Ports: []PortProtocol{
						{
							Port:     "53",
							Protocol: "UDP",
						},
						{
							Port:     "53",
							Protocol: "TCP",
						},
					},
				},
			},
		}

		policy.Spec.Egress = append(policy.Spec.Egress, dnsEgressRule)
	}

	// Add etcd access
	if includePolicies["etcd"] {
		etcdRule := IngressRule{
			ToPorts: []PortRule{
				{
					Ports: []PortProtocol{
						{
							Port:     "2379",
							Protocol: "TCP",
						},
						{
							Port:     "2380",
							Protocol: "TCP",
						},
					},
				},
			},
			FromEntities: []string{"remote-node", "host"},
		}

		policy.Spec.Ingress = append(policy.Spec.Ingress, etcdRule)

		// Allow egress to etcd
		etcdEgressRule := EgressRule{
			ToPorts: []PortRule{
				{
					Ports: []PortProtocol{
						{
							Port:     "2379",
							Protocol: "TCP",
						},
						{
							Port:     "2380",
							Protocol: "TCP",
						},
					},
				},
			},
			ToEntities: []string{"remote-node", "host"},
		}

		policy.Spec.Egress = append(policy.Spec.Egress, etcdEgressRule)
	}
}
