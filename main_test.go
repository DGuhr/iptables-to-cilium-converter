package main

import (
	"bytes"
	"fmt"
	"gopkg.in/yaml.v2"
	"strings"
	"testing"
)

func TestParseIPTablesRules(t *testing.T) {
	testCases := []struct {
		name             string
		input            string
		expectedRules    []IPTablesRule
		expectedDefaults map[string]bool
	}{
		{
			name: "Basic INPUT rules",
			input: `*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
COMMIT
`,
			expectedRules: []IPTablesRule{
				{Chain: "INPUT", Interface: "lo", Action: "ACCEPT"},
				{Chain: "INPUT", Protocol: "tcp", DstPort: "22", Action: "ACCEPT"},
				{Chain: "INPUT", Protocol: "tcp", DstPort: "80", Action: "ACCEPT"},
			},
			expectedDefaults: map[string]bool{"INPUT": true, "FORWARD": false, "OUTPUT": false},
		},
		{
			name: "Rules with different actions",
			input: `*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -s 192.168.1.100 -j DROP
-A OUTPUT -d 10.0.0.0/8 -j REJECT
COMMIT
`,
			expectedRules: []IPTablesRule{
				{Chain: "INPUT", SrcIP: "192.168.1.100", Action: "DROP"},
				{Chain: "OUTPUT", DstIP: "10.0.0.0/8", Action: "REJECT"},
			},
			expectedDefaults: map[string]bool{"INPUT": false, "FORWARD": false, "OUTPUT": false},
		},
		{
			name: "ICMP rules",
			input: `*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p icmp -j ACCEPT
-A INPUT -p icmp --icmp-type 8 -j ACCEPT
COMMIT
`,
			expectedRules: []IPTablesRule{
				{Chain: "INPUT", Protocol: "icmp", Action: "ACCEPT"},
				{Chain: "INPUT", Protocol: "icmp", ICMPType: 8, Action: "ACCEPT"},
			},
			expectedDefaults: map[string]bool{"INPUT": true, "FORWARD": true, "OUTPUT": false},
		},
		{
			name: "Established connections",
			input: `*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
COMMIT
`,
			expectedRules: []IPTablesRule{
				{Chain: "INPUT", Established: true, Action: "ACCEPT"},
			},
			expectedDefaults: map[string]bool{"INPUT": true, "FORWARD": false, "OUTPUT": false},
		},
		{
			name: "Ignore non-filter tables",
			input: `*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.0.0.0/24 -j MASQUERADE
COMMIT
*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 443 -j ACCEPT
COMMIT
`,
			expectedRules: []IPTablesRule{
				{Chain: "INPUT", Protocol: "tcp", DstPort: "443", Action: "ACCEPT"},
			},
			expectedDefaults: map[string]bool{"INPUT": true, "FORWARD": false, "OUTPUT": false},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Save and restore the global defaultDrop map
			oldDefaultDrop := defaultDrop
			defaultDrop = map[string]bool{}
			defer func() { defaultDrop = oldDefaultDrop }()

			reader := strings.NewReader(tc.input)
			rules, err := parseIPTablesRules(reader)
			if err != nil {
				t.Fatalf("Error parsing rules: %v", err)
			}

			// Check if rules match expected
			if len(rules) != len(tc.expectedRules) {
				t.Errorf("Expected %d rules, got %d", len(tc.expectedRules), len(rules))
			}

			for i, expected := range tc.expectedRules {
				if i >= len(rules) {
					t.Errorf("Missing expected rule at index %d: %+v", i, expected)
					continue
				}

				actual := rules[i]

				// Compare relevant fields
				if actual.Chain != expected.Chain {
					t.Errorf("Rule %d: Expected Chain '%s', got '%s'", i, expected.Chain, actual.Chain)
				}
				if actual.Action != expected.Action {
					t.Errorf("Rule %d: Expected Action '%s', got '%s'", i, expected.Action, actual.Action)
				}
				if actual.Protocol != expected.Protocol {
					t.Errorf("Rule %d: Expected Protocol '%s', got '%s'", i, expected.Protocol, actual.Protocol)
				}
				if actual.DstPort != expected.DstPort {
					t.Errorf("Rule %d: Expected DstPort '%s', got '%s'", i, expected.DstPort, actual.DstPort)
				}
				if actual.SrcIP != expected.SrcIP {
					t.Errorf("Rule %d: Expected SrcIP '%s', got '%s'", i, expected.SrcIP, actual.SrcIP)
				}
				if actual.DstIP != expected.DstIP {
					t.Errorf("Rule %d: Expected DstIP '%s', got '%s'", i, expected.DstIP, actual.DstIP)
				}
				if actual.Interface != expected.Interface {
					t.Errorf("Rule %d: Expected Interface '%s', got '%s'", i, expected.Interface, actual.Interface)
				}
				if actual.ICMPType != expected.ICMPType {
					t.Errorf("Rule %d: Expected ICMPType %d, got %d", i, expected.ICMPType, actual.ICMPType)
				}
				if actual.Established != expected.Established {
					t.Errorf("Rule %d: Expected Established %v, got %v", i, expected.Established, actual.Established)
				}
			}

			// Verify default policies
			for chain, expectedDrop := range tc.expectedDefaults {
				if defaultDrop[chain] != expectedDrop {
					t.Errorf("Default policy for chain %s: expected DROP=%v, got DROP=%v",
						chain, expectedDrop, defaultDrop[chain])
				}
			}
		})
	}
}

func TestParseRule(t *testing.T) {
	testCases := []struct {
		line     string
		expected *IPTablesRule
		isError  bool
	}{
		{
			line: "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
			expected: &IPTablesRule{
				Chain:    "INPUT",
				Protocol: "tcp",
				DstPort:  "22",
				Action:   "ACCEPT",
			},
		},
		{
			line: "-A INPUT -i lo -j ACCEPT",
			expected: &IPTablesRule{
				Chain:     "INPUT",
				Interface: "lo",
				Action:    "ACCEPT",
			},
		},
		{
			line: "-A OUTPUT -d 10.0.0.0/8 -j DROP",
			expected: &IPTablesRule{
				Chain:  "OUTPUT",
				DstIP:  "10.0.0.0/8",
				Action: "DROP",
			},
		},
		{
			line: "-A INPUT -s 192.168.1.1 -j REJECT",
			expected: &IPTablesRule{
				Chain:  "INPUT",
				SrcIP:  "192.168.1.1",
				Action: "REJECT",
			},
		},
		{
			line: "-A INPUT -p icmp -j ACCEPT",
			expected: &IPTablesRule{
				Chain:    "INPUT",
				Protocol: "icmp",
				Action:   "ACCEPT",
			},
		},
		{
			line: "-A INPUT -p icmp --icmp-type 8 -j ACCEPT",
			expected: &IPTablesRule{
				Chain:    "INPUT",
				Protocol: "icmp",
				ICMPType: 8,
				Action:   "ACCEPT",
			},
		},
		{
			line: "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
			expected: &IPTablesRule{
				Chain:       "INPUT",
				Established: true,
				Action:      "ACCEPT",
			},
		},
		{
			line: "-A INPUT -p tcp -m multiport --dports 80,443,8080 -j ACCEPT",
			expected: &IPTablesRule{
				Chain:    "INPUT",
				Protocol: "tcp",
				DstPort:  "80,443,8080",
				Action:   "ACCEPT",
			},
		},
		{
			// This should be skipped by the parser as it's not INPUT or OUTPUT
			line:     "-A FORWARD -j ACCEPT",
			expected: nil,
		},
		{
			// Too short, should error
			line:    "-A INPUT",
			isError: true,
		},
		{
			// Not a rule, should error
			line:    "COMMIT",
			isError: true,
		},
	}

	for i, tc := range testCases {
		result, err := parseRule(tc.line)

		if tc.isError && err == nil {
			t.Errorf("Test case %d: Expected error but got none for line '%s'", i, tc.line)
			continue
		}

		if !tc.isError && err != nil {
			t.Errorf("Test case %d: Unexpected error: %v for line '%s'", i, err, tc.line)
			continue
		}

		if tc.expected == nil && result != nil {
			t.Errorf("Test case %d: Expected nil result, got %+v", i, result)
			continue
		}

		if tc.expected != nil && result == nil {
			t.Errorf("Test case %d: Expected non-nil result, got nil", i)
			continue
		}

		if tc.expected != nil && result != nil {
			// Compare fields
			if result.Chain != tc.expected.Chain {
				t.Errorf("Test case %d: Expected Chain '%s', got '%s'", i, tc.expected.Chain, result.Chain)
			}
			if result.Action != tc.expected.Action {
				t.Errorf("Test case %d: Expected Action '%s', got '%s'", i, tc.expected.Action, result.Action)
			}
			if result.Protocol != tc.expected.Protocol {
				t.Errorf("Test case %d: Expected Protocol '%s', got '%s'", i, tc.expected.Protocol, result.Protocol)
			}
			if result.DstPort != tc.expected.DstPort {
				t.Errorf("Test case %d: Expected DstPort '%s', got '%s'", i, tc.expected.DstPort, result.DstPort)
			}
			if result.SrcIP != tc.expected.SrcIP {
				t.Errorf("Test case %d: Expected SrcIP '%s', got '%s'", i, tc.expected.SrcIP, result.SrcIP)
			}
			if result.DstIP != tc.expected.DstIP {
				t.Errorf("Test case %d: Expected DstIP '%s', got '%s'", i, tc.expected.DstIP, result.DstIP)
			}
			if result.Interface != tc.expected.Interface {
				t.Errorf("Test case %d: Expected Interface '%s', got '%s'", i, tc.expected.Interface, result.Interface)
			}
			if result.ICMPType != tc.expected.ICMPType {
				t.Errorf("Test case %d: Expected ICMPType %d, got %d", i, tc.expected.ICMPType, result.ICMPType)
			}
			if result.Established != tc.expected.Established {
				t.Errorf("Test case %d: Expected Established %v, got %v", i, tc.expected.Established, result.Established)
			}
		}
	}
}

func TestCreateCiliumPolicy(t *testing.T) {
	testCases := []struct {
		name         string
		rules        []IPTablesRule
		policyName   string
		nodeSelector string
		validateFunc func(t *testing.T, policy CiliumClusterwideNetworkPolicy)
	}{
		{
			name: "Basic SSH and HTTP rules",
			rules: []IPTablesRule{
				{Chain: "INPUT", Protocol: "tcp", DstPort: "22", Action: "ACCEPT"},
				{Chain: "INPUT", Protocol: "tcp", DstPort: "80", Action: "ACCEPT"},
				{Chain: "INPUT", Protocol: "tcp", DstPort: "443", Action: "ACCEPT"},
			},
			policyName:   "test-policy",
			nodeSelector: "",
			validateFunc: func(t *testing.T, policy CiliumClusterwideNetworkPolicy) {
				// Check metadata
				if policy.Metadata.Name != "test-policy" {
					t.Errorf("Expected policy name 'test-policy', got '%s'", policy.Metadata.Name)
				}

				// Check ingress rules for ports
				if len(policy.Spec.Ingress) != 1 {
					t.Errorf("Expected 1 ingress rule, got %d", len(policy.Spec.Ingress))
					return
				}

				// Check port rules
				ingressRule := policy.Spec.Ingress[0]
				if len(ingressRule.ToPorts) != 1 {
					t.Errorf("Expected 1 port rule in ingress, got %d", len(ingressRule.ToPorts))
					return
				}

				portRule := ingressRule.ToPorts[0]
				if len(portRule.Ports) != 3 {
					t.Errorf("Expected 3 ports in rule, got %d", len(portRule.Ports))
					return
				}

				// Check for expected ports
				expectedPorts := map[string]bool{"22": false, "80": false, "443": false}
				for _, port := range portRule.Ports {
					if _, exists := expectedPorts[port.Port]; !exists {
						t.Errorf("Unexpected port %s in policy", port.Port)
					} else {
						expectedPorts[port.Port] = true
					}

					if port.Protocol != "tcp" {
						t.Errorf("Expected protocol 'tcp' for port %s, got '%s'", port.Port, port.Protocol)
					}
				}

				// Verify all expected ports were found
				for port, found := range expectedPorts {
					if !found {
						t.Errorf("Expected port %s was not found in policy", port)
					}
				}
			},
		},
		{
			name: "ICMP rules",
			rules: []IPTablesRule{
				{Chain: "INPUT", Protocol: "icmp", Action: "ACCEPT"},
			},
			policyName:   "icmp-policy",
			nodeSelector: "",
			validateFunc: func(t *testing.T, policy CiliumClusterwideNetworkPolicy) {
				// Check ingress rules for ICMP
				if len(policy.Spec.Ingress) != 1 {
					t.Errorf("Expected 1 ingress rule, got %d", len(policy.Spec.Ingress))
					return
				}

				// Check ICMP rules
				ingressRule := policy.Spec.Ingress[0]
				if len(ingressRule.ICMPs) < 1 {
					t.Errorf("Expected at least 1 ICMP rule, got %d", len(ingressRule.ICMPs))
					return
				}

				// We expect echo request (8) and echo reply (0) at minimum
				foundEchoRequest := false
				foundEchoReply := false

				for _, icmp := range ingressRule.ICMPs {
					if icmp.Type == 8 {
						foundEchoRequest = true
					}
					if icmp.Type == 0 {
						foundEchoReply = true
					}
				}

				if !foundEchoRequest {
					t.Errorf("ICMP Echo Request (type 8) not found in policy")
				}
				if !foundEchoReply {
					t.Errorf("ICMP Echo Reply (type 0) not found in policy")
				}
			},
		},
		{
			name: "Source IP rules",
			rules: []IPTablesRule{
				{Chain: "INPUT", SrcIP: "192.168.1.0/24", Action: "ACCEPT"},
				{Chain: "INPUT", SrcIP: "10.0.0.1", Action: "ACCEPT"},
			},
			policyName:   "cidr-policy",
			nodeSelector: "",
			validateFunc: func(t *testing.T, policy CiliumClusterwideNetworkPolicy) {
				// Check ingress rules for CIDRs
				if len(policy.Spec.Ingress) != 1 {
					t.Errorf("Expected 1 ingress rule, got %d", len(policy.Spec.Ingress))
					return
				}

				// Check CIDR rules
				ingressRule := policy.Spec.Ingress[0]
				if len(ingressRule.FromCIDRs) != 2 {
					t.Errorf("Expected 2 CIDR rules, got %d", len(ingressRule.FromCIDRs))
					return
				}

				// Check for expected CIDRs
				expectedCIDRs := map[string]bool{"192.168.1.0/24": false, "10.0.0.1": false}
				for _, cidr := range ingressRule.FromCIDRs {
					if _, exists := expectedCIDRs[cidr]; !exists {
						t.Errorf("Unexpected CIDR %s in policy", cidr)
					} else {
						expectedCIDRs[cidr] = true
					}
				}

				// Verify all expected CIDRs were found
				for cidr, found := range expectedCIDRs {
					if !found {
						t.Errorf("Expected CIDR %s was not found in policy", cidr)
					}
				}
			},
		},
		{
			name: "Node selector",
			rules: []IPTablesRule{
				{Chain: "INPUT", Protocol: "tcp", DstPort: "22", Action: "ACCEPT"},
			},
			policyName:   "node-selector-policy",
			nodeSelector: "kubernetes.io/hostname=worker1",
			validateFunc: func(t *testing.T, policy CiliumClusterwideNetworkPolicy) {
				// Check node selector
				nodeSelector := policy.Spec.NodeSelector
				if nodeSelector == nil {
					t.Errorf("Expected node selector to be set, got nil")
					return
				}

				matchLabels, ok := nodeSelector["matchLabels"]
				if !ok {
					t.Errorf("Expected node selector to have matchLabels, got %v", nodeSelector)
					return
				}

				matchLabelsMap, ok := matchLabels.(map[string]string)
				if !ok {
					t.Errorf("Expected matchLabels to be a map[string]string, got %T", matchLabels)
					return
				}

				hostname, ok := matchLabelsMap["kubernetes.io/hostname"]
				if !ok {
					t.Errorf("Expected matchLabels to have key 'kubernetes.io/hostname', got %v", matchLabelsMap)
					return
				}

				if hostname != "worker1" {
					t.Errorf("Expected hostname to be 'worker1', got '%s'", hostname)
				}
			},
		},
		{
			name: "Drop rules",
			rules: []IPTablesRule{
				{Chain: "INPUT", SrcIP: "192.168.1.100", Action: "DROP"},
				{Chain: "OUTPUT", DstIP: "10.0.0.0/8", Action: "REJECT"},
			},
			policyName:   "deny-policy",
			nodeSelector: "",
			validateFunc: func(t *testing.T, policy CiliumClusterwideNetworkPolicy) {
				// Check ingress deny rules
				if len(policy.Spec.IngressDeny) != 1 {
					t.Errorf("Expected 1 ingress deny rule, got %d", len(policy.Spec.IngressDeny))
					return
				}

				// Check CIDR in deny rule
				ingressDeny := policy.Spec.IngressDeny[0]
				if len(ingressDeny.FromCIDRs) != 1 {
					t.Errorf("Expected 1 CIDR in ingress deny, got %d", len(ingressDeny.FromCIDRs))
					return
				}

				if ingressDeny.FromCIDRs[0] != "192.168.1.100" {
					t.Errorf("Expected deny CIDR '192.168.1.100', got '%s'", ingressDeny.FromCIDRs[0])
				}

				// Check egress deny rules
				if len(policy.Spec.EgressDeny) != 1 {
					t.Errorf("Expected 1 egress deny rule, got %d", len(policy.Spec.EgressDeny))
					return
				}

				// Check CIDR in egress deny rule
				egressDeny := policy.Spec.EgressDeny[0]
				if len(egressDeny.ToCIDRs) != 1 {
					t.Errorf("Expected 1 CIDR in egress deny, got %d", len(egressDeny.ToCIDRs))
					return
				}

				if egressDeny.ToCIDRs[0] != "10.0.0.0/8" {
					t.Errorf("Expected deny CIDR '10.0.0.0/8', got '%s'", egressDeny.ToCIDRs[0])
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Call the function
			policy := createCiliumPolicy(tc.rules, tc.policyName, tc.nodeSelector)

			// Run validation
			tc.validateFunc(t, policy)
		})
	}
}

func TestAddEssentialPolicies(t *testing.T) {
	// Setup test cases
	testCases := []struct {
		name               string
		includePolicies    map[string]bool
		expectedIngressLen int
		expectedEgressLen  int
		validateFunc       func(t *testing.T, policy CiliumClusterwideNetworkPolicy)
	}{
		{
			name: "SSH only",
			includePolicies: map[string]bool{
				"ssh": true,
			},
			expectedIngressLen: 1,
			expectedEgressLen:  0,
			validateFunc: func(t *testing.T, policy CiliumClusterwideNetworkPolicy) {
				// Verify SSH is added
				foundSSH := false
				for _, rule := range policy.Spec.Ingress {
					for _, portRule := range rule.ToPorts {
						for _, port := range portRule.Ports {
							if port.Port == "22" && port.Protocol == "TCP" {
								foundSSH = true
								break
							}
						}
					}
				}
				if !foundSSH {
					t.Errorf("SSH rule not found in policy")
				}
			},
		},
		{
			name: "Kubernetes API and DNS",
			includePolicies: map[string]bool{
				"kubernetes-api": true,
				"dns":            true,
			},
			expectedIngressLen: 2, // k8s API rules
			expectedEgressLen:  2, // k8s API egress + DNS egress
			validateFunc: func(t *testing.T, policy CiliumClusterwideNetworkPolicy) {
				// Verify Kubernetes API ports
				foundK8sAPI := false
				for _, rule := range policy.Spec.Ingress {
					for _, portRule := range rule.ToPorts {
						for _, port := range portRule.Ports {
							if (port.Port == "6443" || port.Port == "443") && port.Protocol == "TCP" {
								foundK8sAPI = true
								break
							}
						}
					}
				}
				if !foundK8sAPI {
					t.Errorf("Kubernetes API rule not found in policy")
				}

				// Verify DNS
				foundDNS := false
				for _, rule := range policy.Spec.Egress {
					for _, portRule := range rule.ToPorts {
						for _, port := range portRule.Ports {
							if port.Port == "53" && (port.Protocol == "UDP" || port.Protocol == "TCP") {
								foundDNS = true
								break
							}
						}
					}
				}
				if !foundDNS {
					t.Errorf("DNS rule not found in policy")
				}
			},
		},
		{
			name: "All essential policies",
			includePolicies: map[string]bool{
				"ssh":            true,
				"kubernetes-api": true,
				"dns":            true,
				"etcd":           true,
				"kubelet":        true,
			},
			expectedIngressLen: 5, // ssh, k8s API (2), etcd, kubelet
			expectedEgressLen:  3, // k8s API, DNS, etcd
			validateFunc: func(t *testing.T, policy CiliumClusterwideNetworkPolicy) {
				// Check for etcd ports
				foundEtcd := false
				for _, rule := range policy.Spec.Ingress {
					for _, portRule := range rule.ToPorts {
						for _, port := range portRule.Ports {
							if (port.Port == "2379" || port.Port == "2380") && port.Protocol == "TCP" {
								foundEtcd = true
								break
							}
						}
					}
				}
				if !foundEtcd {
					t.Errorf("etcd rule not found in policy")
				}

				// Check for kubelet port
				foundKubelet := false
				for _, rule := range policy.Spec.Ingress {
					for _, portRule := range rule.ToPorts {
						for _, port := range portRule.Ports {
							if port.Port == "10250" && port.Protocol == "TCP" {
								foundKubelet = true
								break
							}
						}
					}
				}
				if !foundKubelet {
					t.Errorf("kubelet rule not found in policy")
				}
			},
		},
	}

	// Save and restore the global includePolicies map
	oldIncludePolicies := includePolicies
	defer func() { includePolicies = oldIncludePolicies }()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set up global state
			includePolicies = tc.includePolicies

			// Create an empty policy
			policy := CiliumClusterwideNetworkPolicy{
				APIVersion: "cilium.io/v2",
				Kind:       "CiliumClusterwideNetworkPolicy",
			}
			policy.Metadata.Name = "test-policy"

			// Call the function
			addEssentialPolicies(&policy)

			// Check lengths
			if len(policy.Spec.Ingress) != tc.expectedIngressLen {
				t.Errorf("Expected %d ingress rules, got %d", tc.expectedIngressLen, len(policy.Spec.Ingress))
			}

			if len(policy.Spec.Egress) != tc.expectedEgressLen {
				t.Errorf("Expected %d egress rules, got %d", tc.expectedEgressLen, len(policy.Spec.Egress))
			}

			// Run validation
			tc.validateFunc(t, policy)
		})
	}
}

// TestMain provides an integration test of the full workflow
func TestIntegration(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A OUTPUT -d 192.168.0.0/16 -j ACCEPT
COMMIT
`

	// Set up mock for input/output
	inReader := strings.NewReader(input)
	var outBuffer bytes.Buffer

	// Save and restore global state
	oldDefaultDrop := defaultDrop
	oldIncludePolicies := includePolicies
	defer func() {
		defaultDrop = oldDefaultDrop
		includePolicies = oldIncludePolicies
	}()

	// Parse rules
	defaultDrop = map[string]bool{}
	rules, err := parseIPTablesRules(inReader)
	if err != nil {
		t.Fatalf("Error parsing rules: %v", err)
	}

	// Create policy
	policy := createCiliumPolicy(rules, "test-policy", "")

	// Add essential policies (since INPUT is DROP)
	includePolicies = map[string]bool{
		"ssh":            true,
		"kubernetes-api": true,
		"dns":            true,
	}
	addEssentialPolicies(&policy)

	// Marshal to YAML
	yamlData, err := yaml.Marshal(policy)
	if err != nil {
		t.Fatalf("Error marshaling policy to YAML: %v", err)
	}

	// Write to buffer
	output := fmt.Sprintf("# Generated by iptables-to-cilium\n# Default policies: INPUT=DROP, OUTPUT=ACCEPT\n%s", yamlData)
	outBuffer.WriteString(output)

	// Validate output
	outputStr := outBuffer.String()

	// Check that output contains key elements
	requiredElements := []string{
		"apiVersion: cilium.io/v2",
		"kind: CiliumClusterwideNetworkPolicy",
		"name: test-policy",
		"ingress:",
		"toPorts:",
		"port: \"22\"",
		"port: \"80\"",
		"port: \"443\"",
		"protocol: TCP",
		"icmps:",
	}

	for _, elem := range requiredElements {
		if !strings.Contains(outputStr, elem) {
			t.Errorf("Output missing required element: %s", elem)
		}
	}

	// Parse the output YAML to verify it's valid
	var parsedPolicy CiliumClusterwideNetworkPolicy
	err = yaml.Unmarshal(yamlData, &parsedPolicy)
	if err != nil {
		t.Fatalf("Output is not valid YAML: %v", err)
	}
}
