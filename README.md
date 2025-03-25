# iptables-to-cilium-converter
This is a highly experimental vibecoded (yes, really :P) converter from iptables rules to cilium host firewall policy. use at your own risk, i don't even nearly have a clue what's going on ;) 
No, really, just bc. someone in the cilium slack asked if there is a tool, there is none, so I was bored and thought "why not try" :)

Used Claude 3.7 Sonnet and openAI for this. Took 15 min, so more or less a joke. I repeat: USE AT YOUR OWN RISK :-P

Usage with the (also llm-generated) example file iptablesrules.txt: 

0) Save your rules via e.g. `iptables-save > iptablesrules.txt`
1) run `go build . -o iptables-cilium-converter` 
2) run `./iptables-cilium-converter --input iptablesrules.txt --output policy.yaml`
3) apply your policy.yaml and get a beer. What could possibly go wrong ;-) (no, really, don't do this. I have no idea if this works. holy.)