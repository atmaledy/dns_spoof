# If your DNS server is caching then it's likely the real responses will 
# arrive quicker than ours. To get around this, block all returning DNS traffic

iptables -F
iptables -A FORWARD -p udp --sport 53 -d 192.168.0.6 -j DROP

