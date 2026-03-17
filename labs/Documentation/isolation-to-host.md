# Block access from containeurs to host
sudo iptables -I INPUT -s 198.18.100.0/24 -j DROP
sudo iptables -I INPUT -s 198.18.200.0/24 -j DROP

# Autorize only DNS and routing 
sudo iptables -I INPUT -s 198.18.100.0/24 -p udp --dport 53 -j ACCEPT
sudo iptables -I INPUT -s 198.18.200.0/24 -p udp --dport 53 -j ACCEPT
