# uknowit
inspired by mongol. The method is Adjusted. You know what it does.
## detect_fw.py
depend on: `scapy`

Notice:
* Host should be outside of China.
* We should block the RST sent by us.`iptables -A OUTPUT -p tcp --dport 80 --tcp-flags RST RST -j DROP`
