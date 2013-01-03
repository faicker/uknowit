# uknowit
inspired by mongol. The method is Adjusted. You know what it does.
## detect\_fw.py
depend on: `scapy`

Notice:
* Host should be outside of China.
* We should block the RST sent by us.`iptables -A OUTPUT -p tcp --dport 80 --tcp-flags RST RST -j DROP`
* This method can't find it! Because the traffic is mirrored to IDS.
