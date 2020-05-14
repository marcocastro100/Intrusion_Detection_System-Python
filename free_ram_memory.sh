for pid in $(ps -aux | grep "tcpdump" | cut -d ' ' -f 6); do $(sudo kill $pid); done
for pid in $(ps -aux | grep "tshark" | cut -d ' ' -f 6); do $(sudo kill $pid); done
for pid in $(ps -aux | grep "sniff.sh" | cut -d ' ' -f 6); do $(sudo kill $pid); done
for pid in $(ps -aux | grep "handler.py" | cut -d ' ' -f 6); do $(sudo kill $pid); done
for pid in $(ps -aux | grep "ids.py" | cut -d ' ' -f 6); do $(sudo kill $pid); done
