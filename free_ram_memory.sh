for pid in $(ps -aux | grep "tcpdump" | tr -s ' '| cut -d ' ' -f 2); do $(sudo kill $pid); done
for pid in $(ps -aux | grep "tshark" | tr -s ' '| cut -d ' ' -f 2); do $(sudo kill $pid); done
for pid in $(ps -aux | grep "sniff.sh" | tr -s ' '| cut -d ' ' -f 2); do $(sudo kill $pid); done
for pid in $(ps -aux | grep "handler.py" | tr -s ' '| cut -d ' ' -f 2); do $(sudo kill $pid); done
for pid in $(ps -aux | grep "ids.py" | tr -s ' '| cut -d ' ' -f 2); do $(sudo kill $pid); done
