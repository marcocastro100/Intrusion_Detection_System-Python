#! /bin/bash
#SNIFF.SH
#Deletion of old folders
sudo rm -r tcp_csvs
sudo rm -r udp_csvs
sudo rm -r logs
#Creates necessary folders IF they not exists already
if [ ! -e tcp_csvs ];then mkdir tcp_csvs; fi
if [ ! -e udp_csvs ];then mkdir udp_csvs; fi
if [ ! -e logs ];then mkdir logs; fi
#Call tcpdump for sniffing the network packages, and for each package, sending the result to tshark to extract the features
sudo tcpdump -w ./logs/log_dump.pcap tcp or udp |
sudo tshark -T fields -e tcp.stream -e udp.stream -e _ws.col.No. -e _ws.col.UTCTime -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Protocol -e frame.cap_len -e ip.proto -e ip.flags -e tcp.srcport -e tcp.dstport -e tcp.flags -e udp.srcport -e udp.dstport -e tcp.urgent_pointer -e tcp.window_size_value -E header=n -E separator=, -E occurrence=f > ./logs/streams.csv

