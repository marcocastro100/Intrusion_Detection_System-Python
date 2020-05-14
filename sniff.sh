#! /bin/bash
#SNIFF.SH
#Deletion of old folders
./free_ram_memory.sh
sudo rm -r logs
#Creates necessary folders IF they not exists already
if [ ! -e ./logs ];then mkdir logs; fi
if [ ! -e ./logs/tcp_csvs ];then mkdir ./logs/tcp_csvs; fi
if [ ! -e ./logs/udp_csvs ];then mkdir ./logs/udp_csvs; fi
#Call tcpdump for sniffing the network packages, and for each package, sending the result to tshark to extract relevant features for machine learning analisys
sudo tcpdump -q -w ./logs/network_dump.pcap tcp or udp |
sudo tshark -q -T fields -e tcp.stream -e udp.stream -e frame.time_relative -e ip.proto -e _ws.col.Protocol -e tcp.flags -e tcp.urgent_pointer -e frame.cap_len  -e ip.flags -e tcp.window_size_value -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e ip.src -e ip.dst -E header=n -E separator=, -E occurrence=f > ./logs/brute_streams.csv

