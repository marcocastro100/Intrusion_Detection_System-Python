#! /usr/bin/env python3
import sys #terminal interact
import pandas as pd
import time #discover how much time doesent come packages
import subprocess #call shell cripts subprocess.call([./shell.sh])
subprocess.Popen(['~/python/darpa99/ids/sniff.sh'], shell=True)
time.sleep(3)
dump_file = './logs/brute_streams.csv'
global_count = 0;

list_time_tcp = [] #holds the last time modified of each stream
list_time_udp = []
list_done_tcp = [] #holds the streams that already have been analised
list_done_udp = []

while True:

    with open(dump_file, 'r') as file: 
        lines = file.readlines(); #read all lines
        lines = lines[global_count:len(lines)] #holds only the lines that havent been analised
    file.close() #close the read file
    
    pkg = [aux.strip() for aux in lines] #line stay in same formatation as tshark and tcpdump export 
    lines = [aux.split(',') for aux in lines] #every feature as a position, but the formatation is altered with ''s and "'s
    
    for line in range(0,len(lines)):
        if(lines[line][0] != ''): #if tcp

            with open('./logs/tcp_csvs/tcp_stream_'+str(lines[line][0])+'.csv', 'a') as stream_file:
                stream_file.write(pkg[line]+'\n'); #print pkg(original line) on the correspondet stream file num(lines[line])
            stream_file.close()
            
            try:list_time_tcp[int(lines[line][0])] = (int(lines[line][0]),time.time()) #try to modify position
            except:list_time_tcp.append([lines[line][0],time.time()]) #case an error (not defined), define position

        elif(lines[line][1] != ''):#if udp

            with open('./logs/udp_csvs/udp_stream_'+str(lines[line][1])+'.csv', 'a') as stream_file:
                stream_file.write(pkg[line]+'\n');
            stream_file.close()
            
            try:list_time_udp[int(lines[line][1])] = (lines[line][1],time.time()) 
            except:list_time_udp.append([lines[line][1],time.time()]) 

    global_count += len(lines) 

#     print('tcp_analiseds:',list_done_tcp)
#     print('udp_analiseds:',list_done_udp)
    
#     Verify the time that the stream doesent receive pkgs
    for count in range(0,len(list_time_tcp)):
        if((int(time.time()) - int(list_time_tcp[count][1])) >= 60): #compares the time of last update in the stream
            if(int(list_time_tcp[count][0]) not in list_done_tcp):
                print('Stream',count);
                subprocess.call(['./handler.py', './logs/tcp_csvs/tcp_stream_'+str(count)+'.csv', 'tcp', str(count)])
                list_done_tcp.append(int(list_time_tcp[count][0])) #append the number of stream
                                     
    for count in range(0,len(list_time_udp)):
        if((int(time.time()) - int(list_time_udp[count][1])) >= 60):
            if(int(list_time_udp[count][0]) not in list_done_udp):
                print('Stream',count)
                subprocess.call(['./handler.py', './logs/udp_csvs/udp_stream_'+str(count)+'.csv', 'udp', str(count)])
                list_done_udp.append(int(list_time_udp[count][0]))
                                     
    time.sleep(6)
        
#Arquiteture linux: how to manage linux process to work toguether? sniff, ids, handler
#How does a udp stream finishes? how can i detect without depending on time