#! /usr/bin/env python3
from handler import *
import sys #terminal interact
import pandas as pd
import time #calculate ocious time on stream
import subprocess #call shell cripts subprocess.call

subprocess.Popen(['~/python/darpa99/ids/sniff.sh'], shell=True)
time.sleep(3) #Time for sniff creates folders

dump_file = './logs/brute_streams.csv'
global_count = 0;
list_time_tcp = [];list_time_udp = [] #holds the last time modified of each stream
list_done_tcp = [];list_done_udp = [] #holds the streams that already have been analised
num_anomaly = 0;num_normal =0; #holds the number of anomaly and normal connections detected

while True: #Visits dump files continualy since tcpdump is dumping new data all the time

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
            except:list_time_tcp.append([lines[line][0],time.time()]) #case an error (not defined), append to the position

        elif(lines[line][1] != ''):#if udp

            with open('./logs/udp_csvs/udp_stream_'+str(lines[line][1])+'.csv', 'a') as stream_file:
                stream_file.write(pkg[line]+'\n');
            stream_file.close()
            
            try:list_time_udp[int(lines[line][1])] = (lines[line][1],time.time()) 
            except:list_time_udp.append([lines[line][1],time.time()]) 

    global_count += len(lines)
    maximum_hold_time = 0 #time to consider the connection over
    
#     Verify the time that the stream doesent receive pkgs, calling the handler if execced time (connection over)
    for count in range(0,len(list_time_tcp)):
        if((int(time.time()) - int(list_time_tcp[count][1])) >= maximum_hold_time): #compares the time of last update in the stream
            if(int(list_time_tcp[count][0]) not in list_done_tcp):
                analisys = Handler('./logs/tcp_csvs/tcp_stream_'+str(count)+'.csv','tcp',str(count),'analyse')
                if(analisys == 1):num_anomaly += 1;
                elif(analisys == 0):num_normal +=1;
#                 subprocess.call(['./handler.py', './logs/tcp_csvs/tcp_stream_'+str(count)+'.csv', 'tcp', str(count),'analyse'])
#                 subprocess.call(['./handler.py', '../Week1/streams/tcp_csvs/tcp_stream_'+str(count)+'.csv', 'tcp', str(count),'train'])
#                 subprocess.call(['./handler.py', '../Week2/streams/tcp_csvs/tcp_stream_'+str(count)+'.csv', 'tcp', str(count),'train'])
    
                list_done_tcp.append(int(list_time_tcp[count][0])) #append the number of stream
                                     
    for count in range(0,len(list_time_udp)):
        if((int(time.time()) - int(list_time_udp[count][1])) >= maximum_hold_time):
            if(int(list_time_udp[count][0]) not in list_done_udp):
                analisys = Handler('./logs/udp_csvs/udp_stream_'+str(count)+'.csv','udp',str(count),'analyse')
                if(analisys == 1):num_anomaly += 1;
                elif(analisys == 0):num_normal +=1;
#                 subprocess.call(['./handler.py', './logs/udp_csvs/udp_stream_'+str(count)+'.csv', 'udp', str(count),'analyse'])
#                 subprocess.call(['./handler.py', '../Week1/streams/udp_csvs/udp_stream_'+str(count)+'.csv', 'udp', str(count),'train'])
#                 subprocess.call(['./handler.py', '../Week2/streams/udp_csvs/udp_stream_'+str(count)+'.csv', 'udp', str(count),'train'])
    
                list_done_udp.append(int(list_time_udp[count][0]))
    print(num_anomaly, num_normal) #print number of ataqs and normal connections analised
    time.sleep(5) #wait 5 sec just to not overhead output and process
        
#Arquiteture linux: how to manage linux process to work toguether? sniff, ids, handler. ::module.subprocess, make a sudo before
#How does a udp stream finishes? how can i detect without depending on time
#How to improve managing of already processed streams (eventualy memory overflow holding on list)
