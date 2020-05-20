#! /usr/bin/env python3
from processor_network import *
from processor_database import *
import sys
import os
import pandas as pd
import time
import subprocess
#===============================================================================
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
#Analise every package sniffed live-time
def Analyse(current_path,current_protocol,current_stream):
    stream = Import_data(current_path,current_protocol) #import single stream
    series_processed = Process_data(stream) #generate features
    streams_dataframe = Store_data(series_processed) #create dataset with new features
    streams_dataframe_ml = ML_preprocess(streams_dataframe) #string to int for ml model understand
    prediction = Predict_train(current_protocol,current_stream,streams_dataframe_ml) #result of ml model
    return(prediction[0])
#===============================================================================
#Train a new model (needs full directory tree including darpa99 tcpdump dataset)
def Train(max_stream=0):
    stream = Import_train_data(max_stream)
    series_processed = Process_train_data(stream)
    streams_dataframe = Store_train_data(series_processed)
    streams_dataframe_ml = ML_train_preprocess(streams_dataframe)
    trained_model = Model_train(streams_dataframe_ml)
    pickle.dump(trained_model,open('./models/trained_model_darpa.sav','wb'))
#===============================================================================
#Verify a train acurracy (needs full directory tree including darpa99 tcpdump dataset)
def Verify(max_stream=0,week=1):
    score = Import_verify(max_stream,week);
    print('anomaly:',((int(score[0])*100)/(int(max_stream)-10000)),'%');
    print('normal:',((int(score[1])*100)/(int(max_stream)-10000)),'%');
#===============================================================================
def Handler_pkg(stream_protocol,stream_number,list_time,pkg_line):    
    for aux in range(0,len(list_time)): #Removes any stream with same number (update)
        if(int(list_time[aux][1]) == int(stream_number) and str(list_time[aux][2]) == str(stream_protocol)):
            match = aux;
    try:list_time.remove(list_time[match]);
    except:pass;

    record = (int(time.time()),int(stream_number),str(stream_protocol))
    list_time.append(record)
    with open(path+stream_protocol+'_stream_'+str(stream_number)+'.csv', 'a') as file: file.write(pkg_line+'\n');
    file.close()
#===============================================================================    
def Handler_time(list_time):
    global num_normal;
    global num_anomaly;
    global num_fail;
    global list_done_tcp;
    global list_done_udp;
    analised = list();
    for stream in list_time:
        if((int(time.time()-int(stream[0])) >= maximum_hold_time)):
            try:
                analisys = Analyse(path+stream[2]+'_stream_'+str(stream[1])+'.csv',stream[2],stream[1])
                if(analisys == 0):
                    num_normal +=1;
                    output=(stream[2]+' stream '+str(stream[1])+bcolors.OKGREEN + ' Normal Connection ' + bcolors.ENDC)
                    print(output,num_normal)
                elif(analisys == 1):
                    num_anomaly += 1;
                    output=(stream[2]+' stream '+str(stream[1])+bcolors.WARNING + ' Anomaly Connection ' + bcolors.ENDC)
                    print(output,num_anomaly);
                    with open('./logs/anomaly.txt','a') as file: file.write(output+'\n'); file.close()
            except:
                num_fail +=1;
                output=(stream[2]+' stream '+str(stream[1])+bcolors.FAIL + ' Fail in package read ' + bcolors.ENDC)
                print(output,num_fail);
                with open('./logs/fails.txt', 'a') as file:file.write(output+'\n');file.close()
            analised.append(stream) 
    for stream in analised:
        list_time.remove(stream);
        if(stream[2] == 'tcp'):list_done_tcp.append(int(stream[1]));
        elif(stream[2] == 'udp'):list_done_udp.append(int(stream[1]));
#===============================================================================
try:
    if(sys.argv[1] == 'train'):
        print('Training Model...');
        try:
            Train(sys.argv[2]);
        except:
            Train();
    elif(sys.argv[1] == 'verify'):
        print('Verifying Model Acurracy...')
        try:
            Verify(sys.argv[2],sys.argv[3]);
        except:
            Verify();
except: 
    print('Analysing Network...');
else:
    sys.exit(); 
#===================================================================================
subprocess.Popen(['./processor_shell.sh sniff'], shell=True);time.sleep(3) 
dump_file = './logs/brute_streams.csv' #Read file containing network packages
path = './logs/streams/'; #local that the streams 
global_count = 0; #last package readed
#==================================================================================
list_time = list() 
list_done_tcp = [];
list_done_udp = [];
num_anomaly=0;
num_normal=0;
num_fail=0;
maximum_hold_time = 0 
#==================================================================================
while True: 
    with open(dump_file, 'r') as file: 
        lines = file.readlines(); 
        lines = lines[global_count:len(lines)-1] 
    file.close()
    global_count += len(lines)
    #====================================================================================================
    pkg = [aux.strip() for aux in lines] 
    lines = [aux.split(',') for aux in lines] 
    index_proto = 3;
    for line in range(0,len(lines)):
        stream_pkg = lines[line];
#         try:
        if(lines[line][index_proto] == '6' and lines[line][0] != ''): 
            if(int(stream_pkg[0]) not in list_done_tcp):
                Handler_pkg('tcp',stream_pkg[0],list_time,pkg[line]);
        elif(lines[line][index_proto] == '17' and lines[line][1] != ''):
            if(int(stream_pkg[1]) not in list_done_udp):
                Handler_pkg('udp',stream_pkg[1],list_time,pkg[line]);
#         except:print('Error package ',lines[line]);continue
#================================================================================================================
    Handler_time(list_time);
    time.sleep(5) #wait 5 sec just to not overhead output and process
    
#How does a udp stream finishes? how can i detect without depending on TTL
#How to improve managing of already processed streams (eventualy memory overflow holding on list)
