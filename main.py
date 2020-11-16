#! /usr/bin/env python3
from module_database import Processor_database;
from module_system import System;
import sys #Deal with arguments passed to the script
import subprocess #Calls for the sniff program
from shutil import copyfile
import time
#Ignore warning mesages (old versions)
import warnings
warnings.filterwarnings("ignore")

def Run():
    subprocess.Popen(['./module_shell.sh sniff'], shell=True);time.sleep(3) #starts tcpdump package sniff process
    sys = System();
    while(True): #Constantly sniff the network and manage the streams
        copyfile('./logs/brute_streams.csv', './logs/dump_read.csv');#dump file copy for reading without sniff interference
        sys.Check_network(); #checks network new pacakges and insert them on the correct streams
        sys.Check_activity();#verifty how long the streams has been without activity

def Dataset(mode='verify',week=['1','2']):
    database = Processor_database();
    database.Load_dataset(mode,week);

#Handles the arguments: train = train a new ML model, verify or verify + 1 or 2 = see how model scores the dataset data, no arguments or sniff argument goes to network sniffing.
num_args = len(sys.argv);
if(num_args == 1):Run();
elif(num_args == 2):
    if(sys.argv[1] == 'sniff'):Run(); 
    elif(sys.argv[1] == 'train' or sys.argv[1] == 'verify'):Dataset(sys.argv[1]);
elif(num_args == 3):
    Dataset(sys.argv[1],sys.argv[2]); #Verify model, week number to verify (normal1 x anomaly2)
    
    
    
    

    
    
    
    
    
    

