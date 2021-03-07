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

def Run_Sniff():
    subprocess.Popen(['./module_shell.sh sniff'], shell=True); #starts tcpdump package sniff process
    time.sleep(5)
    obj_System_class = System();
    while(True): #Constantly sniff the network and manage the streams
        copyfile('./logs/brute_streams.csv', './logs/dump_read.csv');#copy dump file for reading without sniff interference
        obj_System_class.Check_network(); #checks network new pacakges and insert them on the correct streams
        obj_System_class.Check_activity();#verifty how long the streams has been without activity
        # time.sleep(5); #Holds 5 sec to the next iteration

def Dataset(mode='verify',week=['1','2']):
    obj_database_class = Processor_database();
    obj_database_class.Load_dataset(mode,week);

#Handles the arguments: 
    # train = train a new ML model, 
    # verify or verify + 1 or 2 = see how model scores the dataset data, 
    # No arguments or sniff argument goes straight to network sniffing:
num_args = len(sys.argv);
if(num_args == 1): #No arguments
    Run_Sniff();
elif(num_args == 2):
    if(sys.argv[1] == 'sniff'):
        Run_Sniff(); 
    elif(sys.argv[1] == 'train' or sys.argv[1] == 'verify'):
        Dataset(sys.argv[1]);
elif(num_args == 3):
    Dataset(sys.argv[1],sys.argv[2]); #Mode (train/verify), Week (1/2/3)