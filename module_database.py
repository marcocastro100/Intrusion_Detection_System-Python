#! /usr/bin/env python3
from module_common import Print_prediction, Features_names, Read_file
from module_stream import Processor_stream
from module_package import Processor_package
from module_learning import Processor_learning
import pandas as pd
import os
class Processor_database:
    #Contains a dataframe base, stream features names, ans stream features that the ML model will analise
    def __init__(self):
        self.train_dataframe = pd.DataFrame(columns = Features_names); #this dataframe hold all the features (all streams) #Features_names = common.py
        #TRAIN model configurations for processing:
        self.list_weeks = ['1','2','3']; #Weeks
        self.list_protocols = ['tcp']; #protocols ['tcp','udp','icmp']
        self.list_modes = ['inside']; #modes ['inside','outside']
        self.list_days = ['1','2','3','4','5']; #days

    #Generates the model  
    def Load_dataset(self,mode_run,week): #Week deprecated
        streams_dataframe_list = list();
        obj_learning = Processor_learning(); #Uses the functions on learning class
        for week in self.list_weeks: #Dataset Logic (Attack or Normal)
            for protocol in self.list_protocols: #Dataset Logic 
                for mode in self.list_modes:  #Dataset Logic (sniff mode) #going without outise for now
                    for day in self.list_days: #Dataset Logic (days of week)
                        if(mode_run=='train'):
                            print('Processing week',week,protocol,mode,'day',day);
                            self.Structure_data(week,protocol,mode,day,mode_run); #assemble packages | stream
                        elif(mode_run=='verify'):
                            dataframe_list = self.Structure_data(week,protocol,mode,day,mode_run);
                            for dataframe in dataframe_list: #gets every dataframe generated at the current loop
                                streams_dataframe_list.append(dataframe); #saves the current streams
        if(mode_run=='train'):model = obj_learning.Train_model(self.train_dataframe); #trains and saves the model
        elif(mode_run=='verify'):
            normal_anomaly_count = [0,0]; #To check number of normal and anomaly connections idetified
            for dataframe in streams_dataframe_list:
                prediction = obj_learning.Predict_data(dataframe[0]);
                Print_prediction(prediction,dataframe[1],normal_anomaly_count);#output predicion
    
    #Modeling packages,streams,features from dataset data to dataframe 
    def Structure_data(self,week,protocol,mode,day,mode_run):
        path_dataset = ('../Week'+week+'/streams/'+protocol+'_'+mode+'_'+day+'/') #Path to dataset streams folder SO
        dataframe_list = []; #stores the dataframes of each stream separately for Verify mode)
        max_streams = int(Read_file(path_dataset+protocol+'_'+mode+'_'+day+'_numstream.csv')[0]) #read the total number of streams
        for count in range(0,max_streams): #reads from stream 0 until the specified stream on init
            path_stream = (path_dataset+protocol+'_stream_'+str(count)+'.csv'); #path to each stream SO
            if(os.path.exists(path_stream) and os.stat(path_stream).st_size != 0):#check if exists the streams file amd not empty
                readed_packages = Read_file(path_stream); #read the file (COMMON.py)
                processor_package = Processor_package(); #Use function assemble_packages;
                list_packages = processor_package.Assemble_packages(readed_packages); #assemble the lines into packages
                stream = Processor_stream(list_packages); #creates the structure of the stream;
                stream.Generate_features(); #generates the features
                features_dataframe = stream.Generate_dataframe(week); #structures the features in pandas table
                if(mode_run=='train'):self.Join_dataframe(features_dataframe); #append current dataframe to the final dataframe
                elif(mode_run=='verify'):dataframe_list.append([features_dataframe,stream,week]); #saves the stream 
            else:print('week',week,protocol,mode,day,'stream',count,' Inexists or empty file!');
        if(mode_run=='verify'):return(dataframe_list);
    
    #Concatenate a dataframe to the main dataframe of the class
    def Join_dataframe(self,features_dataframe):
        self.train_dataframe = self.train_dataframe.append(features_dataframe);

    
#=================================================================================
