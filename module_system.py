
#! /usr/bin/env python3
from module_learning import Processor_learning;
from module_package import Processor_package
from module_stream import Processor_stream
from module_features import Processor_features
from module_common import *
import time #Used to calculate the time that a stream has not been active
#==================================================================================
class System:
    #Settings system configuration
    path_new_pkgs = './logs/dump_read.csv'; #dump file from network live-time dump
    max_hold_time = 5; #Max time without receiving packages that a stream can have before considered dead

    #Control structures
    normal_anomaly_count = [0,0]; #[0] = normal connections count. [1] anomaly connections count (output purpose)
    last_pkg_readed = 0; #Control the read flow on the dump file
    streams_tcp = []; #stores the streams instances
    streams_udp = []; #stores the streams instances
    streams_icmp = []; #stores the streams instances
    existing_streams_tcp = [] #Controls stream creation
    existing_streams_udp = [] #Controls stream creation
    existing_streams_icmp = [] #Controls stream creation
    done_streams_tcp = [] #Controls stream encerration
    done_streams_udp = [] #Controls stream encerration
    done_streams_icmp = [] #Controls stream encerration
    
    def __init__(self):
        pass;
    
    #checks network dump file to get the new packages sniffed and add them into the structure
    def Check_network(self):
        obj_package_class = Processor_package();
        lines = Read_file(self.path_new_pkgs); #lines receive the file content (COMMON.py)
        lines = lines[(self.last_pkg_readed):len(lines)] #lines updated to only the packages not readed. Discosider the last line in case that one is not fully formated yet, read it int the next loop:
        if(len(lines)>=1):
            self.last_pkg_readed += (len(lines)) #update the last package readed
            assembled_packages = obj_package_class.Assemble_packages(lines); #lines readed of the file tranformed into packages
            self.Redirect_packages(assembled_packages); #send the packages to their corresponding streams
    
    #Insert a list of packages passed by parameter into the corresponding stream
    def Redirect_packages(self,assembled_packages_list):
        tcp_protocol = 6; #code for tcp
        udp_protocol = 17; #code for udp
        for obj_package in assembled_packages_list: #run through all the packages passed;
            #Just some pointers
            pkg_protocol = 'tcp' if obj_package.protocol_type == 6 else 'udp'
            existing_streams = eval('self.existing_streams_'+pkg_protocol);
            done_streams = eval('self.done_streams_'+pkg_protocol);
            streams_vector = eval('self.streams_'+pkg_protocol);

            if(obj_package.stream not in existing_streams and obj_package.stream not in done_streams): # if stream dont exists
                if((obj_package.protocol_type == 6 and obj_package.flag == '0x00000002') #Check if is the syn package(TCP) (old streams shouldnt be considered)
                or obj_package.protocol_type == 17): 
                    obj_stream = Processor_stream(obj_package); #Creates stream
                    obj_stream.Add_pkg(obj_package); #add package on the new stream
                    existing_streams.append(obj_package.stream); #add stream number to the control
                    streams_vector.append(obj_stream); #add the stream on the list of streams
            elif(obj_package not in done_streams): #if stream exists, only insert the current package on it
                for count in range(0,len(streams_vector)): #searchs for all active streams
                    if(streams_vector[count].index == obj_package.stream): #search for the right stream
                        streams_vector[count].Add_pkg(obj_package); #add the package to the right stream
    
    #Verify if there's activity on streams packages to determine if that stream is already over and ready to be analised
    def Check_activity(self):
        for protocol in ['tcp','udp']: 
            streams_protocol = eval('self.streams_'+protocol);#just some pointers
            done_streams = eval('self.done_streams_'+protocol);#just some pointers
            for obj_stream in streams_protocol: #get every stream in the stored streams
                if(len(obj_stream.package_list) > 0): #Check if the stream already has any package
                    if((int(time.time() - obj_stream.last_modified)) >= self.max_hold_time): #if too long without activity...
                        obj_stream.Generate_features(); #Generate Machine Learn features of the stream
                        stream_dataframe = obj_stream.Generate_dataframe(); #Generates stream dataframe
                        obj_learning_class = Processor_learning(); #use predict data with model on learning module
                        prediction = obj_learning_class.Predict_data(stream_dataframe); #Analyses the stream with ML
                        Print_prediction(prediction,obj_stream,self.normal_anomaly_count); #Outputs the result of analisys
                        streams_protocol.remove(obj_stream); #do not analise this stream again
                        done_streams.append(obj_stream.index); #Add the stream to the analised list
    
