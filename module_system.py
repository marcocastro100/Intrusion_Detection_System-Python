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
    max_hold_time = 30; #Max time without receiving packages that a stream can have before considered dead

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
        processor_package = Processor_package();
        lines = Read_file(self.path_new_pkgs); #lines receive the file content (COMMON.py)
        lines = lines[(self.last_pkg_readed+1):len(lines)-1] #lines updated to only the packages not readed
        self.last_pkg_readed += len(lines) #update the last package readed
        assembled_packages = processor_package.Assemble_packages(lines); #lines readed of the file tranformed into packages
        self.Redirect_packages(assembled_packages); #send the packages to their right streams
    
    #Insert a list of packages passed by parameter into the corresponding stream
    def Redirect_packages(self,assembled_packages_list):
        tcp_protocol = 6; #code for tcp
        udp_protocol = 17; #code for udp
        icmp_protocol = 1;
        for obj_package in assembled_packages_list: #run through all the packages passed;
            if(obj_package.protocol_type == tcp_protocol): #creates some pointer to not use eval()
                existing_streams = self.existing_streams_tcp;
                done_streams = self.done_streams_tcp;
                streams_vector = self.streams_tcp;
            elif(obj_package.protocol_type == udp_protocol):
                existing_streams = self.existing_streams_udp;
                done_streams = self.done_streams_udp;
                streams_vector = self.streams_udp;
            elif(obj_package.protocol_type == icmp_protocol):
                existing_streams = self.existing_streams_icmp;
                done_streams = self.done_streams_icmp;
                streams_vector = self.streams_icmp;

            if(obj_package.stream not in existing_streams and obj_package.stream not in done_streams): # if stream dont exists
                if(obj_package.protocol_type == 6 and obj_package.flag == '0x00000002'): #Check if is the syn package(TCP) (old streams shouldnt be considered)
                    obj_stream = Processor_stream(obj_package); #Creates stream
                    obj_stream.Add_pkg; #add package on the new stream
                    existing_streams.append(obj_package.stream); #add stream number to the control
                    streams_vector.append(obj_stream); #add the stream on the list of streams
            else: #if exists, only insert the current package
                for count in range(0,len(streams_vector)): #searchs for all active streams
                    if(streams_vector[count].index == obj_package.stream): #search for the right stream
                        streams_vector[count].Add_pkg(obj_package); #add the package to the right stream
    
    #Verify if there's activity on streams packages to determine if that stream is already over and ready to be analised
    def Check_activity(self):
        for protocol in ['tcp','icmp','udp']: 
            streams_protocol = eval('self.streams_'+protocol);#just some pointers
            done_streams = eval('self.done_streams_'+protocol);#just some pointers
            for obj_stream in streams_protocol: #get every stream in the stored streams
                if(len(obj_stream.package_list) > 0): #Check if the stream already has any package
                    if((int(time.time() - obj_stream.last_modified)) >= self.max_hold_time): #if too long without activity...
                        obj_stream.Generate_features(); #Generate features of the stream
                        stream_dataframe = obj_stream.Generate_dataframe(); #Generates stream dataframe
                        obj_learning = Processor_learning(); #use predict data with model on learning module
                        prediction = obj_learning.Predict_data(stream_dataframe); #Analyses the stream with ML
                        Print_prediction(prediction,obj_stream,self.normal_anomaly_count); #Outputs the result of analisys
                        streams_protocol.remove(obj_stream); #do not analise this stream again
                        done_streams.append(obj_stream.index); #Add the stream to the analised list
    