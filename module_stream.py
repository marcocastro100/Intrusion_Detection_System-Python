import time
import pandas as pd
from module_features import Processor_features
class Processor_stream:
    def __init__(self,package):
        self.last_modified = int(time.time()); #Controls when the last action of the stream has been seened
        if(isinstance(package, list)): #check if is a list of package objects (TRAIN MODE)
            self.index = package[0].stream;
            self.package_list = package;
            self.protocol = package[0].protocol_type;
        else: #if is a unique package (NETWORK MODE)
            self.index = package.stream;
            self.package_list = [];
            self.protocol = package.protocol_type;
    
    #Add a single package passed by parameter in the stream
    def Add_pkg(self,obj_package):
        self.package_list.append(obj_package);
        self.last_modified  = int(time.time()); #resets the last seened
    
    #Creates the features in base of all the packages in the stream (features stays holded into the stream itself)
    def Generate_features(self):
        processor_features = Processor_features(self.package_list); #instatiate a processor to create the features
        #stores every feature separately in the stream
        self.duration = processor_features.Duration(self.package_list);
        self.src_bytes,self.dst_bytes = processor_features.Src_dst_bytes(self.package_list);
        self.protocol = processor_features.Protocol(self.package_list);
        self.service = processor_features.Service(self.package_list);
        self.land = processor_features.Land(self.package_list);
        self.flag = processor_features.Flags(self.package_list);
        self.len,self.win,self.urg,self.clas = processor_features.Len_win_urg_clas(self.package_list);
        (self.count,self.srv_count,self.serror_rate,self.srv_serror_rate,self.rerror_rate,
         self.srv_rerror_rate,self.same_srv_rate,self.diff_srv_rate,self.srv_diff_host_rate
        ) = processor_features.Srvcount(self.package_list);
        
    #Store the features on a dataframe (table format (ML))
    def Generate_dataframe(self,classe='NaN'):#classe = Define if normal or anomaly connection depending on week (TRAIN)
        #Append every feature to the list of features
        self.features = [];
        self.features.append(self.duration)
        self.features.append(self.src_bytes)
        self.features.append(self.dst_bytes)
        self.features.append(self.land)
        self.features.append(self.flag)
        self.features.append(self.service)
        self.features.append(self.protocol)
        self.features.append(self.len)
        self.features.append(self.win)
        self.features.append(self.urg)
        self.features.append(self.count)
        self.features.append(self.srv_count)
        self.features.append(self.serror_rate)
        self.features.append(self.srv_serror_rate)
        self.features.append(self.rerror_rate)
        self.features.append(self.srv_rerror_rate)
        self.features.append(self.same_srv_rate)
        self.features.append(self.diff_srv_rate)
        self.features.append(self.srv_diff_host_rate)
        self.features.append(classe) #normal or attack. or NaN in the case of not training a model
        features_names=['duration','src_bytes','dst_bytes','land','flag','service','protocol_type',
                 'length','window_size','urgent','counts','srv_count','serror_rate','srv_serror_rate',
                 'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate','classe']
        #Creates a one row dataframe with the list of the features generated, and index column with the features names
        features_dataframe = pd.DataFrame([self.features],columns = features_names)
        return(features_dataframe);
#=================================================================================