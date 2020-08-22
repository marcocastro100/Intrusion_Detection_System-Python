from processor_stream import *
from processor_database import *
import sys #Working with OS
import pickle #Importation and exportation of models
import pandas as pd

#=================================================================================================================
#Original features of all packages sniffed in the network
Original_features = ['tcp_stream','udp_stream','relative_time','protocol_type','service','flag','urgent',
'length','ip_flag','window_size','tcp_srcport','tcp_dstport','udp_srcport','udp_dstport','ip_src','ip_dst']
#Generated features pós processing the packages
Stream_features=['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','urgent','counts','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate','length','window_size']
#=================================================================================================================
#import packages from dump file to python_pandas structure
def Import_data(current_path,current_protocol):
    stream = pd.read_csv(current_path,names=(Original_features))
    #Protocol Treatment
    if(current_protocol == 'tcp'):
        stream['src_port'] = stream['tcp_srcport']
        stream['dst_port'] = stream['tcp_dstport']
    elif(current_protocol == 'udp'):
        stream['src_port'] = stream['udp_srcport']
        stream['dst_port'] = stream['udp_dstport']
    stream['classe'] = 'unknow'
    #in case sniffing not get a full package
    stream = stream.fillna(method='ffill'); 
    stream = stream.fillna(method='bfill');
    stream = stream.fillna(0);
    return(stream)
#==================================================================================================================
#Generate features of the connection packages as one
def Process_data(stream):
    if(len(stream)>0): #case list not empty
        series_processed = [] 
        features_serie = [] 
        features_serie.append(Duration(stream))
        features_serie.append(Src_dst_bytes(stream))
        features_serie.append(Protocol(stream))
        features_serie.append(Service(stream))
        features_serie.append(Land(stream))
        features_serie.append(Flags(stream))
        features_serie.append(Len_win_urg_clas(stream))
        features_serie.append(Srvcount(stream))
        series_processed.append(pd.Series(features_serie)) #stores every stream in single position
        return(series_processed)
    else:print('Error num_lines')
#==================================================================================================================
#Store the features generated in dataframe for analisys
def Store_data(series_processed):
    streams_dataframe = pd.DataFrame(columns=Stream_features)
    for count in range(0, len(series_processed)):
        vet_aux = [] #attention to the order in Stream_features
        vet_aux.append(series_processed[count][0]) #duration
        vet_aux.append(series_processed[count][2]) #protocol
        vet_aux.append(series_processed[count][3]) #service
        vet_aux.append(series_processed[count][5]) #flag
        vet_aux.append(series_processed[count][1][0]) #src
        vet_aux.append(series_processed[count][1][1]) #dst
        vet_aux.append(series_processed[count][4]) #land
        vet_aux.append(series_processed[count][6][2]) #urg
        vet_aux.append(series_processed[count][7][0])
        vet_aux.append(series_processed[count][7][1])
        vet_aux.append(series_processed[count][7][2])
        vet_aux.append(series_processed[count][7][3])
        vet_aux.append(series_processed[count][7][4])
        vet_aux.append(series_processed[count][7][5])
        vet_aux.append(series_processed[count][7][6])
        vet_aux.append(series_processed[count][7][7])
        vet_aux.append(series_processed[count][7][8])
        vet_aux.append(series_processed[count][6][0]) #len
        vet_aux.append(series_processed[count][6][1]) #win
        streams_dataframe.loc[count] = vet_aux
    return(streams_dataframe)
#==================================================================================================================
#___Preprocessing categorical data into int64|float
def ML_preprocess(streams_dataframe):
    from sklearn.preprocessing import LabelEncoder;le = LabelEncoder() #None to Literal to int
    #Coercing type of data inside the df
    streams_dataframe.duration = streams_dataframe.duration.astype(float)
    streams_dataframe.protocol_type = streams_dataframe.protocol_type.astype(str)
    streams_dataframe.service = streams_dataframe.service.astype(str)
    streams_dataframe.flag = streams_dataframe.flag.astype(str)
    streams_dataframe.src_bytes = streams_dataframe.src_bytes.astype(float)
    streams_dataframe.dst_bytes = streams_dataframe.dst_bytes.astype(float)
    streams_dataframe.urgent = streams_dataframe.urgent.astype(int)
    streams_dataframe.length = streams_dataframe.length.astype(float)
    streams_dataframe.window_size = streams_dataframe.window_size.astype(float)
    streams_dataframe.counts = streams_dataframe.counts.astype(int)
    streams_dataframe.serror_rate = streams_dataframe.serror_rate.astype(int)
    streams_dataframe.rerror_rate = streams_dataframe.rerror_rate.astype(int)
    streams_dataframe.same_srv_rate = streams_dataframe.same_srv_rate.astype(int)
    streams_dataframe.diff_srv_rate = streams_dataframe.diff_srv_rate.astype(int)
    streams_dataframe.srv_count = streams_dataframe.srv_count.astype(int)
    streams_dataframe.srv_serror_rate = streams_dataframe.srv_serror_rate.astype(int)
    streams_dataframe.srv_rerror_rate = streams_dataframe.srv_rerror_rate.astype(int)
    streams_dataframe.srv_diff_host_rate = streams_dataframe.srv_diff_host_rate.astype(int)
    
    streams_dataframe.protocol_type = le.fit_transform(streams_dataframe.protocol_type)
    streams_dataframe.service = le.fit_transform(streams_dataframe.service)
    streams_dataframe.flag = le.fit_transform(streams_dataframe.flag)
    return(streams_dataframe)
#==================================================================================================================
#Simple predict with the data and the model imported
def Predict_train(current_protocol,current_stream,streams_dataframe_ml):
    trained_model = pickle.load(open('./models/trained_model_darpa.sav','rb')) #import model from a file
    prediction = trained_model.predict(streams_dataframe_ml) #run model with 1 line dataframe
    return(prediction)
#==================================================================================================================