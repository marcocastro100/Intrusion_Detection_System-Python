#==================================TRAIN_FUNCTIONS===========================================================================
import pandas as pd
import os
import sys
import pickle
import numpy as np
from stream_functions import *
#==================================================================================================================
def import_train_data():
    Original_features = ['count','date1','date2','relative_time','ip_src','ip_dst','service','length','protocol_type',
                 'ip_flag','src_port','dst_port','flag','urgent','window_size']

    tcp_list = []
    udp_list = []
    icmp_list = []
    print('Importing Intrusion network Logs for model training...')
    for protocol in ['tcp','udp']:
        for week in ['1','2']:
            path = ('../Week'+week+'/streams/'+protocol+'_csvs/')
            num_streams = int(pd.read_csv(path+protocol+'_num_streams.csv').iloc[-1]);
            df_list = eval(protocol+'_list')
            
            for count in range(0,10000):
                if(os.path.exists(path+protocol+'_stream_'+str(count)+'.csv')):
                    stream = pd.read_csv((path+protocol+'_stream_'+str(count)+'.csv'),names=(Original_features)); #importação
                    if(protocol != 'tcp'):
                        stream['flag'] = '0x00000000'
                        stream['urgent'] = 0
                        stream['window_size'] = 0
                if(week == '2'): stream['classe'] = 'anomaly'
                elif(week == '3' or week == '1'): stream['classe'] = 'normal'
                else: stream['classe'] = 'unknow'
                df_list.append(stream);
                
    print('Done!')
    return(tcp_list,udp_list,icmp_list)
#==================================================================================================================
def process_train_data(lists_imported):
    #Store the stream related features of every stream for post unification on dataframe
    series_processed = [] 
    print('Processing network data streams...')
    #___Calculo e adição de Features de cada Stream
    tcp_stream = lists_imported[0];
    udp_stream = lists_imported[1];
    icmp_stream = lists_imported[2];
    for protocol in ['tcp','udp']:
        if (protocol == 'tcp'): num_streams = len(tcp_stream); 
        elif (protocol == 'udp'): num_streams = len(udp_stream);     
        elif (protocol == 'icmp'): num_streams = len(icmp_stream);

        for count in range(0, num_streams):
            current_dataframe = eval(protocol+'_stream['+str(count)+']')
            if(current_dataframe.empty == True):continue # Caso o dataframe esteja vazio, continuar sem dar error
                
            features_serie = [] #Guarda os resultados de cada loop
            #____Functions
            features_serie.append(Duration(current_dataframe))
            features_serie.append(Src_dst_bytes(current_dataframe))
            features_serie.append(Protocol(current_dataframe))
            features_serie.append(Service(current_dataframe))
            features_serie.append(Land(current_dataframe))
            features_serie.append(Flags(current_dataframe))
            features_serie.append(Len_win_urg_clas(current_dataframe))
            features_serie.append(Srvcount(current_dataframe))
            series_processed.append(pd.Series(features_serie)) #Grava os elementos do loop como uma tupla
    print('Done!')
    return(series_processed)
#==================================================================================================================
def store_train_data(series_processed):
    Stream_features=['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','urgent','counts','srv_count',
                     'serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
                     'srv_diff_host_rate','length','window_size','classe']
    print('Structuring data for Machine Learning...')
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
        vet_aux.append(series_processed[count][6][3])  #classe
        streams_dataframe.loc[count] = vet_aux
    print('done!')
    return(streams_dataframe)
#==================================================================================================================
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import SGDClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier #neural
from sklearn.preprocessing import StandardScaler #neural
from sklearn.metrics import accuracy_score #Calculo de precisão
from sklearn.feature_selection import RFE #Seleção de features importantes
from sklearn.model_selection import train_test_split 
#==================================================================================================================
def Algorithms(algorithm,X_train,y_train,X_test,y_test):
    if(algorithm == 1):model = GaussianNB();name_alg = "Naive Bayes"
    elif(algorithm == 2):model = SGDClassifier(loss='modified_huber',shuffle=True,random_state=101);name_alg = "Stocastic"
    elif(algorithm == 3):model = DecisionTreeClassifier(max_depth=10,random_state=101,max_features=None,min_samples_leaf=15);name_alg = "Decision Tree"
    elif(algorithm == 4):model = LogisticRegression();name_alg = "Logistic Regression"
    elif(algorithm == 5):model = MLPClassifier(solver='lbfgs', alpha=1e-5, hidden_layer_sizes=(5, 2), random_state=15);name_alg = "Neural Network"
    elif(algorithm == 6):model = RandomForestClassifier(n_estimators=70,oob_score=True,n_jobs=-1,random_state=101,max_features=None,min_samples_leaf=30);name_alg = "Random Forest"
    model.fit(X_train,y_train)
    y_pred = model.predict(X_test) 
    print(name_alg,accuracy_score(y_test, y_pred))
    return(accuracy_score(y_test, y_pred),model)
#==================================================================================================================
def ML_train_preprocess(streams_dataframe):
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
    streams_dataframe.classe = streams_dataframe.classe.astype(int)
    streams_dataframe.protocol_type = le.fit_transform(streams_dataframe.protocol_type)
    streams_dataframe.service = le.fit_transform(streams_dataframe.service)
    streams_dataframe.flag = le.fit_transform(streams_dataframe.flag)
    return(streams_dataframe)
#==================================================================================================================
def model_train(streams_dataframe_ml):
    Stream_features=['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','urgent','counts','srv_count',
                     'serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
                     'srv_diff_host_rate','length','window_size']
    
    X_train, X_test, y_train, y_test = train_test_split(streams_dataframe_ml[Stream_features],
                                                        streams_dataframe_ml.classe,
                                                        test_size=0.33,random_state=42) 
    print(X_train,y_train,X_test,y_test)
    print('****** Algorithms Score: *******')
    high = 0 
    index = 0 
    for count in range(1,7):
        performance = Algorithms(count,X_train,y_train,X_test,y_test)
        if performance[0] > high:
            high=performance[0]
            index=count
            best_model = performance[1]
    print('Model Trained!')
    return(best_model)
