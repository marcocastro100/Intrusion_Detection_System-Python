#!/usr/bin/env python3
# coding: utf-8

# In[22]:


#____Bibliotecas padrão
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
import time
import os
warnings.filterwarnings('ignore') #ignorar mensagens de aviso
#==================================================================================================================
#Features da importação bruta tcpdump
Original_features = ['count','date1','date2','relative_time','ip_src','ip_dst','service','length','protocol','ip_flag','src_port','dst_port','tcp_flag','urgent','window_size']

Stream_features=['duration','src_bytes','dst_bytes','protocol_type','service','land',
                 'flags','length','window_size','urgent','classe','counts','serror_rate','rerror_rate',
                 'same_srv_rate','diff_srv_rate','srv_count','srv_serror_rate',
                 'srv_rerror_rate','srv_diff_host_rate']
#==================================================================================================================
#________Verificação de correta conversão pcap para csv (demora), usar quando ouver problemas de importação
def Debug(stream):
    for line_count in range(0,stream.shape[0]):
        try:
            int(stream.iloc[line_count]['frame.cap_len'])
        except:
            print('Tentando excluir ',protocol,' week ',week,' stream ',count,' line ',line_count)
            stream.drop(stream.iloc[line_count])
#==================================================================================================================
#_________Função que deixa tcp, udp e icmp com a mesmo formatação
def Stream_filter(protocol,week,count,path):
    #Leitura pelo pandas
    stream = pd.read_csv((path+protocol+'_stream_'+count+'.csv'),names=(Original_features)); #importação
    #Udp e Icmp não tem os valores especificados, logo é necessário atribuir esses valores padrões
    if(protocol != 'tcp'):
        stream['tcp_flag'] = '0x00000000'
        stream['urgent'] = 0
        stream['window_size'] = 0
    #Classifica os pacotes em normal e ataque para treinamento do modelo, dependendo da semana em questão (week2 ==  atack)
    if(week == '2'): stream['classe'] = 'anomaly'
    elif(week == '3' or week == '1'): stream['classe'] = 'normal'
    else: stream['classe'] = 'unknow'
    #Cria a features stream_num (caso seja não prático trabalhar separadamente com as listas de tcp, udp e icmp)
    stream['stream_num'] = count; #adiciona feature contendo o numero da stream
    return(stream)
#==================================================================================================================
#____Duration Feature
def Duration(current_dataframe):
    first_relative_time = float(current_dataframe.iloc[0]["relative_time"]); #Tempo relativo da primeira linha
    last_relative_time = float(current_dataframe.iloc[-1]["relative_time"]); #Tempo relativo da ultima linha
    duration = last_relative_time - first_relative_time
#     current_dataframe['duration'] = duration #Adiciona a duration da stream em todos os seus pacotes
    return(duration)
#==================================================================================================================
#____Src and dst bytes
def Src_dst_bytes(current_dataframe):
    if((current_dataframe['ip_src'].unique()).shape[0] == 1): #Verifica se ambos os hosts enviam dados (icmp não)
        source = (current_dataframe['ip_src'].unique())[0] #define o source da conexão
        destination = (current_dataframe['ip_dst'].unique())[0]#define o destination da conexão
    else:
        source = (current_dataframe['ip_src'].unique())[0]
        destination = (current_dataframe['ip_src'].unique())[1]
        
    src_bytes = 0 #total de bytes enviados pelo source
    dst_bytes = 0 #total de bytes enviados pelo destination
    for line_count in range(0,current_dataframe.shape[0]): #Percorre todas as linhas do dataset
        if(current_dataframe.iloc[line_count]['ip_src'] == source):
            src_bytes += int(current_dataframe.iloc[line_count]['length']);
        elif(current_dataframe.iloc[line_count]['ip_src'] == destination):
            dst_bytes += int(current_dataframe.iloc[line_count]['length']);
#     current_dataframe['src_bytes'] = src_bytes
#     current_dataframe['dst_bytes'] = dst_bytes
    return(src_bytes,dst_bytes)
#==================================================================================================================
#_____Land Feature (src and dst ports equal)
def Land(current_dataframe):
    if((current_dataframe['ip_src'].unique()).shape[0] == 1): #Verifica se ambos os hosts enviam dados (icmp não)
#         current_dataframe['land'] = 0; #Como não tem 2 hosts.. impossível ter uma conexão land (src e dst same port)
        return(0)
    else:
        src_port1 = 0
        src_port2 = 0
        dst_port1 = 0
        dst_port2 = 0
        source = (current_dataframe['ip_src'].unique())[0] #define o source da conexão
        destination = (current_dataframe['ip_src'].unique())[1]#define o destination da conexão
        for line_count in range(0,current_dataframe.shape[0]):#Percorre toda a conexão e grava src e dst ports
            if(current_dataframe.iloc[line_count]['ip_src'] == source):
                src_port1 = current_dataframe.iloc[line_count]['src_port'];
                src_port2 = current_dataframe.iloc[line_count]['dst_port'];
            elif(current_dataframe.iloc[line_count]['ip_src'] == destination):
                dst_port1 = current_dataframe.iloc[line_count]['src_port'];
                dst_port2 = current_dataframe.iloc[line_count]['dst_port'];
        if(src_port1 == dst_port1 and src_port2 == dst_port2):current_dataframe['land'] = 1; return(1);
        else:current_dataframe['land'] = 0; return(0);
#==================================================================================================================
#_____Flags Feature (code for Syn,Ack,Fin,Push...)
def Flags(current_dataframe):
    if(current_dataframe.iloc[0].protocol == 6):#Caso seja TCP, fazer análise de flags.. caso udp ou icmp.. retornar conexão normal
        if((current_dataframe['ip_src'].unique()).shape[0] == 1): #Verifica se ambos os hosts enviam dados (icmp não)
            source = (current_dataframe['ip_src'].unique())[0] #define o source da conexão
            destination = (current_dataframe['ip_dst'].unique())[0]#define o destination da conexão
        else:
            source = (current_dataframe['ip_src'].unique())[0]
            destination = (current_dataframe['ip_src'].unique())[1]
        flag_index = 12 #POSIÇÃO QUE TCP_FLAGS ESTÁ NA COLUMNS DO DATAFRAME!
        buffer_syn_src = 0
        buffer_synack_dst = 0
        buffer_ack_src = 0
        buffer_ack_dst = 0
        buffer_fin_src = 0
        buffer_fin_dst = 0
        buffer_rst_src = 0
        buffer_rst_dst = 0
        for line_count in range(0,current_dataframe.shape[0]):#Percorre toda a conexão e converte as flags
            if(str(current_dataframe.iloc[line_count]['tcp_flag']) == "0x00000002"):
                current_dataframe.iloc[line_count,flag_index] = 'SYN'
                if(current_dataframe.iloc[line_count].ip_src == source):buffer_syn_src = 1
            elif(str(current_dataframe.iloc[line_count]['tcp_flag']) == '0x00000012'):
                current_dataframe.iloc[line_count,flag_index] = 'SYN-ACK'
                if(current_dataframe.iloc[line_count].ip_src == destination):buffer_synack_dst = 1
            elif(str(current_dataframe.iloc[line_count]['tcp_flag']) == '0x00000010'):
                current_dataframe.iloc[line_count,flag_index] = 'ACK'
                if(current_dataframe.iloc[line_count].ip_src == source):buffer_ack_src = 1
                if(current_dataframe.iloc[line_count].ip_src == destination):buffer_ack_dst = 1
            elif(str(current_dataframe.iloc[line_count]['tcp_flag']) == '0x00000018'):
                current_dataframe.iloc[line_count,flag_index] = 'PSH-ACK'
                if(current_dataframe.iloc[line_count].ip_src == source):buffer_ack_src = 1
                if(current_dataframe.iloc[line_count].ip_src == destination):buffer_ack_dst = 1
            elif(str(current_dataframe.iloc[line_count]['tcp_flag']) == '0x00000011'):
                current_dataframe.iloc[line_count,flag_index] = 'FIN'
                if(current_dataframe.iloc[line_count].ip_src == source):buffer_fin_src = 1
                elif(current_dataframe.iloc[line_count].ip_src == destination):buffer_fin_dst = 1
            elif(str(current_dataframe.iloc[line_count]['tcp_flag']) == '0x00000019'):
                current_dataframe.iloc[line_count,flag_index] = 'FIN-PSH-ACK'
                if(current_dataframe.iloc[line_count].ip_src == source):buffer_fin_src = 1
                elif(current_dataframe.iloc[line_count].ip_src == destination):buffer_fin_dst = 1
            elif(str(current_dataframe.iloc[line_count]['tcp_flag']) == '0x00000004'):
                current_dataframe.iloc[line_count,flag_index] = 'RST'
                if(current_dataframe.iloc[line_count].ip_src == source):buffer_rst_src = 1
                elif(current_dataframe.iloc[line_count].ip_src == destination):buffer_rst_dest = 1
            elif(str(current_dataframe.iloc[line_count]['tcp_flag']) == '0x00000038'):
                current_dataframe.iloc[line_count,flag_index] =  'PSH-ACK_URG'
                if(current_dataframe.iloc[line_count].ip_src == source):buffer_ack_src = 1
                if(current_dataframe.iloc[line_count].ip_src == destination):buffer_ack_dst = 1
            elif(str(current_dataframe.iloc[line_count]['tcp_flag']) == '0x00000000'):
                current_dataframe.iloc[line_count,flag_index] = 'Null'
            elif(str(current_dataframe.iloc[line_count]['tcp_flag']) == '0x00000014'):
                current_dataframe.iloc[line_count,flag_index] = 'RST-ACK'
        #Stream_Feature
        if(buffer_syn_src == 1 and buffer_synack_dst == 0): return('S0')
        elif(buffer_syn_src == 1 and buffer_synack_dst == 1):#conexão estabelecida
            if(buffer_rst_src == 1 and buffer_rst_dst == 0):return('RSTO')
            elif(buffer_rst_src == 0 and buffer_rst_dst == 1):return('RSTR')
            elif(buffer_fin_src == 0 and buffer_fin_dst == 0): return('S1')
            elif(buffer_fin_src == 1 and buffer_fin_dst == 0):return('S2')
            elif(buffer_ack_src == 0 and buffer_ack_dst == 1):return('S3')
            elif(buffer_syn_src == 1 and buffer_synack_dst == 1):return('SF') #Conexão normal
        elif(buffer_syn_src == 1 and buffer_rst_src == 1 and buffer_synack_dst ==0):return('RSTRH')
        elif(buffer_syn_src == 1 and buffer_fin_src == 1 and buffer_synack_dst ==0):return('SH')
        elif(buffer_syn_src == 0 and buffer_fin_src == 0 and buffer_fin_dst == 0):return('OTH')
        elif(buffer_syn_src == 1 and buffer_synack_dst == 0 and buffer_rst_dst == 1):return('REJ')
    else:return('SF') #Udp e ICMP
#==================================================================================================================
#____Service (port_number usage)
def Service(current_dataframe): #Retorna o primeiro serviço que encontrar se este campo não for igual a TCP (wireshark limitation)
    for line_count in range(0, current_dataframe.shape[0]):
        if(current_dataframe.iloc[line_count].service != 'TCP' and current_dataframe.iloc[line_count].service != 'ICMP'): 
            return(current_dataframe.iloc[line_count].service)
    return('PRIVATE')
#==================================================================================================================
#___Protocol
def Protocol(current_dataframe):
    if(current_dataframe.protocol.unique() == 6): return('TCP')
    elif(current_dataframe.protocol.unique() == 17):return('UDP')
    elif(current_dataframe.protocol.unique() == 1):return('ICMP')
    else:return('PRIVATE')
#==================================================================================================================
#___Total package length, window_size(tcp), urgent bit(if 1 has, supose the stream is urgent)
def Len_win_urg_clas(current_dataframe):
    total_window = 0
    total_length = 0
    urgent = 0
    classe = 0
    for line_count in range(0, current_dataframe.shape[0]):
        total_window += current_dataframe.iloc[line_count].window_size;
        total_length += current_dataframe.iloc[line_count].length;
        if(current_dataframe.iloc[line_count].urgent == 1):urgent = 1;
        if(current_dataframe.iloc[line_count].classe == 'anomaly'):classe=1;
            
    return(total_length,total_window,urgent,classe)
#==================================================================================================================
#Count and service stream features
def Srvcount(current_dataframe):
    #Definir quem é source e destination na conexão
    if((current_dataframe['ip_src'].unique()).shape[0] == 1): #Verifica se ambos os hosts enviam dados (icmp não)
        source = (current_dataframe['ip_src'].unique())[0] #define o source da conexão
        destination = (current_dataframe['ip_dst'].unique())[0]#define o destination da conexão
    else:
        source = (current_dataframe['ip_src'].unique())[0] #define o source da conexão
        destination = (current_dataframe['ip_src'].unique())[1]#define o destination da conexão
    #Definir quando é source e destination na conexão
    start_time1 = 0
    start_time2 = 0
    end_time1 = 2
    end_time2 = 2
    
    count  = 0 #Count feature
    serror_rate = 0 #serror_rate feature
    rerror_rate = 0 #rerror_rate feature
    same_srv_rate = 0 #same_srv_rate feature
    diff_srv_rate = 0 #diff_srv_rate feature
    
    srv_count = 0 #Srv_Count feature
    srv_serror_rate = 0 #srv_serror_rate feature
    srv_rerror_rate = 0 #srv_rerror_rate feature
    srv_diff_host_rate = 0 #srv_diff_host_rate feature
    
    for line_count in range(0,current_dataframe.shape[0]):
        #COUNT
        if(current_dataframe.iloc[line_count]['ip_src'] == source):
            sec = int((current_dataframe.iloc[line_count]['relative_time']))
            if (sec >= start_time1 and sec <= end_time1):  #Se está dentro da faixa de 2 segundos
                count += 1; #Count
                if(current_dataframe.iloc[line_count].tcp_flag == 'SYN'):
                    if(current_dataframe.iloc[line_count+1].tcp_flag == 'RST'):rerror_rate += 1
                    elif(current_dataframe.iloc[line_count+1].tcp_flag != 'SYN-ACK'):serror_rate += 1 #linecount+1 = destination synack, caso não seja, erro de syn
                if(current_dataframe.iloc[line_count].src_port == current_dataframe.iloc[line_count].dst_port):same_srv_rate += 1
                else:diff_srv_rate += 1
            else: start_time1 = sec; end_time1 = sec+2;
        #SrvCount
        sec = int((current_dataframe.iloc[line_count]['relative_time']))
        if(sec >= start_time2 and sec <= end_time2): 
            if (current_dataframe.iloc[line_count]['src_port'] == current_dataframe.iloc[line_count]['dst_port']):
                srv_count += 1;
                if(current_dataframe.iloc[line_count].tcp_flag == 'SYN'): #Erros syn e Rej:
                    if(current_dataframe.iloc[line_count+1].tcp_flag == 'RST'):srv_rerror_rate += 1
                    elif(current_dataframe.iloc[line_count+1].tcp_flag != 'SYN-ACK'):srv_serror_rate += 1 #linecount+1 = destination synack, caso não seja, erro de syn
                if(current_dataframe.iloc[line_count].ip_src != current_dataframe.iloc[line_count].ip_dst):srv_diff_host_rate += 1
        else: start_time2 = sec; end_time2 = sec+2

#     current_dataframe['count'] = num_connections_2sec;
#     current_dataframe['srv_count'] = num_same_srv_2sec;
    return(count,serror_rate,rerror_rate,same_srv_rate,diff_srv_rate,srv_count,srv_serror_rate,srv_rerror_rate,srv_diff_host_rate)
#==================================================================================================================
#==================================================================================================================
import os
def import_data_train():
    #Listas que irão conter as streams de cada protocolo
    tcp_list = []
    udp_list = []
    icmp_list = []
    lists_imported = []
    print('Importing Intrusion network Logs for model training...')
    #Para cada cada semana e cada protocolo, fazer a importação dos arquivos (1 para cada stream) sendo que o número exato que deve ser importado em loop está no arquivo _num_stream.csv do protocolo correspondente
    for protocol in ['tcp','udp']:
        for week in ['1']:
            #Através da concatenação de string necessária por ser vários arquivos com vários nomes, se chega ao arquivo especificado
            path = ('../Week'+week+'/streams/'+protocol+'_csvs/')
            num_streams = int(pd.read_csv(path+protocol+'_num_streams.csv').iloc[-1]);
            #Dependendo do protocolo do loop atual, escolher em qual das listas adicionar a stream a ser lida
            df_list = eval(protocol+'_list')
            #Já tendo o número de streams do protocolo na semana week, para todos os arquivos no diretório, fazer a importação, filtrar com a função acima e adicionar esta na lista de streams
            for count in range(0,num_streams):
                #Verifica se o arquivo existe para não dar erro, caso exista, enviar para função de filtagem e tratamento inicial dos dados
                if(os.path.exists(path+protocol+'_stream_'+str(count)+'.csv')):
                    stream = Stream_filter(protocol,week,str(count),path)
                    #Adiciona à lista do protocolo correspondente
                    df_list.append(stream);
    print('Done!')
    return(tcp_list,udp_list,icmp_list)
#==================================================================================================================
#==================================================================================================================
def process_data(lists_imported):
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
#==================================================================================================================
def store_data(series_processed):
    #Creates de dataframe with every line representing a intire stream
    darpa_streams = pd.DataFrame(columns=Stream_features)
    print('Structuring data for Machine Learning...')
    for count in range(0, len(series_processed)): #Retira de cada item do vetor feature, uma nova linha stream
        vet_aux = []
        vet_aux.append(series_processed[count][0])
        #src_dst_bytes:
        vet_aux.append(series_processed[count][1][0])
        vet_aux.append(series_processed[count][1][1])
        vet_aux.append(series_processed[count][2])
        vet_aux.append(series_processed[count][3])
        vet_aux.append(series_processed[count][4])
        vet_aux.append(series_processed[count][5])
        #len_win_urg_clas:
        vet_aux.append(series_processed[count][6][0])
        vet_aux.append(series_processed[count][6][1])
        vet_aux.append(series_processed[count][6][2])
        vet_aux.append(series_processed[count][6][3])
        #count...:
        vet_aux.append(series_processed[count][7][0])
        vet_aux.append(series_processed[count][7][1])
        vet_aux.append(series_processed[count][7][2])
        vet_aux.append(series_processed[count][7][3])
        vet_aux.append(series_processed[count][7][4])
        vet_aux.append(series_processed[count][7][5])
        vet_aux.append(series_processed[count][7][6])
        vet_aux.append(series_processed[count][7][7])
        vet_aux.append(series_processed[count][7][8])
        darpa_streams.loc[count] = vet_aux
    print('Done!')
    #For some reason, every feature exits the series in string form... so have to pass to int those that are int:
    darpa_streams.duration = darpa_streams.duration.astype(float)
    darpa_streams.src_bytes = darpa_streams.src_bytes.astype(float)
    darpa_streams.dst_bytes = darpa_streams.dst_bytes.astype(float)
    darpa_streams.length = darpa_streams.length.astype(float)
    darpa_streams.window_size = darpa_streams.window_size.astype(float)
    darpa_streams.urgent = darpa_streams.urgent.astype(int)
    darpa_streams.classe = darpa_streams.classe.astype(int)
    darpa_streams.counts = darpa_streams.counts.astype(int)
    darpa_streams.serror_rate = darpa_streams.serror_rate.astype(int)
    darpa_streams.rerror_rate = darpa_streams.rerror_rate.astype(int)
    darpa_streams.same_srv_rate = darpa_streams.same_srv_rate.astype(int)
    darpa_streams.diff_srv_rate = darpa_streams.diff_srv_rate.astype(int)
    darpa_streams.srv_count = darpa_streams.srv_count.astype(int)
    darpa_streams.srv_serror_rate = darpa_streams.srv_serror_rate.astype(int)
    darpa_streams.srv_rerror_rate = darpa_streams.srv_rerror_rate.astype(int)
    darpa_streams.srv_diff_host_rate = darpa_streams.srv_diff_host_rate.astype(int)
    return(darpa_streams)
#==================================================================================================================
#==================================================================================================================
#==================================================================================================================
#==================================================================================================================
#==================================================================================================================
#==================================================================================================================
#Importação das bibliotecas que serão usadas pelo aprendizado de maquina
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
#___Preprocessing categorical data into int64|float
def ML_preprocess(series_processed):
    from sklearn.preprocessing import LabelEncoder
    le = LabelEncoder()
    #Literal para int
    series_processed.protocol_type = le.fit_transform(series_processed.protocol_type.astype(str))
    series_processed.service = le.fit_transform(series_processed.service.astype(str))
    series_processed.flags = le.fit_transform(series_processed.flags.astype(str))
    return(series_processed)
#==================================================================================================================
#___Funções de cada um dos algoritmos de ML
def Algorithms(algorithm,X_train,y_train,X_test,y_test):
    if(algorithm == 1):model = GaussianNB();name_alg = "Naive Bayes"
    elif(algorithm == 2):model = SGDClassifier(loss='modified_huber',shuffle=True,random_state=101);name_alg = "Stocastic"
    elif(algorithm == 3):model = DecisionTreeClassifier(max_depth=10,random_state=101,max_features=None,min_samples_leaf=15);name_alg = "Decision Tree"
    elif(algorithm == 4):model = LogisticRegression();name_alg = "Logistic Regression"
    elif(algorithm == 5):model = MLPClassifier(solver='lbfgs', alpha=1e-5, hidden_layer_sizes=(5, 2), random_state=15);name_alg = "Neural Network"
    elif(algorithm == 6):model = RandomForestClassifier(n_estimators=70,oob_score=True,n_jobs=-1,random_state=101,max_features=None,min_samples_leaf=30);name_alg = "Random Forest"
    time1=time.clock()
    model.fit(X_train,y_train)
    time2=time.clock()
    time3=time.clock()
    y_pred = model.predict(X_test) 
    time4=time.clock()
    print(name_alg,accuracy_score(y_test, y_pred))
    return(accuracy_score(y_test, y_pred),model,time2-time1,time4-time3)
#==================================================================================================================
def Predict_train(data):
    prediction = best_model.predict(data)
    print('Prediction:',prediction)   
#==================================================================================================================
#___Conversão da index para o nome do algoritmo correspondente
def Name_model(index):
    if index==1:
        return("Naive Bayes");
    elif index==2:
        return("Stochastic Gradient")
    elif index==3:
        return("Decision Tree")
    elif index==4:
        return("Gradient Decendent")
    elif index==5:
        return("Neural Network")
    elif index==6:
        return("Random Forest")
#==================================================================================================================
#==================================================================================================================
classe_model = []
classe_score =[]
classe_features =[]
classe_figure=[]
classe_time1=[]
classe_time2=[]
def train_data(series_processed):
    print('Running Algorithms for prediction...')
    #Pré processamento: converte as variaveis nos types corretos
    darpa_train = ML_preprocess(series_processed)
    ml_features=['duration','src_bytes','dst_bytes','protocol_type','service','land', #Sem Classe
                 'flags','urgent','counts','serror_rate','rerror_rate',
                 'same_srv_rate','diff_srv_rate','srv_count','srv_serror_rate',
                 'srv_rerror_rate','srv_diff_host_rate']
    #___divide o dataset em 4: Xtrain = features selecionadas(sem a feature classe) Ytrain(feature classe como respotas para se aprender com as demais features), Xtest que são as features que servirão para validar o aprendizado feito em train, e Ytest que servirá como indicador de quantas vezes o algoritmo acertou e errou
    X_train, X_test, y_train, y_test = train_test_split(darpa_train[ml_features],
                                                        darpa_train.classe,
                                                        test_size=0.33,
                                                        random_state=42) 

    #___Chamada para cada algoritmo, a rodagem do algoritmo de machine learning retorna uma tupla: precisão do modelo, e também retorna o modelo para que possa ser possível a modelagem rápida pelo feature selector
    print('****** Algorithms Score: *******')
    high = 0 
    index = 0 
    T1 = 0 #Guarda o tempo de processamento do algoritmo mais bem pontuado(treino)
    T2= 0 #(test)
    for count in range(1,7):
        result = Algorithms(count,X_train,y_train,X_test,y_test)
        if result[0] > high:
            high=result[0]
            index=count
            best_model = result[1]
    print(Name_model(index), "Model selected!,\n\nModel trained and ready to run!")
    return(best_model)


# In[24]:


import pickle
lists_imported = import_data_train()
series_processed = process_data(lists_imported)
streams_dataframe = store_data(series_processed)
darpa_train = ML_preprocess(series_processed)
# trained_model = train_data(streams_dataframe)

# pickle.dump(trained_model,open('trained_model.sav','wb')) # #Salva o modelo treinado em um arquivo que pode ser importando depois

trained_model = pickle.load(open('./trained_model.sav','rb')) #import model from a file
print(trained_model.predict(darpa_train))
# In[17]:


# kdd = pd.read_csv(r'../../kdd99/10%')

# #___Cria uma linha index contendo o nome de todas as features (colunas)
# kddfeatures = ['duration','protocol_type','service','flag','src_bytes',
#                    'dst_bytes','land','wrong_fragment','urgent','hot','num_failed_logins',
#                    'logged_in','num_compromised','root_shell','su_attempted','num_root',
#                    'num_file_creations','num_shells','num_access_files',
#                    'num_outbound_cmds','is_hot_login','is_guest_login','counts',
#                    'srv_count','serror_rate','srv_serror_rate','rerror_rate',
#                    'srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate',
#                    'dst_host_count','dst_host_srv_count','dst_host_same_srv_rate',
#                    'dst_host_diff_srv_rate','dst_host_same_src_port_rate',
#                    'dst_host_srv_diff_host_rate','dst_host_serror_rate',
#                    'dst_host_srv_serror_rate','dst_host_rerror_rate',
#                    'dst_host_srv_rerror_rate','classe']
# kdd.columns = kddfeatures

# Stream_features=['duration','src_bytes','dst_bytes','protocol_type','service','land',
#                  'flags','length','window_size','urgent','classe','counts','serror_rate','rerror_rate',
#                  'same_srv_rate','diff_srv_rate','srv_count','srv_serror_rate',
#                  'srv_rerror_rate','srv_diff_host_rate']

# new_kdd = pd.DataFrame()
# new_kdd['duration'] = kdd['duration']
# new_kdd['src_bytes'] = kdd['src_bytes']
# new_kdd['dst_bytes'] = kdd['dst_bytes']
# new_kdd['protocol_type'] = kdd['protocol_type']
# new_kdd['service'] = kdd['service']
# new_kdd['land'] = kdd['land']
# new_kdd['flags'] = kdd['flag']
# new_kdd['urgent'] = kdd['urgent']
# new_kdd['counts'] = kdd['counts']
# new_kdd['serror_rate'] = kdd['serror_rate']
# new_kdd['rerror_rate'] = kdd['rerror_rate']
# new_kdd['same_srv_rate'] = kdd['same_srv_rate']
# new_kdd['diff_srv_rate'] = kdd['diff_srv_rate']
# new_kdd['srv_count'] = kdd['srv_count']
# new_kdd['srv_serror_rate'] = kdd['srv_serror_rate']
# new_kdd['srv_rerror_rate'] = kdd['srv_rerror_rate']
# new_kdd['srv_diff_host_rate'] = kdd['srv_diff_host_rate']
# new_kdd['classe'] = kdd['classe']


# In[20]:


# new_kdd = ML_preprocess(new_kdd)
# # new_kdd.head(40)


# In[ ]:





# In[25]:


# import pickle
# pickle.dump(trained_model,open('trained_model.sav','wb')) # #Salva o modelo treinado em um arquivo que pode ser importando depois

