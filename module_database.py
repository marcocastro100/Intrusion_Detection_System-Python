#! /usr/bin/env python3
from module_common import *
from module_stream import Processor_stream
from module_package import Processor_package
import pandas as pd
import os
class Processor_database:
    #Contains a dataframe base, stream features names, ans stream features that the ML model will analise
    def __init__(self):
        self.Features_names=['duration','src_bytes','dst_bytes','land','flag','service','protocol_type',
         'length','window_size','urgent','counts','srv_count','serror_rate','srv_serror_rate',
         'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate','classe'];    
        self.train_dataframe = pd.DataFrame(columns = self.Features_names); #this dataframe hold all the features (all streams)
        self.max_streams = 40; #number of streams that will be readed from dataset files (the more, the longer it takes)
        self.path_model = './models/model_2000_0.77.sav'; #Alter this line to change model file
        
        from sklearn.naive_bayes import GaussianNB #bayes
        from sklearn.linear_model import LogisticRegression #regression
        from sklearn.linear_model import SGDClassifier #stocastic
        from sklearn.tree import DecisionTreeClassifier
        from sklearn.neural_network import MLPClassifier #neural
        from sklearn.preprocessing import StandardScaler #neural
        from sklearn.ensemble import RandomForestClassifier
        self.models_list =[ #Holds the models (algorithms) and their names
            (GaussianNB(),"Naive Bayes"),
            (LogisticRegression(),"Logistic Regression"),
            (SGDClassifier(loss='modified_huber',
                shuffle=True,
                random_state=101),
                "Stocastic Linear"),
            (DecisionTreeClassifier(max_depth=10,
                    random_state=101,
                    max_features=None,
                    min_samples_leaf=15),
                    "Decision Tree"),
            (MLPClassifier(solver='lbfgs',
                alpha=1e-5,
                hidden_layer_sizes=(5, 2),
                random_state=15),
                "Neural Network"),
            (RandomForestClassifier(n_estimators=70,
                    oob_score=True,
                    n_jobs=-1,
                    random_state=101,
                    max_features=None,
                        min_samples_leaf=30),
                    "Random Forest")];

    #Generates the model  
    def Load_dataset(self,mode_run,week):
        list_weeks = week;
        list_protocols = ['tcp','udp']
        list_modes = ['inside'];
        list_days = ['1','2','3','4','5'];
        streams_dataframe_list = list();
        for week in list_weeks: #Dataset Logic (Attack or Normal)
            for protocol in list_protocols: #Dataset Logic 
                for mode in list_modes:  #Dataset Logic (sniff mode) #going without outise for now
                    for day in list_days: #Dataset Logic (days of week)
                        if(mode_run=='train'):
                            print('Processing week',week,protocol,mode,'day',day);
                            self.Structure_data(week,protocol,mode,day,mode_run); #assemble packages | stream
                        elif(mode_run=='verify'):
                            dataframe_list = self.Structure_data(week,protocol,mode,day,mode_run);
                            for dataframe in dataframe_list: #gets every dataframe generated at the current loop
                                streams_dataframe_list.append(dataframe); #saves the current streams
        if(mode_run=='train'):model = self.Train_model(self.train_dataframe); #trains and saves the model
        elif(mode_run=='verify'):
            normal_anomaly_count = [0,0]; #To check number of normal and anomaly connections idetified
            for dataframe in streams_dataframe_list:
                prediction = self.Predict_data(dataframe[0]);
                Print_prediction(prediction,dataframe[1],normal_anomaly_count);#output predicion
    
    #Modeling packages,streams,features from dataset data to dataframe 
    def Structure_data(self,week,protocol,mode,day,mode_run):
        path_dataset = ('../Week'+week+'/streamsfalse/'+protocol+'_'+mode+'_'+day+'/') #Path to dataset streams SO
        dataframe_list = []; #stores the dataframes of each stream separately for Verify mode)
        for count in range(0,self.max_streams): #reads from stream 0 until the specified stream on init
            path_stream = (path_dataset+protocol+'_stream_'+str(count)+'.csv'); #path to each stream SO
            if(os.path.exists(path_stream) and os.stat(path_stream).st_size != 0):#check if exists the streams file
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
    
    #Get the dataframe with all the features and let the algorithms running to see witch one classifies de data better
    def Train_model(self,train_dataframe):
        train_dataframe = self.Preprocess_data(train_dataframe) #converts literal features to int for ML
        models_scores = []; #holds the model name and his score in classifying normal and anomaly connections correctly
        from sklearn.model_selection import train_test_split
        Features_train_model = self.Features_names[:];Features_train_model.remove('classe');
        (X_train, X_test, y_train, y_test) = (  #Divide all data into 4 pieces for ML (y=verify acurracy, x=train)
           train_test_split(train_dataframe[Features_train_model],train_dataframe.classe,test_size=0.33,random_state=42));
        for model in self.models_list: #for each model registered at __init__
            model[0].fit(X_train,y_train) #model[0] = model, model[1] = model-name
            y_pred = model[0].predict(X_test)  #get model score
            from sklearn.metrics import accuracy_score #Calculo de precisão
            print(model[1],accuracy_score(y_test,y_pred));
            models_scores.append([model[1],accuracy_score(y_test, y_pred),model[0]]) #score[0]=name,[1]=score,[2]=trained-model
        best_score = 0;
        for score in models_scores:
            if (score[1] > best_score):
                best_name = score[0];
                best_score = score[1];
                best_model = score[2]; #saves the model with the better score
        print('Saving ',best_name,' model with score ',best_score);
        self.Save_model(best_model,round(best_score,2)); #send the trained model to be saved in a file and be used on sniffing
        
    #Concatenate a dataframe to the main dataframe of the class
    def Join_dataframe(self,features_dataframe):
        self.train_dataframe = self.train_dataframe.append(features_dataframe);
        
    def Preprocess_data(data,dataframe):
        from sklearn.preprocessing import LabelEncoder;le = LabelEncoder() #Literal to int
        dataframe.flag = le.fit_transform(dataframe.flag);
        dataframe.service = le.fit_transform(dataframe.service);
        dataframe.protocol_type = le.fit_transform(dataframe.protocol_type);
        return(dataframe);
    
    def Save_model(self,trained_model,model_score):
        import pickle;
        with open('./models/model_'+str(self.max_streams)+'_'+str(model_score)+'.sav','wb') as path_save:
            pickle.dump(trained_model, path_save) #saves model
    
    def Load_model(self,path_to_model):
        import pickle;
        model = pickle.load(open(path_to_model,'rb'));
        return(model);
    
    def Predict_data(self,stream_dataframe):
        obj_database = Processor_database(); #initializate for use his methods
        stream_dataframe = obj_database.Preprocess_data(stream_dataframe);
        model = obj_database.Load_model(self.path_model); #loads the ml model to the program (alter in self.attributes)
        stream_dataframe = stream_dataframe.drop(columns = 'classe'); #drops classe since data hasnt label
        data_prediction = model.predict(stream_dataframe); #prediction normal vs attack
        return(int(data_prediction));
#=================================================================================
