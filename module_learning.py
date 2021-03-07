from module_common import Features_names
#Imports the algorithms
from sklearn.naive_bayes import GaussianNB #bayes
from sklearn.linear_model import LogisticRegression #regression
from sklearn.linear_model import SGDClassifier #stocastic
from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier #neural
from sklearn.preprocessing import StandardScaler #neural
from sklearn.ensemble import RandomForestClassifier

class Processor_learning:
    def __init__(self):
        #List that holds the models (algorithms) and their names
        self.models_list =[ 
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

    #Get the dataframe with all the features and let the algorithms running to see witch one classifies de data better
    def Train_model(self,train_dataframe):
        train_dataframe = self.Preprocess_data(train_dataframe) #converts literal features to int for ML
        models_scores = []; #holds the model name and his score in classifying normal and anomaly connections correctly
        from sklearn.model_selection import train_test_split
        Features_train_model = Features_names[:];Features_train_model.remove('classe');
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
        
    def Preprocess_data(data,dataframe):
        from sklearn.preprocessing import LabelEncoder;
        le = LabelEncoder() #Literal to int
        dataframe.flag = le.fit_transform(dataframe.flag);
        dataframe.service = le.fit_transform(dataframe.service);
        dataframe.protocol_type = le.fit_transform(dataframe.protocol_type);
        return(dataframe);
    
    def Save_model(self,trained_model,model_score):
        import pickle;
        with open('./models/model_3_protocolnotspecified_inside'+str(model_score)+'.sav','wb') as path_save:
            pickle.dump(trained_model, path_save) #saves model
    
    def Load_model(self,path_to_model):
        import pickle;
        model = pickle.load(open(path_to_model,'rb'));
        return(model);
    
    def Predict_data(self,stream_dataframe):
        current_protocol = stream_dataframe.protocol_type[0].lower(); #Defines a string protocol for loading the right model (tcp,udp or icmp)
        stream_dataframe = self.Preprocess_data(stream_dataframe);
        model = self.Load_model('./models/model_3_'+current_protocol+'_inside.sav'); #loads the ml model to the program
        stream_dataframe = stream_dataframe.drop(columns = 'classe'); #drops classe since sniffed data dont have a classe yet
        data_prediction = model.predict(stream_dataframe); #prediction normal vs attack
        return(int(data_prediction));
