#Common functions used by various modules at the time (create to not have multiple dependencies between modules)
from module_package import Processor_package

#ML Features that will be generated for machine learning algorithms analisys
Features_names=['duration','src_bytes','dst_bytes','land','flag','service','protocol_type',
         'length','window_size','urgent','counts','srv_count','serror_rate','srv_serror_rate',
         'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate','classe']; 

#Reads a file (localized in path on SO) containing network packages in csv format and return the readed lines
def Read_file(path):
    with open (path, 'r') as file:
        file.flush();
        lines = file.readlines(); #Read lines on the file passed as parameter
        file.close() #closes the file
        return(lines);
#===================================================================================

#Receives a prediction (number) corresponding to the ML model analisys and prints to the user if a stream analised has a pattern of normal or anomaly connection. Receives: int prediction (model return), stream analised, connection_type for control the number of normal or anomalies founded so far, and classe
def Print_prediction(prediction,stream,normal_anomaly_count,classe='0'):
    class col: #Just some colors code
        HEADER = '\033[95m';
        OKBLUE = '\033[94m';
        OKGREEN = '\033[92m';
        WARNING = '\033[93m';
        FAIL = '\033[91m';
        ENDC = '\033[0m';
        BOLD = '\033[1m';
        UNDERLINE = '\033[4m';
    if(prediction == 1 or prediction == 3): #Normal Connection
        normal_anomaly_count[0] = normal_anomaly_count[0] + 1; #adds 1 to number of normal connections
        print(
              str(stream.protocol)+' stream '+str(stream.index)+
              col.OKGREEN + ' \tNormal Connection\t ' + col.ENDC+'('+
              col.OKGREEN+str(normal_anomaly_count[0])+' '+col.WARNING+str(normal_anomaly_count[1])+col.ENDC+')\t');
    elif(prediction ==2): #Attack Connection
        normal_anomaly_count[1] = normal_anomaly_count[1] + 1; #adds 1 to number of anomaly connections
        print(
              str(stream.protocol)+' stream '+str(stream.index)+
              col.WARNING+' \tAnomaly Connection\t '+col.ENDC+'('+
              col.OKGREEN+str(normal_anomaly_count[0])+' '+col.WARNING+str(normal_anomaly_count[1])+col.ENDC+')\t');
        with open('./logs/anomaly.txt','a') as file: file.write(str(stream)+'\n'); file.close() #writes anomaly in a file