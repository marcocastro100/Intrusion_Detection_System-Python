#! /usr/bin/env python3
import os

list_weeks = ['1','2','3'];
list_protocols = ['tcp','udp','icmp'];
list_modes = ['inside','outside'];
list_days = ['1','2','3','4','5'];
for week in list_weeks: #Dataset Logic (Attack or Normal)
    for protocol in list_protocols: #Dataset Logic 
        for mode in list_modes:  #Dataset Logic (sniff mode) #going without outise for now
            for day in list_days: #Dataset Logic (days of week)
                print("Computing Week "+week+' '+protocol+' '+mode+' '+day)
                read_file='../Week'+week+'/pcaps/csvs/'+protocol+'_'+mode+'_'+day+'.csv';
                with open (read_file, 'r') as file_r: #Realiza a leitura do arquivo csv atual
                    lines = file_r.readlines(); #Read lnes on the file passed as parameter
                    print(lines);
                    raw_packages = [aux.split(',') for aux in lines] #Stores the pkg attributes (that are divided by a ',')
                    for single_package in range(0,len(raw_packages)): #len(lines) == quantity of packages readed from file_lines
                        print(len(raw_packages));
                        if(protocol == 'tcp'):
                            stream = raw_packages[single_package][0];#pegar número de stream do single_package atual
                        else:
                            stream = raw_packages[single_package][1];
                        write_file='../Week'+week+'/streams/'+protocol+'_'+mode+'_'+day+'/'+protocol+'_stream_'+stream+'.csv';
                        os.makedirs(os.path.dirname(write_file), exist_ok=True)
                        with open (write_file,'a+') as file_w: #a+ stands for append(not overwrite) and + for create if not exists
                            file_w.write(str(lines[single_package]));
                            file_w.close()
                    file_r.close() #closes the file
