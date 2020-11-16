#! /usr/bin/env python3
class Processor_features:
    def __init__(self,package_list):
        self.source = package_list[0].ip_src #defines o source da conexão (who started the network communication)
        self.destination = package_list[0].ip_dst #defines o destination da conexão (who first received the request)
    
    def Duration(self,package_list):
        return(package_list[-1].relative_time - package_list[0].relative_time); #Last package time - first = total time
    
    def Src_dst_bytes(self,package_list):
        src_bytes = 0 #total de bytes enviados pelo source
        dst_bytes = 0 #total de bytes enviados pelo destination
        for count in range(0,len(package_list)): #run through all the packages on the connection
            if(package_list[count].ip_src == self.source): #case package sended by source
                src_bytes += package_list[count].length; 
            else:dst_bytes += package_list[count].length; #case package sended by destination
        return src_bytes,dst_bytes
    
    def Land(self,package_list): #src and dst port are equal
        if(self.source == self.destination): return(1);
        elif(self.source != self.destination):return(0);
        
    def Flags(self,package_list):
        buffer_syn_src = 0 #buffers stores the state of the conection depending on every flag of every package
        buffer_synack_dst = 0
        buffer_ack_src = 0
        buffer_ack_dst = 0
        buffer_fin_src = 0
        buffer_fin_dst = 0
        buffer_rst_src = 0
        buffer_rst_dst = 0
        for count in range(0,len(package_list)): #run through every package
            if(package_list[count].flag == '0x00000002'): #check the code for the flag
                package_list[count].flag = 'SYN'; #translated to be used later
                if(package_list[count].ip_src == self.source):buffer_syn_src = 1; #register the existance of the flag
            elif(package_list[count].flag == '0x00000012'):
                package_list[count].flag = 'SYN-ACK'
                if(package_list[count].ip_src != self.source):buffer_synack_dst = 1
            elif(package_list[count].flag == '0x00000010'):
                package_list[count].flag = 'ACK'
                if(package_list[count].ip_src == self.source):buffer_ack_src = 1
                if(package_list[count].ip_src != self.source):buffer_ack_dst = 1
            elif(package_list[count].flag == '0x00000018'):
                package_list[count].flag = 'PSH-ACK'
                if(package_list[count].ip_src == self.source):buffer_ack_src = 1
                if(package_list[count].ip_src != self.source):buffer_ack_dst = 1
            elif(package_list[count].flag == '0x00000011'):
                package_list[count].flag = 'FIN'
                if(package_list[count].ip_src == self.source):buffer_fin_src = 1
                if(package_list[count].ip_src != self.source):buffer_fin_dst = 1
            elif(package_list[count].flag == '0x00000019'):
                package_list[count].flag = 'FIN-PSH-ACK'
                if(package_list[count].ip_src == self.source):buffer_fin_src = 1
                if(package_list[count].ip_src != self.source):buffer_fin_dst = 1
            elif(package_list[count].flag == '0x00000004'):
                package_list[count].flag = 'RST'
                if(package_list[count].ip_src == self.source):buffer_rst_src = 1
                if(package_list[count].ip_src != self.source):buffer_rst_dst = 1
            elif(package_list[count].flag == '0x00000038'):
                package_list[count].flag = 'PSH-ACK_URG'
                if(package_list[count].ip_src == self.source):buffer_ack_src = 1
                if(package_list[count].ip_src != self.source):buffer_ack_dst = 1
            elif(package_list[count].flag == ''):
                package_list[count].flag = 'UDP-Null'
            elif(package_list[count].flag == '0x00000014'):
                package_list[count].flag = 'RST-ACK'
        #Process the flags registered in the conection to return the corresponding behavior of the packages
        if(buffer_syn_src == 1 and buffer_synack_dst == 0): return('S0') #connection tryed.. no answer
        elif(buffer_syn_src == 1 and buffer_synack_dst == 1):#conexão estabelecida
            if(buffer_rst_src == 1 and buffer_rst_dst == 0):return('RSTO')#source aborted the connection
            elif(buffer_rst_src == 0 and buffer_rst_dst == 1):return('RSTR')#destination aborted the connection
            elif(buffer_fin_src == 0 and buffer_fin_dst == 0): return('S1')#connected, not finished
            elif(buffer_fin_src == 1 and buffer_fin_dst == 0):return('S2')#connected, finished, no answer from destination
            elif(buffer_ack_src == 0 and buffer_ack_dst == 1):return('S3')#connected, finished, no answer from source
            elif(buffer_syn_src == 1 and buffer_synack_dst == 1):return('SF') #Conexão normal
        elif(buffer_syn_src == 1 and buffer_rst_src == 1 and buffer_synack_dst ==0):return('RSTRH')#dst answered and aborted
        elif(buffer_syn_src == 1 and buffer_fin_src == 1 and buffer_synack_dst ==0):return('SH')#src send a syn and aborted
        elif(buffer_syn_src == 0 and buffer_fin_src == 0 and buffer_fin_dst == 0):return('OTH')#traffic without SYN
        elif(buffer_syn_src == 1 and buffer_synack_dst == 0 and buffer_rst_dst == 1):return('REJ')#connection rejected
        else: return('NaN');
        
    def Service(self,package_list):
        #identify the first service(stream service) in the packages that is not a general service (TCP, UDP and ICMP)
        for count in range(0,len(package_list)): #run through all the packages
            if(package_list[count].service != 'TCP' and package_list[count].service != 'UDP' and package_list[count].service != 'ICMP'):
                return(str(package_list[count].service));
        return(package_list[0].service); #case only general services have been found
    
    def Protocol(self,package_list):
        if(package_list[0].protocol_type == 6):return('TCP');
        elif(package_list[0].protocol_type == 17):return('UDP');
        elif(package_list[0].protocol_type == 1):return('ICMP');
        else:return('None');
        
    def Len_win_urg_clas(self,package_list):
        total_window = 0
        total_length = 0
        urgent = 0
        classe = 0
        for count in range(0,len(package_list)):
            total_window += package_list[count].window_size;
            total_length += package_list[count].length;
            if(package_list[count].urgent == 1): urgent = 1; #bit that say that this package has priority
            classe = 'nolabel'; #only to fill the model train structure
        return(total_length,total_window,urgent,classe)
    
    def Srvcount(self,package_list):
        start_time1 = 0 #time control
        start_time2 = 0
        end_time1 = 2
        end_time2 = 2

        feat_count  = 0 #Count feature
        serror_rate = 0 #serror_rate feature
        rerror_rate = 0 #rerror_rate feature
        same_srv_rate = 0 #same_srv_rate feature
        diff_srv_rate = 0 #diff_srv_rate feature

        srv_count = 0 #Srv_Count feature
        srv_serror_rate = 0 #srv_serror_rate feature
        srv_rerror_rate = 0 #srv_rerror_rate feature
        srv_diff_host_rate = 0 #srv_diff_host_rate feature

        for count in range(0,len(package_list)):
            if(package_list[count].ip_src == self.source): #veirfy if this package is from source
                current_pkg_time = package_list[count].relative_time; #holds the time that the package arrived
                if (current_pkg_time >= start_time1 and current_pkg_time <= end_time1): #veify if the difference from last is 2
                    feat_count += 1; #Count
                    if(package_list[count].flag == 'SYN'): #current package
                        if(package_list[count+1].flag == 'RST'):rerror_rate += 1 #next package (count+1)
                        elif(package_list[count+1].flag != 'SYN-ACK'):serror_rate += 1 
                    if(package_list[count].src_port == package_list[count].dst_port):same_srv_rate+=1
                    else:diff_srv_rate += 1
                else: start_time1 = current_pkg_time; end_time1 = current_pkg_time+2; #Case not in the 2 seconds window
            #SrvCount
            current_pkg_time = int((package_list[count].relative_time))
            if(current_pkg_time >= start_time2 and current_pkg_time <= end_time2): 
                if (package_list[count].src_port == package_list[count].dst_port):
                    srv_count += 1;
                    if(package_list[count].flag == 'SYN'): #Erros syn e Rej:
                        if(package_list[count+1].flag == 'RST'):srv_rerror_rate += 1
                        elif(package_list[count+1].flag != 'SYN-ACK'):srv_serror_rate += 1 
                    if(package_list[count].ip_src != package_list[count].ip_dst):srv_diff_host_rate+= 1
            else: start_time2 = current_pkg_time; end_time2 = current_pkg_time+2
            return(count,srv_count,serror_rate,srv_serror_rate,rerror_rate,srv_rerror_rate,same_srv_rate,diff_srv_rate,srv_diff_host_rate)

#=================================================================================

