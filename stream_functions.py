#==================================================================================================================
def Duration(current_dataframe):
    first_relative_time = float(current_dataframe.iloc[0]["relative_time"]); #Tempo relativo da primeira linha
    last_relative_time = float(current_dataframe.iloc[-1]["relative_time"]); #Tempo relativo da ultima linha
    duration = last_relative_time - first_relative_time
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
    for line_count in range(0,current_dataframe.shape[0]): #run through every line in current df
        if(current_dataframe.iloc[line_count]['ip_src'] == source):
            src_bytes += int(current_dataframe.iloc[line_count]['length']);
        elif(current_dataframe.iloc[line_count]['ip_src'] == destination):
            dst_bytes += int(current_dataframe.iloc[line_count]['length']);
    return(src_bytes,dst_bytes)
#==================================================================================================================
#_____Land Feature (src and dst ports equal)
def Land(current_dataframe):
    if((current_dataframe['ip_src'].unique()).shape[0] == 1): #both hosts sending verification
        current_dataframe['land'] = 0; #Como não tem 2 hosts.. impossível ter uma conexão land (src e dst same port)
        return(0)
    else:
        src_port1 = 0
        src_port2 = 0
        dst_port1 = 0
        dst_port2 = 0
        source = (current_dataframe['ip_src'].unique())[0] 
        destination = (current_dataframe['ip_src'].unique())[1]
        for line_count in range(0,current_dataframe.shape[0]):
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
    if(current_dataframe.iloc[0].protocol_type == 6):# only tcp pkgs has to have tcp_flag analisys....
        if((current_dataframe['ip_src'].unique()).shape[0] == 1): #Verifica se ambos os hosts enviam dados (icmp não)
            source = (current_dataframe['ip_src'].unique())[0] #define o source da conexão
            destination = (current_dataframe['ip_dst'].unique())[0]#define o destination da conexão
        else:
            source = (current_dataframe['ip_src'].unique())[0]
            destination = (current_dataframe['ip_src'].unique())[1]
        flag_index = current_dataframe.columns.get_loc('flag');
        buffer_syn_src = 0
        buffer_synack_dst = 0
        buffer_ack_src = 0
        buffer_ack_dst = 0
        buffer_fin_src = 0
        buffer_fin_dst = 0
        buffer_rst_src = 0
        buffer_rst_dst = 0
        for line_count in range(0,current_dataframe.shape[0]):#Percorre toda a conexão e converte as flags
            if(str(current_dataframe.iloc[line_count]['flag']) == "0x00000002"):
                current_dataframe.iloc[line_count,flag_index] = 'SYN'
                if(current_dataframe.iloc[line_count].ip_src == source):buffer_syn_src = 1
            elif(str(current_dataframe.iloc[line_count]['flag']) == '0x00000012'):
                current_dataframe.iloc[line_count,flag_index] = 'SYN-ACK'
                if(current_dataframe.iloc[line_count].ip_src == destination):buffer_synack_dst = 1
            elif(str(current_dataframe.iloc[line_count]['flag']) == '0x00000010'):
                current_dataframe.iloc[line_count,flag_index] = 'ACK'
                if(current_dataframe.iloc[line_count].ip_src == source):buffer_ack_src = 1
                if(current_dataframe.iloc[line_count].ip_src == destination):buffer_ack_dst = 1
            elif(str(current_dataframe.iloc[line_count]['flag']) == '0x00000018'):
                current_dataframe.iloc[line_count,flag_index] = 'PSH-ACK'
                if(current_dataframe.iloc[line_count].ip_src == source):buffer_ack_src = 1
                if(current_dataframe.iloc[line_count].ip_src == destination):buffer_ack_dst = 1
            elif(str(current_dataframe.iloc[line_count]['flag']) == '0x00000011'):
                current_dataframe.iloc[line_count,flag_index] = 'FIN'
                if(current_dataframe.iloc[line_count].ip_src == source):buffer_fin_src = 1
                elif(current_dataframe.iloc[line_count].ip_src == destination):buffer_fin_dst = 1
            elif(str(current_dataframe.iloc[line_count]['flag']) == '0x00000019'):
                current_dataframe.iloc[line_count,flag_index] = 'FIN-PSH-ACK'
                if(current_dataframe.iloc[line_count].ip_src == source):buffer_fin_src = 1
                elif(current_dataframe.iloc[line_count].ip_src == destination):buffer_fin_dst = 1
            elif(str(current_dataframe.iloc[line_count]['flag']) == '0x00000004'):
                current_dataframe.iloc[line_count,flag_index] = 'RST'
                if(current_dataframe.iloc[line_count].ip_src == source):buffer_rst_src = 1
                elif(current_dataframe.iloc[line_count].ip_src == destination):buffer_rst_dest = 1
            elif(str(current_dataframe.iloc[line_count]['flag']) == '0x00000038'):
                current_dataframe.iloc[line_count,flag_index] =  'PSH-ACK_URG'
                if(current_dataframe.iloc[line_count].ip_src == source):buffer_ack_src = 1
                if(current_dataframe.iloc[line_count].ip_src == destination):buffer_ack_dst = 1
            elif(str(current_dataframe.iloc[line_count]['flag']) == '0x00000000'):
                current_dataframe.iloc[line_count,flag_index] = 'Null'
            elif(str(current_dataframe.iloc[line_count]['flag']) == '0x00000014'):
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
def Service(current_dataframe): #Define the service on the stream given that is not a general tcp or icmp (wireshrk flaw)
    for line_count in range(0, current_dataframe.shape[0]):
        if(current_dataframe.iloc[line_count].service != 'TCP' and current_dataframe.iloc[line_count].service != 'ICMP'): 
            return(current_dataframe.iloc[line_count].service)
    return('PRIVATE') #case none identified
#==================================================================================================================
#___Protocol
def Protocol(current_dataframe):
    if(current_dataframe.protocol_type.unique() == 6): return('TCP')
    elif(current_dataframe.protocol_type.unique() == 17):return('UDP')
    elif(current_dataframe.protocol_type.unique() == 1):return('ICMP')
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
        elif(current_dataframe.iloc[line_count].classe == 'normal'):classe=0;
        else:classe = 20;
    return(total_length,total_window,urgent,classe)
#==================================================================================================================
#Count and service stream features
def Srvcount(current_dataframe):
    if((current_dataframe['ip_src'].unique()).shape[0] == 1):
        source = (current_dataframe['ip_src'].unique())[0]
        destination = (current_dataframe['ip_dst'].unique())[0]
    else:
        source = (current_dataframe['ip_src'].unique())[0]
        destination = (current_dataframe['ip_src'].unique())[1]

    start_time1 = 0 #time control
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
        if(current_dataframe.iloc[line_count]['ip_src'] == source):
            sec = int((current_dataframe.iloc[line_count]['relative_time']))
            if (sec >= start_time1 and sec <= end_time1):  #Se está dentro da faixa de 2 segundos
                count += 1; #Count
                if(current_dataframe.iloc[line_count].flag == 'SYN'):
                    if(current_dataframe.iloc[line_count+1].flag == 'RST'):rerror_rate += 1
                    elif(current_dataframe.iloc[line_count+1].flag != 'SYN-ACK'):serror_rate += 1
                if(current_dataframe.iloc[line_count].src_port == current_dataframe.iloc[line_count].dst_port):same_srv_rate+=1
                else:diff_srv_rate += 1
            else: start_time1 = sec; end_time1 = sec+2;
        #SrvCount
        sec = int((current_dataframe.iloc[line_count]['relative_time']))
        if(sec >= start_time2 and sec <= end_time2): 
            if (current_dataframe.iloc[line_count]['src_port'] == current_dataframe.iloc[line_count]['dst_port']):
                srv_count += 1;
                if(current_dataframe.iloc[line_count].flag == 'SYN'): #Erros syn e Rej:
                    if(current_dataframe.iloc[line_count+1].flag == 'RST'):srv_rerror_rate += 1
                    elif(current_dataframe.iloc[line_count+1].flag != 'SYN-ACK'):srv_serror_rate += 1 
                if(current_dataframe.iloc[line_count].ip_src != current_dataframe.iloc[line_count].ip_dst):srv_diff_host_rate+= 1
        else: start_time2 = sec; end_time2 = sec+2
    return(count,srv_count,serror_rate,srv_serror_rate,rerror_rate,srv_rerror_rate,same_srv_rate,diff_srv_rate,srv_diff_host_rate)
