#! /bin/bash
#Interage diretamente com o diretorio de arquivos da pasta com o intuito de ser realizado separação logica e o processamento de conteúdo dos dados brutos do dataset, sendo que, como resultado, varios diretorios correspondendo às diferentes naturezas dos dados presentes no dataset, como a separação por cada stream individualmente, protocolo usado, natureza da conexão (normal x attack), etc. O código cria os diretorios basicos necessários, em loop passar por todas as possibilidades de leitura e escrita de dados presentes no dataset, através do tshark os dados são estruturados e organizados. Em um loop que deve ir de 0 até um número que deve chegar até, no maximo, à variável max que contém a quantidade total de streams presentes no arquivo do dataset sendo analisado. Com o tshark, as informações relevantes são extraidas e exportadas para os arquivos correspondentes que são importados posteriormente pelos scritps responsáveis pelo processamento dos dados do dataset e treinamento do modelo de ML.
build_streams() {
    if [ -z $1 ];then #If parameter ($1) not informed
        echo "Inform Week's directory path!";
    else
        for max_streams in '100' '300' '500' '700' '800' '1000' '1300' '1600' '1800' '2000'; do #divides the number of streams available for each week equaly
            for week in '1' '2'; do
                for protocol in 'tcp' 'udp'; do #2 protocols that we are working on
                    for mode in 'inside'; do #two sniffing modes from dataset
                        for day in '1' '2' '3' '4' '5'; do #5 days (mon ~ fri)
                            path='../Week'$week'/streamsfalse/';
                            if [ ! -e $path$protocol'_'$mode'_'$day ];then #case directory not exists yet
                                $(mkdir $path$protocol'_'$mode'_'$day); #creates directory for stream files
                            fi
                            file=$path'../pcaps/'$protocol'_'$mode'_'$day'.pcap'; #file holds stream files location

                            for ((stream = 0; stream < $max_streams; stream++));do #keep processing strams until condition
                                if [ ! -e $path$protocol"_"$mode"_"$day"/"$protocol"_stream_"$stream".csv" ];then #strea not exists yet
                                    echo -ne "Computing Week $week $protocol $mode $day $stream"\\r; #feedback to user
                                    #Reads from pcap files(network dump) filtering the data to the selected (-e) attributes of the packages, and filtering even more (-Y) since for each file will be recorded only one stream (file stream_0 will contain only the packages that are from the connection 0
                                    tshark  -r  $file  -Y "$protocol.stream eq $stream" -T fields -e tcp.stream -e udp.stream -e frame.time_relative -e ip.proto -e _ws.col.Protocol -e tcp.flags -e tcp.urgent_pointer -e frame.cap_len  -e ip.flags -e tcp.window_size_value -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e ip.src -e ip.dst -E header=n -E separator=, -E occurrence=f >> $path$protocol"_"$mode"_"$day"/"$protocol"_stream_"$stream".csv";
                                fi
                            done
                        done
                    done
                done
            done
        done
    fi
}
#=======================================================#===================================================
sniff() {
    sudo rm -r logs
    if [ ! -e ./logs ];then mkdir logs; fi
    sudo tcpdump -q -w ./logs/network_dump.pcap tcp or udp |
    sudo tshark -q -T fields -e tcp.stream -e udp.stream -e frame.time_relative -e ip.proto -e _ws.col.Protocol -e tcp.flags -e tcp.urgent_pointer -e frame.cap_len  -e ip.flags -e tcp.window_size_value -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e ip.src -e ip.dst -E header=n -E separator=, -E occurrence=f > ./logs/brute_streams.csv 
}
#=======================================================#===================================================
kill() { #Kill all processses related to the ids system using kill command
    for pid in $(ps -aux | grep "module_shell.sh sniff" | tr -s ' '| cut -d ' ' -f 2); do $(sudo kill $pid); done
    for pid in $(ps -aux | grep "tcpdump -q" | tr -s ' '| cut -d ' ' -f 2); do $(sudo kill $pid); done
    for pid in $(ps -aux | grep "tshark -q " | tr -s ' '| cut -d ' ' -f 2); do $(sudo kill $pid); done
    for pid in $(ps -aux | grep "/usr/bin/dumpcap -n " | tr -s ' '| cut -d ' ' -f 2); do $(sudo kill $pid); done
    for pid in $(ps -aux | grep "./main.py" | tr -s ' '| cut -d ' ' -f 2); do $(sudo kill $pid); done
}
#===================================================#===================================================
extract_darpa() {
    if [ -z $1 ];then echo "Path of week/pcaps not informed";
    else
        path=$1;
        for mode in 'inside' 'outside';do
            for num in '1' '2' '3' '4';do
                $(gunzip $path$mode.tcpdump\ \($num\))
            done
            $(gunzip $path$mode.tcpdump)
        done
    fi
}
#=====================================================#===================================================
change_extension() {
    if [ -z $1 ];then echo "Path of week/pcaps not informed";
    else
        path=$1;
        for mode in 'inside' 'outside';do
            for num in '1' '2' '3' '4';do
                $(mv $path$mode.tcpdump\ \($num\) $path$mode$((num2=$num+1))'.pcap');
            done
            $(mv $path$mode.tcpdump $path$mode'1.pcap')
        done
    fi
}
#=====================================================#===================================================
extract_protocol() {
    if [ -z $1 ];then echo "Path of week/pcaps not informed";
    else
        path=$1;
        for mode in 'inside' 'outside';do
            for num in '1' '2' '3' '4' '5';do
                for protocol in 'tcp' 'udp';do
                    $(sudo tcpdump -r $path$mode$num'.pcap' -w $path$protocol'_'$mode'_'$num'.pcap' $protocol);
                done
            done
        done
    fi
}
#==========================================================#===================================================
build_directories() {
    for num in '1' '2' '3';do
        $(mkdir './Week'$num);
        $(mkdir './Week'$num'/streams');
        $(mkdir './Week'$num'/pcaps');
    done
}
#===================================================#===================================================
catch_old() {
#Starts tcpdump and tshark sniff script in background process
./sniff.sh &
#Guarda a posição real de processamento dos pacotes (mesmo quando leitura é resetada, só começará a computação a partir deste indice global)
dump_file=./logs/brute_streams.csv
global_count=0
#Seta um loop infinito para que o arquivo, que é variável, seja sempre lido mesmo quando foram lidas todas as linhas
while true;do
#Guarda a posição atual de percorrimento de linhas no arquivo (só começará a computar quando este indice se igualar ao global_count)
    local_count=0;
#Lê cada linha do arquivo e adiciona esta à variavel $line
    for line in $(cat $dump_file); do
#Verifica se global e local tem o mesmo valor (locals sempre é resetado para recomeçar o scan)
        if [ $local_count = $global_count ];then
            col_tcp=$(echo $line | cut -d ',' -f 1); #Store only the tcp_stream number (tshark tcp.stream)
            col_udp=$(echo $line | cut -d ',' -f 2); #Store only the udp_stream number (if pkg is tcp this is null)
#Check if the pkg belong to a tcp or udp stream or neither (arp, icmp, ....(not used))

            if [ -z $col_tcp ]; then #Check pkg.tcp_stream is null in the file line
                if [ -z $col_udp ]; then ((global_count++)); #if neither tcp or udp
                else 
                    ((global_count++));
                    echo $line >> "./logs/udp_csvs/udp_stream_"$col_udp".csv"; 
                fi
            else 
                ((global_count++));
                echo $line >> "./logs/tcp_csvs/tcp_stream_"$col_tcp".csv";
                #Verificação de término de stream para enviar o arquivo para verificação com modelo de machine learning
                col_fin=$(echo $line | cut -d ',' -f 14); #store space of tcp.flags of packages
                if [[ $col_fin == '0x00000011' ]];then #if the tcp.flags is a fin flag (finish mesage)
                    analisys=$(echo "Stream $col_tcp $(python3 ./handler.py './logs/tcp_csvs/tcp_stream_'$col_tcp'.csv' 'tcp')")
                    echo $analisys >> ./logs/analisys.log
                    echo -ne "\n$analisys\n"
                fi
            fi
        fi
    ((local_count++)) #increment until equal to global_count (in the case of a reset scan on file)
    done
done
}
#===================================================#===================================================

"$@"  #This makes the script accept the execution code by parameter in script call.. beeing that one of the functions
