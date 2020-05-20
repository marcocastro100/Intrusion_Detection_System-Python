#! /bin/bash
build_streams() {
    if [ -z $1 ];then echo "Path of week/streams not informed";
    else
        path=$1;
        for protocol in 'udp' 'tcp'; do
            for mode in 'inside' 'outside'; do
                for day in '1' '2' '3' '4' '5'; do
                    $(mkdir $path$protocol'_'$mode'_'$day);
                    file=$path'../pcaps/'$protocol'_'$mode'_'$day'.pcap';
                    tshark -r $file -T fields -e $protocol'.stream' | sort -n > $path$protocol'_'$mode'_'$day'/'$protocol'_num_streams.csv';
                    max=$(echo "tail -1 $path$protocol'_'$day'/$protocol'_num_streams.csv'" | bash);
                    
                    echo $protocol $mode $day '...';
                    for ((stream = 0; stream < 1000; stream++));do
                        if [ ! -e $path$protocol"_"$mode"_"$day"/"$protocol"_stream_"$stream".csv" ];then
                            echo -ne "Computing $protocol $mode $day $stream"\\r;
                            tshark  -r  $file  -Y "$protocol.stream eq $stream" -T fields -e _ws.col.No. -e _ws.col.DateTime -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Protocol -e frame.cap_len -e ip.proto -e ip.flags -e $protocol'.srcport' -e $protocol'.dstport' -e tcp.flags -e tcp.urgent_pointer -e tcp.window_size_value -E header=n -E separator=, -E occurrence=f >> $path$protocol"_"$mode"_"$day"/"$protocol"_stream_"$stream".csv";
                        fi
                    done
                done
            done
        done
    fi
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
#=======================================================#===================================================
kill() {    
    for pid in $(ps -aux | grep "tcpdump" | tr -s ' '| cut -d ' ' -f 2); do $(sudo kill $pid); done
    for pid in $(ps -aux | grep "tshark" | tr -s ' '| cut -d ' ' -f 2); do $(sudo kill $pid); done
    for pid in $(ps -aux | grep "sniff.sh" | tr -s ' '| cut -d ' ' -f 2); do $(sudo kill $pid); done
    for pid in $(ps -aux | grep "handler.py" | tr -s ' '| cut -d ' ' -f 2); do $(sudo kill $pid); done
    for pid in $(ps -aux | grep "ids.py" | tr -s ' '| cut -d ' ' -f 2); do $(sudo kill $pid); done
}
#=======================================================#===================================================
sniff() {
    sudo rm -r logs
    if [ ! -e ./logs ];then mkdir logs; fi
    if [ ! -e ./logs/streams ];then mkdir ./logs/streams; fi
     if [ ! -e ./logs/tcp_csvs ];then mkdir ./logs/tcp_csvs; fi
     if [ ! -e ./logs/udp_csvs ];then mkdir ./logs/udp_csvs; fi
    sudo tcpdump -q -w ./logs/network_dump.pcap tcp or udp |
    sudo tshark -q -T fields -e tcp.stream -e udp.stream -e frame.time_relative -e ip.proto -e _ws.col.Protocol -e tcp.flags -e tcp.urgent_pointer -e frame.cap_len  -e ip.flags -e tcp.window_size_value -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e ip.src -e ip.dst -E header=n -E separator=, -E occurrence=f > ./logs/brute_streams.csv
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
