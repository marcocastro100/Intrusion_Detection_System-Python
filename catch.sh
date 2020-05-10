#! /bin/bash
#CATCH.SH
#Starts tcpdump and tshark sniff script in background process
./sniff.sh &
#Guarda a posição real de processamento dos pacotes (mesmo quando leitura é resetada, só começará a computação a partir deste indice global)
dump_file=./logs/streams.csv
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
                    echo $line >> "./udp_csvs/udp_stream_"$col_udp".csv"; 
                fi
            else 
                ((global_count++));
                echo $line >> "./tcp_csvs/tcp_stream_"$col_tcp".csv";
                #Verificação de término de stream para enviar o arquivo para verificação com modelo de machine learning
                col_fin=$(echo $line | cut -d ',' -f 14); #store space of tcp.flags of packages
                if [[ $col_fin == '0x00000011' ]];then #if the tcp.flags is a fin flag (finish mesage)
                    echo "$col_tcp $(python3 ./handler.py './tcp_csvs/tcp_stream_'$col_tcp'.csv' 'tcp')" >> ./logs/ataqs.csv
                fi
            fi
        fi
    ((local_count++)) #increment until equal to global_count (in the case of a reset scan on file)
    done
done

