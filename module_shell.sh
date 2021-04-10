#! /bin/bash
#Interage diretamente com o diretorio de arquivos da pasta com o intuito de ser realizado separação logica e o processamento de conteúdo dos dados brutos do dataset, sendo que, como resultado, varios diretorios correspondendo às diferentes naturezas dos dados presentes no dataset, como a separação por cada stream individualmente, protocolo usado, natureza da conexão (normal x attack), etc. O código cria os diretorios basicos necessários, em loop passar por todas as possibilidades de leitura e escrita de dados presentes no dataset, através do tshark os dados são estruturados e organizados. Em um loop que deve ir de 0 até um número que deve chegar até, no maximo, à variável max que contém a quantidade total de streams presentes no arquivo do dataset sendo analisado. Com o tshark, as informações relevantes são extraidas e exportadas para os arquivos correspondentes que são importados posteriormente pelos scritps responsáveis pelo processamento dos dados do dataset e treinamento do modelo de ML.
build_streams() {
    if [ -z $1 ];then #If parameter ($1) not informed
        echo "Inform Week's directory path!";
    else
        for week in '1' '2' '3'; do
            for protocol in 'tcp' 'udp' 'icmp'; do #2 protocols that we are working on
                for mode in 'inside' 'outside'; do #two sniffing modes from dataset
                    for day in '1' '2' '3' '4' '5'; do #5 days (mon ~ fri)
                        mkdir $path'pcaps/csvs/'
                        path=$1'Week'$week;
                        file=$path'/pcaps/'$protocol'_'$mode'_'$day'.pcap'; #file holds stream files location
                        echo -ne "Computing Week $week $protocol $mode $day "\\r; #feedback to user
                        #Reads from pcap files(network dump) filtering the data to the selected (-e) attributes of the packages, and filtering even more (-Y) since for each file will be recorded only one stream (file stream_0 will contain only the packages that are from the connection 0
                        tshark  -r  $file -T fields -e tcp.stream -e udp.stream -e frame.time_relative -e ip.proto -e _ws.col.Protocol -e tcp.flags -e tcp.urgent_pointer -e frame.cap_len  -e ip.flags -e tcp.window_size_value -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e ip.src -e ip.dst -E header=n -E separator=, -E occurrence=f >> $path'/pcap/csvs/'$protocol"_"$mode"_"$day".csv";
                    done
                done
            done
        done
       # echo "Initilizing module_python.py";
        #$(./module_python.py); #Call script ids/module_python.py to separate the streams from the csv files generated here #not tested for take too long
        #echo "Initializing module_shell.sh"
        #$(./module_shell.sh build_streams ../)#calculate total number of streams present per day in all weeks (for control in aplication)
    fi
}
#===================================================#===================================================
#Generates a file containing the number of streams in that part of the dataset (necessary for looping)
build_max(){
    for week in '1' '2' '3'; do
        for protocol in 'tcp' 'udp' 'icmp'; do #2 protocols that we are working on
            for mode in 'inside' 'outside'; do #two sniffing modes from dataset
                for day in '1' '2' '3' '4' '5'; do #5 days (mon ~ fri)
                    if [ $protocol = 'tcp' ];
                        then protocol_network='tcp';
                        else protocol_network='udp'; #udp and icmp are both udp protocol..
                    fi
                    path='../Week'$week'/streams';
                    file=$path'/../pcaps/'$protocol'_'$mode'_'$day'.pcap'; #file holds stream files location
                    tshark -r $file -T fields -e "$protocol_network.stream" |sort -n > $path'/../pcaps/max_aux.csv';
                    tail -1 $path'/../pcaps/max_aux.csv' > $path'/'$protocol'_'$mode'_'$day'/'$protocol'_'$mode'_'$day'_numstream.csv'; #grab al conections and save the total on a file for registry
                    max_streams=$(tail -1 $path'/../pcaps/max_aux.csv'); #Max number of streams present in the pcap file
                    echo "max streams for " $week' '$protocol' '$mode' '$day':'$max_streams
                done
            done
        done
    done
}
#===================================================#===================================================
setup() { #setup the enviroment for the system
    for week in '1' '2' '3';do
        path='../Week'$week'/pcaps'
        num=1; #just for control the files (they all have the same names)
        for day in 'monday' 'tuesday' 'wednesday' 'thursday' 'friday';do
            for mode in 'inside' 'outside';do
                if [ ! -e $path'/'$day ];then
                    mkdir $path'/'$day;
                fi
                wget -c -P $path'/'$day'/' 'https://archive.ll.mit.edu/ideval/data/1999/'$week'week/'$day'/'$mode'.tcpdump.gz' #Download dataset
                gunzip $path'/'$day'/'$mode'.tcpdump.gz'; #Extract dataset from compressed file
                mv $path'/'$day'/'$mode'.tcpdump' $path'/'$mode$num'.pcap' #Rename the data file to pcap to be able to read
            done;
            ((num++))
        done;
        for mode in 'inside' 'outside';do
            for num in '1' '2' '3' '4' '5';do
                for protocol in 'tcp' 'udp' 'icmp';do
                    $(tcpdump -r $path$mode$num'.pcap' -w $path$protocol'_'$mode'_'$num'.pcap' $protocol); #Select only the data with tcp, udp and icmp
                done
            done
        done
    done;
}
#=======================================================#===================================================
sniff() { #Sniff the network and records the data in a csv file in ids/logs/dump*
    sudo rm -r logs
    if [ ! -e ./logs ];then mkdir logs; fi #Creates a logs directory for register
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

"$@"  #This makes the script run the function that is given by parameter to this script
