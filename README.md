<i><ol>
<li>Introduction
<li>Used Database
<li>Training ML Model
<li>The system developed
<li>Files of the project
<li>Used Features for ML
<li>Data collected from PKG's
<li>Attacks included
<li>Installation
</ol>
</i>

<b>1 Introdução </b><p>
Este projeto foi criado com o propósito de estudo e com o objetivo de implementação um Sistema de Detecção de Intrusão (IDS) em redes locais, utilizando para isto técnicas de aprendizado de maquina, que possibilitam a geração de algoritmos capazes de distinguir estados de um conjunto de dados de acordo com a variação de valores das entradas fornecidas, gerando assim modelos capazes de distinguir o estado (normal ou anômalo) de uma conexão.

O sistema desenvolvido visa dar ao usuário a possibilidade de analisar, em tempo real ou rotineiramente, se está havendo ou houve alguma tentativa de exploração ao sistema a partir da rede interna ou externa a qual o sistema está se comunicando. A efetividade dos resultados está diretamente relacionada à qualidade do dataset utilizado para treinamento do modelo de Machine Learning, além da qualidade das features que são geradas para analise do modelo proposto, dados estes que serão explicitados nesse documento.

<b>2 A Base de Dados utilizada </b><p>
Para se definir se um conjunto de dados provenientes de uma rede são ou não tentativas de ataque ao sistema via rede, se faz necessário um banco de dados contendo registros de conexões maliciosas e normais, afim de os dados serem computados pelo algoritmo de aprendizado de maquina e, através do cruzamento entre esses dados, a geração de um modelo contendo regras que definem, a partir de uma estrada de dados ainda não computada, se esses dados são provenientes de uma conexão anômala ou normal. Foi escolhida a utilização da base de dados de uma agência do departamento de defesa dos Estados Unidos, o dataset DARPA99, que contém um número muito grande de conexões anômalas, geradas a partir da simulação de ataques em redes de computadores em ambiente controlado.

O dataset DARPA99 conta com, além de outros atributos, estados e variáveis de todos os atributos da rede que foram gerados ao longo de 3 semanas de simulação. Os registros das conexões estão classificados entre conexões normais e anômalas, e estas são utilizadas para que o algoritmo possa aprender sob quais circunstancias uma conexão pode ser considerada normal ou um ataque de rede. 

A ideia é treinar um modelo que seja capaz de definir se uma conexão sendo recebida atualmente através rede do usuário se parece com conexões de ataque presentes na base de dados do DARPA99, indicando assim se uma conexão é ou não um ataque de rede.

<b>3 Treinamento do Modelo de Machine Learning</b><p>
O dataset contém arquivos de dump da rede que foi submetida a ataques de rede de variadas formas, esses arquivos se encontram na forma de dados brutos de TCPDUMP. Antes de se analisar os dados do dataset é necessário realizar a limpeza e o modelamento destes, tendo em vista que somente é possível identificar se uma conexão é ou não um ataque de rede através da conexão como um todo, e não através da analise de um pacote específico de uma conexão, então é necessário agrupar os milhares de pacotes em cada arquivo do dataset em conjuntos definidos de <b>streams</b>, sendo esta a conexão como um todo, podendo conter infinitos pacotes.

Com o tratamento de dados concluído, é necessário identificar quais variáveis da conexão são importantes para se identificar uma anomalia (ataque de rede), a logica da criação e implementação dessas features tiveram como base outro dataset derivado do darpa99, KDD99, e estas serão listadas em detalhes no decorrer deste documento.

Com as features já definidas e implementadas, é necessário realizar o preprocessamento dos dados coletados e finalmente gerar um modelo através dos algoritmos de Aprendizado de Maquina. Foi implementado um algoritmo que roda os principais algoritmos ML, e realiza a escolha do modelo gerado pelo algoritmo que teve maior Pontuação (Score) analisando os dados do dataset, o Score de cada algoritmo pode variar de dataset em dataset, por isso a necessidade de escolha dinâmica.

```python 
[...]
def Algorithms(algorithm,X_train,y_train,X_test,y_test):
    elif(algorithm == lr):model = LogisticRegression();name_alg = "Logistic Regression"
    elif(algorithm == neural):model = MLPClassifier(solver='lbfgs', alpha=1e-5, hidden_layer_sizes=(5, 2), random_state=15);name_alg = "Neural Network"
    elif(algorithm == forest):model = RandomForestClassifier(n_estimators=70,oob_score=True,n_jobs=-1,random_state=101,max_features=None,min_samples_leaf=30);name_alg = "Random Forest"
    model.fit(X_train,y_train)
    y_pred = model.predict(X_test) 
    [...]
```
```
Running Algorithms for prediction...
** Algorithms Score: **
Naive Bayes: 0.6212121212121212
Stochastic: 0.5303030303030303
Decision Tree: 0.9545454545454546
Logistic Regression: 0.9242424242424242
Rede Neural: 0.5303030303030303
Random Forest: 0.9393939393939394
```

Com o modelo de ML treinado, este já pode predizer, analisando os dados de uma conexão de rede, se esta tem características que indicam ser uma conexão normal ou um ataque de rede, assim o modelo é armazenado para ser usado pelo algoritmo que verifica os dados da rede do usuário do sistema.

<b>4 Funcionamento do Sistema Desenvolvido</b><p>
O Script inicia uma chamada para o software livre TCPDUMP, responsável pela captura de pacotes em toda a rede, de forma contínua, recebendo assim todas as informações sobre os pacotes. Com os pacotes da rede sendo capturados, é necessário realizar a filtragem de informação sobre o pacote e sua payload, logo é utilizado o software livre TSHARK; Com este, é possível realizar a filtragem de conteúdo relacionado ao pacote que se deseja armazenar, realizando assim a filtragem de dados relevantes e a conversão de dados brutos do sniffer de rede em formato PCAP para dados utilizáveis em formato CSV. Os dados relevantes foram definidos de acordo com a necessidade de informações necessárias para se criar e manipular as features.

```shell
[...]
sudo tcpdump -q -w ./logs/network_dump.pcap tcp or udp |
tshark  -r  $file  -Y "$protocol.stream eq $stream" -T fields -e _ws.col.No. -e _ws.col.DateTime
-e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Protocol -e frame.cap_len -e ip.proto -e ip.flags
-e $protocol'.srcport' -e $protocol'.dstport' -e tcp.flags -e tcp.urgent_pointer -e tcp.window_size_value
-E header=n -E separator=, -E occurrence=f >> $path$protocol"_"$mode"_"$day"/"$protocol"_stream_"$stream".csv";
```

A informação estruturada recebida é então enviada ao script python que realiza uma série de tratamentos com os dados com base nas informações do pacote, como a identificação do protocolo, o a porta de serviço usada e o mapeamento de stream (conexão), esta sendo a indicação de a qual conjunto de pacotes este pacote pertence, o que é imprescindível para o gerenciamento lógico dos pacotes e a identificação e padrões anômalos na rede. Após o tratamento dos dados do pacote, a informação deste é gravada no arquivo de sua stream correspondente e o pacote é então inserido na estrutura de gerenciamento fluxo de rede do sistema, onde este é responsável por analisar e atualizar o estado das conexões existentes; Ativa, Finalizada, erro, morta...

```python
[...]
for stream in list_time: 
        if((int(time.time()-int(stream[0])) >= maximum_hold_time)): 
            try: #case dead.. send the stream of pkg's to features creation, process and model analisys
                analisys = Analyse(path+stream[2]+'_stream_'+str(stream[1])+'.csv',stream[2],stream[1])
                if(analisys == 0):
                    output=(stream[2]+' stream '+str(stream[1])+bcolors.OKGREEN + ' Normal Connection ' + bcolors.ENDC)
[...]                    
```

Quando o termino de uma conexão é identificada (através de flags de termino de comunicação de pacotes TCP, ou excedimento de tempo limite sem resposta), os pacotes referentes a essa conexão são enviados ao script que realiza o modelamento dos dados dos vários pacotes de rede a fim de se obter features referentes à conexão (stream) como um todo, sendo assim possível extrair dados temporais e de interação entre os pacotes.

```python
[...]
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
[...]            
```

As informações extraídas da conexão passam então por um preprocessamento necessário para que o dados possam ser corretamente interpretados pelo modelo de Machine Learning:

```python
[...]
from sklearn.preprocessing import LabelEncoder;le = LabelEncoder() #None to Literal to int
    #Coercing type of data inside the df
    streams_dataframe.duration = streams_dataframe.duration.astype(float)
    streams_dataframe.protocol_type = streams_dataframe.protocol_type.astype(str)
    streams_dataframe.service = streams_dataframe.service.astype(str)
    streams_dataframe.srv_rerror_rate = streams_dataframe.srv_rerror_rate.astype(int)
    streams_dataframe.srv_diff_host_rate = streams_dataframe.srv_diff_host_rate.astype(int)
    [...]
    streams_dataframe.protocol_type = le.fit_transform(streams_dataframe.protocol_type)
    streams_dataframe.service = le.fit_transform(streams_dataframe.service)
[...]
```

Então é necessário apenas realizar o processamento da stream particular que está em análise e enviar os dados de suas features para processamento no modelo treinado, afim de que este possa analisar através da correspondência de suas regras internas aprendida durante o cruzamento de conexões com características normais e anômalas, podendo então ser descoberto a existência ou não de padrões que indiquem que uma determinada conexão na rede do usuário do sistema tenha correspondência com os ataques de rede já determinados dentro do modelo. Caso a conexão seja normal ou anômala, o sistema fará o gerenciamento da informação e exibirá os resultados em tempo real para o usuário.

```python
trained_model = pickle.load(open('./models/trained_model_darpa.sav','rb')) #import model from a file
    prediction = trained_model.predict(streams_dataframe_ml) #run model with 1 line dataframe
    if(prediction == 1):
        num_anomaly_verify+=1;
        print(current_protocol,' stream ',current_stream,bcolors.WARNING + 'Anomaly Connection ' + bcolors.ENDC,num_anomaly_verify,end='\n')
    elif(prediction == 0):
[...]
```

<b>5 Especificação dos Arquivos de Projeto</b><p>
<ul>
<li><i>Processor_shell.sh<i>: Funções em shell que controlam ações em que é necessária a ação direta do sistema linux.
    <ul>
    <li>sniff(): Inicia a captura de pacotes com tcpdump já estruturando a captura com tshark de forma contínua</li>
    <li>build_streams(): Realiza a modelagem dos dados brutos do dataset, dividindo o grande arquivo em diferentes arquivos contendo cada um os pacotes referentes a cada stream (conexão como um todo).</li>
    <li>Outras funções de organização interna de diretorios de projeto</li>
    </ul>
</li>
<li>
<i>Processor_Stream.py</i>: Funções responsáveis por pegar os dados dos vários pacotes de uma mesma conexão e estrutura-los de modo que possam fornecer informações da conexão completa, criando assim as features básicas, relacionadas por tempo e relacionadas por conexão e serviços.
</li>
<li>
<i>Processor_Database.py</i>: Funções responsáveis por manipular os arquivos tratados e estruturados tirados do dataset afim de se aplicar técnicas de machine learning para criar o modelo capaz de analisar conexões e definir de qual natureza esta pertence.
</li>
<li>
<i>Processor_Network.py</i>: Funções que realizam a limpeza, estruturação, preprocessamento e predição de cada conexão capturada com o sniffer de dados, enviando os dados dessa conexão para análise do modelo de ML criado.
</li>
<li>
<i>init_ids.py</i>:Arquivo principal do sistema, onde todas as funções são chamadas de acordo com a execução do script. Responsável pela exibição dos resultados no terminal, gerenciamento de chegada dos pacotes capturados, leitura dos arquivos de registro, gerenciamento lógico do sistema e tratamento de erros que possam ocorrer em tempo de execução. Contém 3 modos: treinamento de modelo, verificação de eficiência do modelo e análise de conexões da rede.
</li>
</ul>

<b>6 Features Utilizadas para treinamento e Analise das conexões:</b><p>
O modo de implementação de cada feature está presente no arquivo processor_stream.py do projeto e foi desenvolvida com base em features do dataset KDD99:<br>
<ul>
<li> Duration: Length of time duration of the connection</li>
<li> Protocoltype: Protocol used in the connection</li>
<li> Service: Destination network service used </li>
<li> Flag: Status of the connection – Normal or Error </li>
<li> Srcbytes: Number of data bytes transferred from source to destination in single connection</li>
<li> Dstbytes: Number of data bytes transferred from destination to source in single connection</li>
<li> Land: if source and destination IP addresses and port numbers are equal then, this variable takes value 1 else 0 </li>
<li> Wrongfragment: Total number of wrong fragments in this connection</li>
<li> Urgent: Number of urgent packets in this connection. Urgent packets are packets with the urgent bit Activated</li>
<li> Srvcount: Number of connections to the same service (port number) as the current connection in th e past two seconds</li>
</ul>

<b>7 Dados capturados de cada pacote (tshark) para geração de features: </b><p>
<ul>
<li>Layer 1</li><ul>
<li>frame.time #hora e data de chegada do pacote</li>
<li>frame.protocols #protocolos presentes no pacote</li>
<li>frame.cap_len #tamanho total do pacote</li>
</ul><li>Layer 2</li><ul>
<li>eth.dst #domain destino</li>
<li>eth.src #domain fonte</li>
</ul><li>Layer 3</li><ul>
<li>ip.src #ip fonte</li>
<li>ip.dst #ip destino</li>
<li>ip.proto #protocolo camada 4 (tcp,udp,icmp)</li>
<li>ip.flags #relatorio pacote *</li>
</ul><li>Layer 4</li><ul>
<li>tcp.flags #relatorio pacote</li>
<li>tcp.srcport #porta source</li>
<li>tcp.dstport #porta destino (service da conexão)</li>
<li>tcp.len #tamanho da payload tcp</li>
<li>tcp.urgent_pointer #flag URG</li>
<li>tcp.window_size_value #tamanho do buffer</li>
<li>tcp.sequence_number #Sequencia de pacotes</li>
<li>udp.srcport</li>
<li>udp.dstport</li>
<li>udp.length</li>
</ul></ul>

<b>8 Ataques que compões o dataset:</b><p>
<ul>
<li> back: Denial of service attack against apache webserver where a client requests a URL containing many backslashes.<br>
<li> crashiis: A single, malformed http request causes the webserver to crash.<br>
<li> dict: Guess passwords for a valid user using simple variants of the account name over a telnet connection. <br>
<li> eject: Buffer overflow using eject program on Solaris. Leads to a user->root transition if successful.<br> 
<li> ffb: Buffer overflow using the ffbconfig UNIX system command leads to root shell<br>
<li> format: Buffer overflow using the fdformat UNIX system command leads to root shell<br> 
<li> ftp: write-Remote FTP user creates .rhost file in world writable anonymous FTP directory and obtains local login. <br>
<li> guest: Try to guess password via telnet for guest account.<br> 
<li> httptunnel: There are two phases to this attack:<br> 
<li> Setup: a web "client" is setup on the machine being attacked, which is configured, perhaps via crontab, to periodically make requests of a "server" running on a non-privilaeged port on the attacking machine.<br>
<li> Action: When the periodic requests are recieved, the server encapsulates commands to be run by the "client" in a cookie.. things like "cat /etc/passwd".. etc..<br>
<li> imap: Remote buffer overflow using imap port leads to root shell <br>
<li> ipsweep: Surveillance sweep performing either a port sweep or ping on multiple host addresses. <br>
<li> land: Denial of service where a remote host is sent a UDP packet with the same source and destination <br>
<li> loadmodule: Non-stealthy loadmodule attack which resets IFS for a normal user and creates a root shell<br> 
<li> mailbomb: A Denial of Service attack where we send the mailserver many large messages for delivery in order to slow it down, perhaps effectively halting normal operation.<br>
<li> multihop: Multi-day scenario in which a user first breaks into one machine<br> 
<li> neptune: Syn flood denial of service on one or more ports.<br> 
<li> nmap: Network mapping using the nmap tool. Mode of exploring network will vary—options include SYN <br>
<li> ntinfoscan: A process by which the attacker scans an NT machine for information concerning its configuration, including ftp services, telnet:services, web services,  system account information, file systems and permissions.<br>
<li> perlmagic: Perl attack which sets the user id to root in a perl script and creates a root shell <br>
<li> phf: Exploitable CGI script which allows a client to execute arbitrary commands on a machine with a misconfigured web server. <br>
<li> pod: Denial of service ping of death<br> 
<li> portsweep: Surveillance sweep through many ports to determine which services are supported on a single host. <br>
<li> ps: Ps takes advantage of a racecondition in the ps command in Sol. 2.5, allowing a user to gain root access.<br>
<li> rootkit: Multi-day scenario where a user installs one or more components of a rootkit<br> 
<li> satan: Network probing tool which looks for well-known weaknesses. Operates at three different levels. Level 0 is light <br>
<li> secret<br>	 
<li> smurf: Denial of service icmp echo reply flood. <br>
<li> spy-Multi: day scenario in which a user breaks into a machine with the purpose of finding important information where the user tries to avoid detection. Uses several different exploit methods to gain access. <br>
<li> syslog: Denial of service for the syslog service connects to port 514 with unresolvable source ip.<br>
<li> teardrop: Denial of service where mis-fragmented UDP packets cause some systems to reboot.<br> 
<li> warez: User logs into anonymous FTP site and creates a hidden directory.<br> 
<li> warezclient: Users downloading illegal software which was previously posted via anonymous FTP by the warezmaster. <br>
<li> warezmaster: Anonymous FTP upload of Warez (usually illegal copies of copywrited software) onto FTP server.<br>
</ul>

<b>9 Instalação</b><p>
O sistema linux deve conter os seguintes programas instalados: python, python3, py.pandas, py.sklearn, py.numpy, py.pickle, tcpdump, tshark:<br>
$(sudo apt update);<br>
$(sudo apt upgrade -y);<br>
$(sudo apt install python);<br>
$(sudo apt install -y python3-pip);<br>
$(python3 -m pip install --upgrade pip);<br>
$(python3 -m pip install pandas);<br>
$(python3 -m pip install sklearn);<br>
$(python3 -m pip install numpy);<br>
$(python3 -m pip install pickle);<br>
$(sudo apt install tcpdump -y);<br>
$(sudo apt install tshark -y);<br>
$(./init_ids.py); #Inicialização do script na pasta do projeto terminal em modo root ou sudo para ser possível a chamada ao TCPDUMP.<br>
obs:Será impossível rodar o script em modo de treinamento e verificação sem ter os dados do dataset darpa99 no mesmo diretório.<br>
