<b> A Base de Dados Utilizada </b>
Com o intuito de ser possível a criação de regras que possam identificar assinaturas ou padrões, presentes em quaisquer tipos de dados, é necessário que sejam pré-estabelecidos dados "parâmetros" que contenham os padrões desejados. Na questão do presente trabalho, que visa a identificação de conexões em rede que possam ter como objetivo a exploração de vulnerabilidades de um sistema via rede, foi escolhida uma base de dados contendo conexões de rede normais (sem a intenção de exploração de sistemas) e conexões que façam parte de ataques em redes.

A base de dados utilizada foi o DARPA99 que consiste em registros de capturas de pacotes em uma rede controlada em um laboratório militar dos EUA. Durante três semanas foram gerados tráfegos de rede interna e externa, em duas das três semanas somente tráfego inofensivo foi gerado e durante uma semana foram simulados somente tráfego que foram compostos por diferentes tentativas de invadir os sistemas terminais do ambiente. Consistindo da captura desses dados, a base de dados DARPA99 foi dividida em dois grupos de dados, aqueles que tenham conexões inofensivas para o correto funcionamento de sistemas, e o grupo que contém as assinaturas de conexões com natureza maliciosa.
    




<b> Seleção de Dados </b>
    Visto a natureza com que o conjunto de dados foi criado, os dados presentes neste estão em sua forma bruta (binários), portanto antes de se começar a trabalhar com os dados da base de dados é necessário realizar uma seleção de dados que serão realmente necessários para a aplicação. Como o objetivo do sistema proposto é a identificação de padrões de conexões maliciosas, a seleção de pacotes de rede foi realizada com base nas características que possibilitem a diferenciação entre pacotes de rede normais e maliciosos.

Os dados foram selecionados com base no protocolo de rede utilizado por estes, visto que as assinaturas de conexões maliciosas presentes no conjunto de dados utilizam estes protocolos. Portanto foram selecionados do conjunto de dados os dados que tenham como protocolo da camada de transporte, os protocolos TCP e UDP, visto que estes são os pacotes que terão utilidade na análise das conexões presentes na base de dados. 

Também é necessário realizar a conversão do tipo de arquivo presente no conjunto de dados ".tcpdump" para um formato em que seja possível trabalhar com os dados, realizando assim a conversão para uma extensão propícia de leitura dos dados de rede ".PCAP". Utilizando a ferramenta tcpdump em cada um dos arquivos disponibilizados pelo conjunto de dados é feita a seleção de dados com base nos protocolos de camada de transporte.

```shell
#Project File: module_shell.sh extract_protocol()
for mode in 'inside' 'outside';do
    for day in '1' '2' '3' '4' '5';do
        for protocol in 'tcp' 'udp' 'icmp';do
            $(sudo tcpdump -r $path$mode$day'.pcap' -w $path$protocol'_'$mode'_'$day'.pcap' $protocol);
        done
    done
done
```





<b> Preparação de Dados </b>
Se tratando de um sistema IDS, o foco deste não é realizar projeções através da análise individual de cada pacote, e sim analisar a conexão como um todo, comparando esta à base de dados contendo assinaturas de conexões maliciosas.

Os arquivos presentes no conjunto de dados contém o registro de todos os pacotes trafegados na rede, assim é necessário realizar engenharia reversa em todo o conjunto de pacotes a fim de remontar as conexões, que nada mais são que conjuntos de pacotes pertencentes à uma mesma comunicação entre 2 terminais em uma rede.

Para isto, é preciso realizar a leitura de cada entrada em todos os arquivos presentes no conjunto de dados, encontrando o identificador de conexão em cada pacote, adicionando esta entrada (pacote de rede) à uma estrutura lógica adequada para se trabalhar posteriormente.

O sistema proposto cria um arquivo para cada conexão distinta e adiciona o pacote lido ao arquivo de conexão correspondente. Assim, ao final do processamento de cada arquivo presente no conjunto de dados, o sistema terá gerado arquivos que representam conexões individuais de uma rede.

O módulo implementado (module\_database) realiza o processo de leitura e processamento de cada arquivo do conjunto de dados, e, ao mesmo tempo, realiza também um processo de estruturação de cada um dos pacotes de rede, extraindo de cada arquivo do conjunto de dados os atributos desejáveis de cada pacote.

Estes atributos são necessários para a mineração de dados em etapas posteriores, sendo esta portanto uma parte crucial do processo visto que as features necessárias para a criação, treinamento e aplicação de um modelo de aprendizado de máquina serão criadas a partir de cada um dos atributos desses pacotes.

```shell
#Project File: module_shell.sh build_streams()
for week in '1' '2' '3';do
  for mode in 'inside' 'outside';do
    for day in '1' '2' '3' '4' '5';do
      for protocol in 'tcp' 'udp' 'icmp';do
        mkdir $path'pcaps/csvs/'
        path=$1'Week'$week;
        file=$path'/pcaps/'$protocol'_'$mode'_'$day'.pcap'; #file holds streams location
        echo -ne "Computing Week $week $protocol $mode $day "\\r; #feedback to user
        #Reads from pcap files(network dump) filtering the data to the selected (-e) attributes of the packages:
        tshark  -r  $file -T fields -e tcp.stream -e udp.stream -e frame.time_relative -e ip.proto -e _ws.col.Protocol 
        -e tcp.flags -e tcp.urgent_pointer -e frame.cap_len  
        -e ip.flags -e tcp.window_size_value -e tcp.srcport 
        -e tcp.dstport -e udp.srcport -e udp.dstport -e ip.src 
        -e ip.dst -E header=n -E separator=, -E occurrence=f 
        >> $path$protocol"_"$mode"_"$day"/"$protocol"_stream_"$stream".csv";
      done
    done
  done
done
```





<b> Transformação de Dados </b>
Com os dados do conjunto de dados já pré-processados, os dados já estão aptos para serem importados pelo sistema e serem trabalhados, através da leitura de arquivos locais o sistema faz a leitura de todos os diretórios gerados na parte de pré-processamento de dados e transforma os pacotes importados para as estruturas de dados do sistema.

Quando o sistema realiza a leitura de um arquivo do conjunto de dados, os dados estão sempre na forma de texto simples e quando esse texto é importado para o sistema é iniciado o construtor da classe Package (module\_package.py), fazendo assim a transformação da linha de texto em um objeto da classe Package, este contendo como atributos de classe os atributos de um pacote de rede.

Os objetos Package são então agrupados em uma estrutura de dados que representa a própria conexão de rede, a classe Stream (module\_stream.py) é responsável por agrupar logicamente os pacotes que provenham de uma mesma conexão, contendo como atributos diversos elementos essenciais para a gestão de dados da aplicação proposta.

Os objetos da classe Stream, que pode ser vista conceitualmente como uma conexão única entre dois nós em uma rede, tem a tarefa de realizar o pós-processamento de seus pacotes no intuito de realizar a análise de todos os seus pacotes de rede constituintes e gerar novas informações que representem o comportamento da conexão como um todo. Essa nova transformação nos dados tem o objetivo de agrupar o comportamento dos pacotes durante toda a conexão em variáveis únicas que possam ser lidas e interpretadas por algoritmos de aprendizado de máquina, passando a serem chamadas de Features, entradas válidas de um modelo de Machine Learning.

```python
[...]
path_stream = (path_dataset+protocol+'_stream_'+str(count)+'.csv'); #path to each stream  into the SO
if(os.path.exists(path_stream) and os.stat(path_stream).st_size != 0):#check if exists the streams file
    readed_packages = Read_file(path_stream); #read the file (COMMON.py)
    processor_package = Processor_package(); #Use function assemble_packages;
    list_packages = processor_package.Assemble_packages(readed_packages); #assemble the lines into packages
    stream = Processor_stream(list_packages); #creates the structure of the stream;
    stream.Generate_features(); #generates the features
    features_dataframe = stream.Generate_dataframe(week); #structures the features in pandas table
    if(mode_run=='train'):self.Join_dataframe(features_dataframe); #append current dataframe to the final dataframe
    elif(mode_run=='verify'):dataframe_list.append([features_dataframe,stream,week]); #saves the stream
    [...]
```
A classe Stream realiza a exportação de seus pacotes para funções que retornam características (features) relativas à conexão, sendo possível, através dessas, a conclusão de informações como o comportamento dos pacotes em relação ao tráfego temporal ocorrido na conexão, informações básicas de cada vetor de conexão, relacionamento de conteúdo trafegado entre outros.

A codificação das features implementadas no presente trabalho (module\_features.py) foram desenvolvidas de acordo com a documentação do conjunto de dados KDD99, um conjunto de dados também relacionado à análise de conexões maliciosas derivadas da base de dados utilizada neste trabalho (DARPA99).

```python
[...]
for count in range(0,len(package_list)): #run through every package
            if(package_list[count].flag == '0x00000002'): #check the code for the flag
                package_list[count].flag = 'SYN'; #translated to be used later
                if(package_list[count].ip_src == self.source):buffer_syn_src = 1; #register the existence of the flag
            elif(package_list[count].flag == '0x00000012'):
                package_list[count].flag = 'SYN-ACK'
                if(package_list[count].ip_src != self.source):buffer_synack_dst = 1
            elif(package_list[count].flag == '0x00000010'):
                package_list[count].flag = 'ACK'
                if(package_list[count].ip_src == self.source):buffer_ack_src = 1
                if(package_list[count].ip_src != self.source):buffer_ack_dst = 1
            elif(package_list[count].flag == '0x00000018'):
            [...]
            Process the flags registered in the connection to return the corresponding behavior of the packages
        if(buffer_syn_src == 1 and buffer_synack_dst == 0): return('S0') #connection tried.. no answer
        elif(buffer_syn_src == 1 and buffer_synack_dst == 1):#conexão estabelecida
            if(buffer_rst_src == 1 and buffer_rst_dst == 0):return('RSTO')#source aborted the connection
            elif(buffer_rst_src == 0 and buffer_rst_dst == 1):return('RSTR')#destination aborted the connection
            elif(buffer_fin_src == 0 and buffer_fin_dst == 0): return('S1')#connected, not finished
            [...]
```





<b> Mineração de Dados </b>
   Com as Features geradas, estas estão aptas a serem processadas pelos algoritmos de aprendizado de máquina. O objetivo é criar um modelo capaz de classificar uma conexão entre dois grupos distintos: conexões maliciosas e normais.

Isto é feito através da técnica de Mineração de dados presentes nos algoritmos, podendo a mineração de dados ser expressa como o processo de encontrar padrões em dados.

As features geradas são então processadas pelos algoritmos, estes utilizarão uma parte dos dados disponíveis para aprender a detectar os tipos de conexão e outra parte para realizar a validação, a fim de determinar o quão precisamente o algoritmo consegue classificar os dados.

Esse processo de aprendizagem se dá por meio da identificação de padrões ou assinaturas presentes em cada tipo de conexão, criando assim regras de modelagem que possibilitam a classificação de uma dada entrada qualquer entre entradas (conexões) Maliciosas ou Normais.

Utilizando como referência a precisão de cada algoritmo, ou seja, a capacidade de reconhecimento de padrões nos dados de entrada e a correta classificação destes, é realizado a seleção do modelo que conseguiu identificar corretamente o maior número de entradas.

Por se tratar de um problema de classificação de dados, os dados já selecionados, pré-processados e transformados como visto nos passos da ciência de dados são então divididos em 2 grupos, Treinamento e Teste O grupo de treinamento será utilizado pelos algoritmos para a criação das regras, do modelo propriamente dito e o grupo de teste será responsável por verificar a precisão com que o modelo consegue classificar corretamente os dados, sendo isto possível pelo fato de os dados já serem previamente categorizados em conexões de ataques e conexões normais.

Ao final do processo de treinamento de um modelo pelos algoritmos, é realizado o teste, onde a parte da base que foi dividida para o grupo de teste entra em ação, o modelo então tenta classificar todos os dados dentro dessa base e, gerando assim sua taxa de sucesso de predição dos dados. Esse dado é utilizado para escolher qual o modelo gerado por qual algoritmo será utilizado pelo sistema principal já na fase de aplicação real do sistema.

```python
def Train_model(self,train_dataframe):
        train_dataframe = self.Preprocess_data(train_dataframe) #converts literal features to int for ML
        models_scores = []; #holds the model name and his score in classifying normal and anomaly connections correctly
        from sklearn.model_selection import train_test_split
        Features_train_model = Features_names[:];Features_train_model.remove('classe');
        (X_train, X_test, y_train, y_test) = (  #Divide all data into 4 pieces for ML (y=verify acurracy, x=train)
           train_test_split(train_dataframe[Features_train_model],
                train_dataframe.classe,test_size=0.33,random_state=42));
        for model in self.models_list: #for each model registered at __init__
            model[0].fit(X_train,y_train) #model[0] = model, model[1] = model-name
            y_pred = model[0].predict(X_test)  #get model score
            from sklearn.metrics import accuracy_score #Calculo de precisão
            print(model[1],accuracy_score(y_test,y_pred));
            models_scores.append([model[1],accuracy_score(y_test, y_pred),model[0]]) 
            [...]
```





<b> Aplicação de Dados </b>
A execução do sistema se inicia a partir do arquivo de projeto main.py, este script python aceita argumentos de acordo com a funcionalidade desejada entre as opções de treinamento de um novo modelo, onde será feito todo o processo descrito nos subcapítulos anteriores, verificação de precisão do modelo de acordo com os dados da base de dados ou a execução da aplicação principal.

A aplicação principal tem como objetivo colocar em prática o sistema IDS, realizando a captura de pacotes trafegando na rede em tempo real, importando, tratando e analisando as conexões por estes geradas. Para isto, o sistema inicia um processo de captura de todo o tráfego na rede do usuário, os pacotes capturados são salvos em um arquivo no formato .PCAP.
```python
#Project File: module_shell.sh Sniff()
sniff() {
    sudo rm -r logs
    if [ ! -e ./logs ];then mkdir logs; fi
    sudo tshark -q -T fields -e tcp.stream -e udp.stream
    -e frame.time_relative -e ip.proto -e _ws.col.Protocol 
    -e tcp.flags -e tcp.urgent_pointer -e frame.cap_len  
    -e ip.flags -e tcp.window_size_value -e tcp.srcport 
    -e tcp.dstport -e udp.srcport -e udp.dstport -e ip.src 
    -e ip.dst -E header=n -E separator=, -E occurrence=f >
    ./logs/brute_streams.csv 
}
```

Em um loop infinito a aplicação realiza a importação dos dados contidos neste arquivo, instanciando-os no sistema como objetos de pacotes de rede. Os objetos pacotes são então adicionados na estrutura de dados das conexões a que fazem parte, realizando ao mesmo tempo uma série de processos que visam o controle da aplicação sobre os dados, como o gerenciamento de conexões ativas e também a atualização de atividade de uma conexão que visa identificar se a conexão entre as máquinas já está encerrada.

```python
#Project File: module_system.py Check_network()
 def Check_network(self):
    processor_package = Processor_package();
    lines = Read_file(self.path_new_pkgs); #lines receive the file content (COMMON.py)
    lines = lines[(self.last_pkg_readed+1):len(lines)-1] #lines updated to only the packages not readed
    self.last_pkg_readed += len(lines) #update the last package readed
    assembled_packages = processor_package.Assemble_packages(lines); #lines readed of the file tranformed into packages
    self.Redirect_packages(assembled_packages); #send the packages to their right streams
```

Depois da importação de pacotes para o sistema, a aplicação faz a verificação de estado de cada uma das conexões, identificando o tempo de ociosidade destas, o qual é atualizado sempre que um novo pacote é adicionado. Caso o tempo de ociosidade máximo da conexão seja extrapolado ou o termino de conexão seja identificado, a aplicação começa o processo de análise dessa stream.

```python
#Project File: module_sytem.py Check_activity()
 for obj_stream in streams_protocol: #get every stream in the stored streams
    if(len(obj_stream.package_list) > 0): #Check if the stream already has any package
        if((int(time.time() - obj_stream.last_modified)) >= self.max_hold_time): #if too long without activity...
            obj_stream.Generate_features(); #Generate features of the stream
            stream_dataframe = obj_stream.Generate_dataframe(); #Generates stream dataframe
            obj_database = Processor_database(); #use predict data with model on database module
            prediction = obj_database.Predict_data(stream_dataframe); #Analyses the stream with ML
            Print_prediction(prediction,obj_stream,self.normal_anomaly_count); #Outputs the result of analisys
            streams_protocol.remove(obj_stream); #do not analise this stream again
            done_streams.append(obj_stream.index); #Add the stream to the analised list
```
A análise consiste em realizar os processos que foram feitos na etapa de treinamento de modelo, realizando uma série de processos na intenção de formatar os dados de todos os pacotes em variáveis que representam a conexão como um todo, gerando as features. 

As features (dados da conexão) são então enviados para uma rotina que realiza a importação do modelo treinado. O modelo então realiza a leitura das features e realiza a inferência de suas entradas com as regras geradas pelo modelo, como se os dados estivessem sendo comparados com dados de ataque de uma base de dados maliciosos, e então retorna para a aplicação a natureza da conexão analisada.

Caso o modelo de aprendizado de máquina identifique uma conexão suspeita, será reportado ao usuário do sistema, gravando os dados gerados da conexão como um todo em um arquivo de registro (log), assim como os dados de todos os pacotes daquela conexão para posterior análise humana ou por outros sistemas de segurança.

```python
#Project File: module_database.py Predict_data()
def Predict_data(self,stream_dataframe):
    obj_database = Processor_database(); #initializate for use his methods
    stream_dataframe = obj_database.Preprocess_data(stream_dataframe);
    model = obj_database.Load_model(self.path_model); #loads the ml model to the program (alter in self.attributes)
    stream_dataframe = stream_dataframe.drop(columns = 'classe'); #drops classe since data hasnt label
    data_prediction = model.predict(stream_dataframe); #prediction normal vs attack
    return(int(data_prediction));
```
    
    
    
    
    
<b>Resultados</b>    
Com a base de dados utilizada para o treinamento do modelo de aprendizado de máquina, foram extraídos mais de 1.600.000 registros de conexões maliciosas e normais, sendo 66\% dos registros foram utilizados para fins de treinamento e 33\% para fins de validação do modelo utilizando a técnica de cross-validation.

Diante da enorme quantidade de dados presentes no conjunto de dados, durante o processo de desenvolvimento das rotinas, ficou claro que era inviável o processamento de todo o conjunto de dados através do uso de computadores de uso geral, modelo que estava sendo utilizado até o momento. Isto se deve à grande quantidade de dados na base de dados demandar muito tempo e extrema requisição de processamento para que os algoritmos processem todas as entradas, assim foi utilizada uma máquina servidor que detém um hardware com melhores condições de processamento, contendo este hardware 47 processadores (Intel Xeon) e 128 Gigabytes de RAM, possibilitando assim a utilização de todo o conjunto de dados na geração do modelo de aprendizado de máquina com tempo médio de 5 dias para o processamento de toda a base pelos algoritmos.

O resultado do treinamento foi um modelo de aprendizado de máquina com precisão de 76\% de acerto na identificação da natureza de uma conexão utilizando o algoritmo Random Forest.

A fim aplicar do modelo de aprendizado de maquina criado e testar o sistema IDS proposto como todo, o sistema foi submetido a diversas simulações de ataques em redes, onde todo o trafego entre uma maquina atacante e a maquina alvo se deu através de uma rede isolada entre as duas máquinas, sendo totalmente analisada em tempo real pelo sistema IDS.

Para isto, foram criada através de um software de virtualização (VirtualBox) os sistemas operacionais que simularam as máquinas atacante e alvo do ataque. A máquina Alvo (Linux Metasploitable - Ubuntu ) é uma distribuição Linux propositalmente projetada para ter falhas de segurança, tendo diversos vetores de exploração de ataques em rede.. A maquina Atacante (Linux Kali - Debian) é uma distribuição Linux com foco em facilitar processos de Pentest (Testes de Segurança).

Com o software VirtualBox foi criada uma rede (Host-Only) onde o trafego de pacotes dentro da rede fosse limitado somente entre as maquinas virtuais e a maquina hospedeira para maior exatidão possível do processo. Para a realização efetiva dos ataques, na maquina atacante foi utilizado o sistema Metasploit que é um framework para desenvolvimento e disponibilização de exploits (Explorações) com o intuito de facilitar testes de Penetração em processos de Auditoria e segurança de sistemas e teste de sistemas IDS/IPS.

Com o sistema IDS proposto já capturando os pacotes dentro da rede, foram executados diversos ataques que se encontram na rotina de módulos de exploração (scripts que exploram vulnerabilidades) do Metasploit Framework. A partir do momento que o processo de ataque começa, com o envio de pacotes TCP/UDP da maquina atacante para a máquina alvo, o sistema IDS realiza todo o processo visto neste documento, capturando pacote a pacote trafegando na rede, realizando engenharia reversa a fim de conectá-los logicamente para formar a própria conexão, analisando cada conexão para gerar as features, alimentando o modelo de aprendizado de maquina com as features, modelo este que compara a conexão capturada com suas regras internas geradas através do treinamento da base de ataques para finalmente realizar a predição da conexão, indicando de forma visual no terminal a natureza (Normal X Anomala) da conexão trafegada na rede.

Uma exploração geralmente requer várias interações da máquina atacante com a máquina alvo, logo, várias conexõessão geradas em um único processo de exploração. O objetivo de um NIDS é conseguir classificar pelo menos uma, das possíveis milhares de conexões envolvidas em um processo de exploração, possibilitando assim a identificação de uma exploração ou tentativa de ataque via rede.

Apesar de ter sido gerado através de uma base de dados relativamente antiga (DARPA99), o modelo proposto conseguiu realizar com sucesso a identificação de ataques recentes que se encontram no arsenal de módulos do Metasploit Framework, um framework recente amplamente utilizado por profissionais da área de segurança para comprometer a segurança de sistemas e explorar vulnerabilidades.

Os ataques, scripts ou módulos Metasploit utilizados para a simulação se encontram listados abaixo, mais detalhes sobre o funcionamento deste por ser encontrada nas referencias do Common Vulnerabilities and Exposures (CVE), um Banco de dados de vulnerabilidades de segurança da informação conhecidas publicamente.


\item auxiliary/scanner/http/ssl\_version ---  Poodle Attack Scanner\\ Mais Informações: https://cvedetails.com/cve/CVE-2014-3566/
\item exploit/multi/samba/usermap\_script --- Exploração do serviço SAMBA\\ Mais Informações: https://cvedetails.com/cve/CVE-2007-2447/
\item exploit/unix/ftp/vsftpd\_234\_backdoor --- Exploração de Servidor FTP
\item exploit/unix/irc/unreal\_ircd\_3281\_backdoor --- Exploração do sistema Daemon de IRC\\ Mais Informações: https://cvedetails.com/cve/CVE-2010-2075/
\item exploit/unix/misc/distcc\_exec --- Explora uma vulnerabilidade do distccd\\ Mais Informações: https://cvedetails.com/cve/CVE-2004-2687/
\item exploit/multi/http/php\_cgi\_arg\_injection --- Explora o PHP quando em modo CGI\\ Mais informações: https://cvedetails.com/cve/CVE-2012-1823/
\item exploit/linux/misc/drb\_remote\_codeexec ---Execução de codigo remota do dRuby
\item auxiliary/dos/http/slowloris --- Ataque de negação de serviços web\\ Mais informações:  https://cvedetails.com/cve/CVE-2007-6750/\\https://cvedetails.com/cve/CVE-2010-2227/
\item auxiliary/dos/http/metasploit\_httphandler\_dos --- Explora um servidor HTTP\\Mais informações:   https://cvedetails.com/cve/CVE-2019-5645/
\item auxiliary/dos/smb/smb\_loris --- Negação de serviço através alocação de memória por requisições SMB






<b> Especificações </b>
<b>Features Utilizadas para treinamento e Analise das conexões:</b><p>
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

<b>Dados capturados de cada pacote (tshark) para geração de features: </b><p>
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

<b>Ataques que compões o dataset:</b><p>
<ul>
<li> back: Denial of service attack against apache web server where a client requests a URL containing many backslashes.<br>
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
<li> ntinfoscan: A process by which the attacker scans an NT machine for information concerning its configuration, including ftp services, telnet:services, web services,  system account information, file systems and permissions.<br>
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
