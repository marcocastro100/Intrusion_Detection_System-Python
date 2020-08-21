<i>
<ol>
<li>Introdução</li>
<li>Database</li>
<li>ML Model Training</li>
<li>Project System</li>
<li>Files on project</li>
<li>Features</li>
<li>Pkg Data</li>
<li>Anomalies</li>
<li>Instalation</li>
</ol>
</i>

<b>1 Introdução </b><p>
Este projeto foi criado com o objetivo de implementação um Sistema de Detecção de Intrusão (IDS) em redes locais, utilizando para isto técnicas de aprendizado
de maquina, que possibilitam a geração de algoritmos capazes de distinguir estados de um conjunto de dados de acordo com a variação de valores das entradas
fornecidas, gerando assim modelos capazes de distinguir o estado (normal ou anômalo) de uma conexão.

O sistema desenvolvido visa dar ao usuário a possibilidade de analisar, em tempo real ou rotineiramente, se está havendo ou houve alguma tentativa de exploração ao sistema a partir da rede interna ou externa a qual o sistema está se comunicando. A efetividade dos resultados está diretamente relacionada à qualidade do dataset utilizado para treinamento do modelo de Machine Learning, além da qualidade das features que são geradas para analise do modelo proposto, dados estes que serão explicitados nesse documento.

<b>2 A Base de Dados utilizada </b><p>
Para se definir se um conjunto de dados provenientes de uma rede são ou não tentativas de ataque ao sistema via rede, se faz necessário um banco de dados contendo registros de conexões maliciosas e normais, afim de os dados serem computados pelo algoritmo de aprendizado de maquina e, através do cruzamento entre esses dados, a geração de um modelo contendo regras que definem, a partir de uma estrada de dados ainda não computada, se esses dados são provenientes de uma conexão anômala ou normal. Foi escolhida a utilização da base de dados de uma agência do departamento de defesa dos Estados Unidos, o dataset DARPA99, que contém um número muito grande de conexões anômalas, geradas a partir da simulação de ataques em redes de computadores em ambiente controlado.

O dataset DARPA99 conta com, além de outros atributos, estados e variáveis de todos os atributos da rede que foram gerados ao longo de 3 semanas de simulação. Os registros das conexões estão classificados entre conexões normais e anômalas, e estas são utilizadas para que o algoritmo possa aprender sob quais circunstancias uma conexão pode ser considerada normal ou um ataque de rede. 

A ideia é treinar um modelo que seja capaz de definir se uma conexão sendo recebida atualmente através rede do usuário se parece com conexões de ataque presentes na base de dados do DARPA99, indicando assim se uma conexão é ou não um ataque de rede.

<b>3 Treinamento do Modelo de Machine Learning</b><p>
O dataset contém arquivos de dump da rede que foi submetida a ataques de rede de variadas formas, esses arquivos se encontram na forma de dados brutos de TCPDUMP. Antes de se analisar os dados do dataset é necessário realizar a limpeza e o modelamento destes, tendo em vista que somente é possível identificar se uma conexão é ou não um ataque de rede através da conexão como um todo, e não através da analise de um pacote específico de uma conexão, então é necessário agrupar os milhares de pacotes em cada arquivo do dataset em conjuntos definidos de <b>streams</b>, sendo esta a conexão como um todo, podendo conter infinitos pacotes.

Com o tratamento de dados concluído, é necessário identificar quais variáveis da conexão são importantes para se identificar uma anomalia (ataque de rede), a logica da criação e implementação dessas features tiveram como base outro dataset derivado do darpa99, KDD99, e estas serão listadas em detalhes no decorrer deste documento.

Com as features já definidas e implementadas, é necessário realizar o preprocessamento dos dados coletados e finalmente gerar um modelo através dos algoritmos de Aprendizado de Maquina. Foi implementado um algoritmo que roda os principais algoritmos ML, e realiza a escolha do modelo gerado pelo algoritmo que teve maior Pontuação (Score) analisando os dados do dataset, o Score de cada algoritmo pode variar de dataset em dataset, por isso a necessidade de escolha dinâmica.

Com o modelo de ML treinado, este já pode predizer, analisando os dados de uma conexão de rede, se esta tem características que indicam ser uma conexão normal ou um ataque de rede, assim o modelo é armazenado para ser usado pelo algoritmo que verifica os dados da rede do usuário do sistema.

<b>4 Funcionamento do Sistema Desenvolvido</b><p>
O Script inicia uma chamada para o software livre TCPDUMP, responsável pela captura de pacotes em toda a rede, de forma contínua, recebendo assim todas as informações sobre os pacotes. Com os pacotes da rede sendo capturados, é necessário realizar a filtragem de informação sobre o pacote e sua payload, logo é utilizado o software livre TSHARK; Com este, é possível realizar a filtragem de conteúdo relacionado ao pacote que se deseja armazenar, realizando assim a filtragem de dados relevantes e a conversão de dados brutos do sniffer de rede em formato PCAP para dados utilizáveis em formato CSV. Os dados relevantes foram definidos de acordo com a necessidade de informações necessárias para se criar e manipular as features. Uma lista dos dados e features é encontrada abaixo no documento.

A informação estruturada recebida é então enviada ao script python que realiza uma série de tratamentos com os dados com base nas informações do pacote, como a identificação do protocolo, o a porta de serviço usada e o mapeamento de stream (conexão), esta sendo a indicação de a qual conjunto de pacotes este pacote pertence, o que é imprescindível para o gerenciamento lógico dos pacotes e a identificação e padrões anômalos na rede. Após o tratamento dos dados do pacote, a informação deste é gravada no arquivo de sua stream correspondente.

Quando o termino de uma conexão é identificada (através de flags de termino de comunicação de pacotes TCP, ou excedimento de tempo limite sem resposta), os pacotes referentes a essa conexão são enviados ao script que realiza o modelamento dos dados dos vários pacotes de rede a fim de se obter features referentes à conexão (stream) como um todo, sendo assim possível extrair dados temporais e de interação entre os pacotes. As novas informações extraídas da conexão são então preprocessadas e encaminhadas para serem analisadas pelo modelo treinado com a base de dados. Este por sua vez tenta encontrar padrões de ataques de rede na conexão individual sendo analisada. O resultado então é exibido pela interface do sistema.

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
-1 Duration: Length of time duration of the connection<br>
-2 Protocoltype: Protocol used in the connection<br> 
-3 Service: Destination network service used<br> 
-4 Flag: Status of the connection – Normal or Error <br>
-5 Srcbytes: Number of data bytes transferred from source to destination in single connection<br>
-6 Dstbytes: Number of data bytes transferred from destination to source in single connection<br> 
-7 Land: if source and destination IP addresses and port numbers are equal then, this variable takes value 1 else 0 <br>
-8 Wrongfragment: Total number of wrong fragments in this connection<br>
-9 Urgent: Number of urgent packets in this connection. Urgent packets are packets with the urgent bit Activated<br>
-10-Srvcount: Number of connections to the same service (port number) as the current connection in th e past two seconds <br>

<b>7 Dados capturados de cada pacote (tshark) para geração de features: </b><p>
Layer 1:<br>
---frame.time #hora e data de chegada do pacote<br>
---frame.protocols #protocolos presentes no pacote<br>
---frame.cap_len #tamanho total do pacote<br>
Layer 2:<br>
---eth.dst #domain destino<br>
---eth.src #domain fonte<br>
Layer 3:<br>
---ip.src #ip fonte<br>
---ip.dst #ip destino<br>
---ip.proto #protocolo camada 4 (tcp,udp,icmp)<br>
---ip.flags #relatorio pacote *<br>
Layer 4:<br>
---tcp.flags #relatorio pacote<br>
---tcp.srcport #porta source<br>
---tcp.dstport #porta destino (service da conexão)<br>
---tcp.len #tamanho da payload tcp<br>
---tcp.urgent_pointer #flag URG<br>
---tcp.window_size_value #tamanho do buffer<br>
---tcp.sequence_number #Sequencia de pacotes<br>
---udp.srcport<br>
---udp.dstport<br>
---udp.length<br>

<b>8 Ataques que compões o dataset:</b><p>

1 back: Denial of service attack against apache webserver where a client requests a URL containing many backslashes.<br>
2 crashiis: A single, malformed http request causes the webserver to crash.<br>
3 dict: Guess passwords for a valid user using simple variants of the account name over a telnet connection. <br>
4 eject: Buffer overflow using eject program on Solaris. Leads to a user->root transition if successful.<br> 
5 ffb: Buffer overflow using the ffbconfig UNIX system command leads to root shell<br>
6 format: Buffer overflow using the fdformat UNIX system command leads to root shell<br> 
7 ftp: write-Remote FTP user creates .rhost file in world writable anonymous FTP directory and obtains local login. <br>
8 guest: Try to guess password via telnet for guest account.<br> 
9 httptunnel: There are two phases to this attack:<br> 
11 Setup: a web "client" is setup on the machine being attacked, which is configured, perhaps via crontab, to periodically make requests of a "server" running on a non-privilaeged port on the attacking machine.<br>
12 Action: When the periodic requests are recieved, the server encapsulates commands to be run by the "client" in a cookie.. things like "cat /etc/passwd".. etc..<br>
13 imap: Remote buffer overflow using imap port leads to root shell <br>
14 ipsweep: Surveillance sweep performing either a port sweep or ping on multiple host addresses. <br>
15 land: Denial of service where a remote host is sent a UDP packet with the same source and destination <br>
16 loadmodule: Non-stealthy loadmodule attack which resets IFS for a normal user and creates a root shell<br> 
17 mailbomb: A Denial of Service attack where we send the mailserver many large messages for delivery in order to slow it down, perhaps effectively halting normal operation.<br>
18 multihop: Multi-day scenario in which a user first breaks into one machine<br> 
19 neptune: Syn flood denial of service on one or more ports.<br> 
20 nmap: Network mapping using the nmap tool. Mode of exploring network will vary—options include SYN <br>
21 ntinfoscan: A process by which the attacker scans an NT machine for information concerning its configuration, including ftp services, telnet:services, web services,  system account information, file systems and permissions.<br>
22 perlmagic: Perl attack which sets the user id to root in a perl script and creates a root shell <br>
23 phf: Exploitable CGI script which allows a client to execute arbitrary commands on a machine with a misconfigured web server. <br>
24 pod: Denial of service ping of death<br> 
25 portsweep: Surveillance sweep through many ports to determine which services are supported on a single host. <br>
26 ps: Ps takes advantage of a racecondition in the ps command in Sol. 2.5, allowing a user to gain root access.<br>
27 rootkit: Multi-day scenario where a user installs one or more components of a rootkit<br> 
28 satan: Network probing tool which looks for well-known weaknesses. Operates at three different levels. Level 0 is light <br>
29 secret<br>	 
30 smurf: Denial of service icmp echo reply flood. <br>
31 spy-Multi: day scenario in which a user breaks into a machine with the purpose of finding important information where the user tries to avoid detection. Uses several different exploit methods to gain access. <br>
32 syslog: Denial of service for the syslog service connects to port 514 with unresolvable source ip.<br>
33 teardrop: Denial of service where mis-fragmented UDP packets cause some systems to reboot.<br> 
34 warez: User logs into anonymous FTP site and creates a hidden directory.<br> 
35 warezclient: Users downloading illegal software which was previously posted via anonymous FTP by the warezmaster. <br>
36 warezmaster: Anonymous FTP upload of Warez (usually illegal copies of copywrited software) onto FTP server.<br>

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
