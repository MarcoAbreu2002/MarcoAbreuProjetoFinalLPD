# Projeto de Segurança Informática

Este projeto consiste na criação de uma aplicação de segurança informática utilizando uma linguagem de programação dinâmica, preferencialmente Python. A aplicação engloba as seguintes funcionalidades:

- **Detecção e listagem das portas de rede disponíveis em máquinas remotas.**
- **Implementação de um ataque de UDP Flood (DoS) para um IP remoto**, possivelmente utilizando a biblioteca Scapy.
- **Implementação de um ataque SYN Flood (Pacotes TCP SYN) para um serviço à escolha do estudante**, como HTTP, SMTP, etc., possivelmente utilizando a biblioteca Scapy.
- **Análise e processamento de ficheiros de registo (logs) de serviços como HTTP, SSH, entre outros**, listando a origem dos acessos ou tentativas de acesso inválidas. É valorizado o uso de um servidor syslog.
- **Desenvolvimento de um serviço básico de mensagens seguras entre cliente e servidor**, com funcionalidades avançadas como mensagens entre múltiplos utilizadores, arquivamento de mensagens, cópia de segurança/exportação de mensagens, etc.
- **Implementação de um sistema de port knocking do cliente para abrir uma ligação de login SSH numa máquina Linux**, incluindo configuração de firewall (iptables, ipchains).

## Instalação

Para começar, clone o repositório deste projeto no GitHub, disponível em:

[CLONE GIT](https://github.com/MarcoAbreu2002/MarcoAbreuProjetoFinalLPD)

Depois, execute o arquivo de requisitos para instalar todas as dependências necessárias para executar este programa, o que pode ser feito com o seguinte comando:

```bash
pip install -r requirements.txt
```

## Utilização

Para começar, navegue até à diretoria do programa. Agora, para instalar todas as dependências necessárias à utilização deste programa deverá seguir os seguintes passos:

**utilizadores de Linux:**

```bash
chmod +x requirements.sh
./requirements.sh
```
Para **utilizadores de Windows**, execute o seguinte ficheiro:

```bash
requirements_windows.bat
```

Certifique-se que possui permissões de administrador e que está a utilizar a versão **mais recente do Python3**.

Por fim, apenas necessita de executar o programa principal, da seguinte forma:

```bash
python3 main.py
```

Após a execução do programa, será apresentado o menu principal, onde poderá escolher entre diversas opções disponíveis.

### Detecção e Listagem de Portas Disponíveis

Para utilizar a funcionalidade de detecção e listagem de portas disponíveis, selecione a opção "A" e siga as instruções fornecidas. 
Será solicitado a escolher o tipo de dispositivo a ser analisado, "D" para domínio e "I" para endereço IP. Em seguida, insira o IP correspondente à máquina em análise, seguido das portas a serem analisadas (porta inicial e porta final). 
Por fim, será questionado sobre o tempo despendido para analisar cada porta. Um maior tempo pode indicar uma análise mais precisa, onde "H" representa um tempo maior e "L" uma análise mais rápida.

Segue abaixo uma demonstração da sua utilização.

```bash
************Aplicação de Segurança Informática**************


               A: Portos de Rede Disponíveis
               B: UDP flood (DoS)
               C: SYN flood (TCP SYN)
               D: Encrypted Chat
               Q: Quit

               Escolha a opção desejada: A
Running available-ports.py...
************************************************************
        Port scanner 
 
        D - Domain Name | I - IP Address        I
         Enter the IP Address to scan: 192.168.1.10
         Enter the start port number    1
         Enter the last port number     99999
Range not Ok
Setting last port 65535
Low connectivity = L | High connectivity = H    H

Scanning in progress...  192.168.1.10
************************************************************
Port Open:-->    9200 -- Elasticsearch—default Elasticsearch port -  Unofficial TCP
Port Open:-->    9000 -- QBittorrent embedded torrent tracker default port-  Unofficial TCP
Port Open:-->    4444 -- I2P HTTP/S proxy -  Unofficial TCP
Port Open:-->    27017 -- MongoDB daemon process (mongod) and routing service (mongos)- No UDP Unofficial TCP
Port Open:-->    9300 -- IBM Cognos BI[citation needed] -  Unofficial TCP
Port Open:-->    12201 -- Graylog Extended Log Format (GELF)[importance?] -  Unofficial TCP and UDP
Port Open:-->    1515 -- No Known service for port 1515
Exiting Main Thread
Scanning complete in  0:00:07.054941
```


### Funcionalidade de UDP Flood

A funcionalidade de UDP flood é intuitiva de usar. Basta inserir o endereço IP alvo, a porta alvo, o número de pacotes a enviar e a mensagem desejada.

Abaixo encontra-se um exemplo de utilização.

```bash
************Aplicação de Segurança Informática**************


               A: Portos de Rede Disponíveis
               B: UDP flood (DoS)
               C: SYN flood (TCP SYN)
               D: Encrypted Chat
               Q: Quit

               Escolha a opção desejada: B
Running udp_flood.py...
Enter the target IP address: 192.168.1.10
Enter the target port: 80
Enter the number of packets to send: 50
Enter a message to send to the target: Hey
```
### Funcionalidade de SYN flood

A utilização do SYN flood é semelhante à anterior, apenas é necessário introduzir o IP alvo e o número de pacotes que cada thread poderá enviar. Uma possível utilização seria:
```bash
************Aplicação de Segurança Informática**************


               A: Portos de Rede Disponíveis
               B: UDP flood (DoS)
               C: SYN flood (TCP SYN)
               D: Encrypted Chat
               Q: Quit

               Escolha a opção desejada: C
Running synflood.py...
Enter the target IP: 192.168.1.10
Enter the number of packets to send per thread: 100
Enter the number of threads: 5
Thread sent 100 packets successfully.
Sent 500 packets successfully.
```

###  Serviço básico de mensagens seguras entre cliente e servidor
Esta funcionalidade contém diversas opções. Na sua utilização é imperativo a inicialização do servidor antes da inicialização do cliente, isto deve-se ao facto de ser o servidor que recebe as mensagens e as conexões dos clientes.
Ao iniciar o servidor, opção 1 do submenu, será requisitada uma password que será utilizada para encriptar a chave privada no servidor para que esta possa ser utilizada novamente:

![image](https://github.com/MarcoAbreu2002/myrepo/assets/88538173/6a948e09-4bab-448b-a0b6-5379727f4b78)

A incialização de um novo cliente, opção 2 do submenu, requer a introdução do nome e de uma password, que também é utilizada para encriptar a chave privada. O momento de autenticação do utilizador seria da seguinte forma: 

![image](https://github.com/MarcoAbreu2002/myrepo/assets/88538173/204983c9-ff0c-4a78-89d6-3583d20c88af)

Feita a conexão, é possível efetuar as seguintes funcionalidades:
- **Envio de Mensagens em modo broadcast**, para tal basta escrever a mensagem e pressionar Enter; 
- **Leitura de todas as mensagens enviadas** até ao momento do utilizador autenticado, utilizando a palavra reservada **/read**;
- **Download de todas as mensagens enviadas** até ao momento do utilizador autenticado, utilizando a palavra reservada **/download**, o ficheiro é criado na mesma diretoria do programa;
- **Desligar**, utilizando a palavra reservada **/exit**

Outra opção disponível nesta funcionalidade, é a consulta de todas as mensagens já trocadas naquele servidor, para tal poderá escolher a opçãp 3 do submenu e inserir a chave de autenticação do utilizador.

###  Sistema de port knocking para abertura de conexão ssh e L2tp/IPSec
Antes da utilização deste script, a firewall da máquina alvo terá de ser configurada para abertura da porta correta após uma sequência de knocks específica. A título de exemplo, é apresentado uma possível configuração:
```bash
#! /bin/bash
### Limpar regras existentes e cadeias personalizadas
iptables -X
iptables -F
iptables -X INTO-P2
iptables -X INTO-P3
iptables -X INTO-P4
# Aceitar conexoes estabelecidas e relacionadas para permitir o
trafego de retorno
iptables -A INPUT -p tcp --dport 22 -m state --state ESTABLISHED -j
ACCEPT
iptables -A INPUT -p tcp --dport 22 -m state --state RELATED -j
ACCEPT
# Criar novas cadeias para controlar o fluxo do programa
iptables -N INTO-P2
iptables -N INTO-P3
iptables -N INTO-P4
# Regras para mover as conexoes de um estagio para outro,acompanhando-as com nomes
# P1 - P2 - P3 - P4
iptables -A INTO-P2 -m recent --name P1 --remove
iptables -A INTO-P2 -m recent --name P2 --set
iptables -A INTO-P2 -j LOG --log-prefix ”INTO P2: ”
iptables -A INTO-P3 -m recent --name P2 --remove
iptables -A INTO-P3 -m recent --name P3 --set
iptables -A INTO-P3 -j LOG --log-prefix ”INTO P3: ”
iptables -A INTO-P4 -m recent --name P3 --remove
iptables -A INTO-P4 -m recent --name P4 --set
iptables -A INTO-P4 -j LOG --log-prefix ”INTO P4: ”
# Atualizar a ultima vez que a conexao P1 foi vista
iptables -A INPUT -m recent --update --name P1
# Definir a sequencia de portas que devem ser acessadas em uma determinada ordem
# Para garantir o acesso a porta SSH
# Se a sequencia for quebrada, as regras de acesso serao rejeitadas
iptables -A INPUT -p tcp --dport 6666 -m recent --name P1 --set
iptables -A INPUT -p tcp --dport 7777 -m recent --rcheck --seconds
10 --name P1 -j INTO-P2
iptables -A INPUT -p tcp --dport 8888 -m recent --rcheck --seconds
10 --name P2 -j INTO-P3
iptables -A INPUT -p tcp --dport 9999 -m recent --rcheck --seconds
10 --name P3 -j INTO-P4
# Se a sequencia estiver completa (P1 -¿ P2 -¿ P3 -¿ P4), a porta SSH sera aberta
iptables -A INPUT -p tcp --dport 22 -m recent --rcheck --seconds 10 --name P4 -j ACCEPT
# Open L2TP/IPSec port (1701) if the sequence is respected
iptables -A INPUT -p udp --dport 1701 -m recent --rcheck --seconds 10 --name P4 -j ACCEPT
# Regra padrao para rejeitar novas conexoes SSH se a sequencia nao for respeitada
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j DROP
```
Adicionalmente, para a criação da ligação L2TP/IPsec, terá de ser configurada uma VPN na máquina alvo, a utilização da biblioteca open-source strongswan poderá facilitar a implementação.
Para a utilização deste script deverá ser introduzido o IP da máquina alvo e sequência de portas separadas por vírgulas, que serão tocadas durante o processo. Depois também será necessário introduzir as credencias que validam o aceeso à máquina por ssh e as credencias de acesso à vpn.
Um exmeplo de utilização da conexão por ssh após o door knocking pode ser:

![kck](https://github.com/MarcoAbreu2002/myrepo/assets/88538173/44225908-74a8-4c82-b993-42af981640c9)
