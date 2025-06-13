
   <h1>Dark Hacker Pro v6.0</h1>
    <p>Bem-vindo ao <strong>Dark Hacker Pro v6.0</strong>, uma ferramenta de escaneamento de rede desenvolvida para monitorar dispositivos em uma rede local, detectar vulnerabilidades e alertar sobre possíveis intrusões. Este projeto utiliza <strong>Python</strong> com bibliotecas como <strong>Scapy, Nmap e SQLAlchemy</strong> para fornecer uma interface gráfica interativa.</p>

   <div class="section">
        <h2>Descrição</h2>
        <ul>
            <li>Escanear redes locais para identificar dispositivos ativos.</li>
            <li>Coletar informações como IP, MAC, portas abertas, sistema operacional e vulnerabilidades.</li>
            <li>Detectar alertas de segurança, como ARP Spoofing.</li>
            <li>Exportar dados em formatos CSV, Excel e JSON.</li>
            <li>Monitorar estatísticas em tempo real via interface gráfica.</li>
        </ul>
    </div>

   <div class="section">
        <h2>Pré-requisitos</h2>
        <ul>
            <li>Python 3.11 ou superior</li>
            <li>Sistema operacional com suporte a ferramentas de rede (recomendado: Linux, como Kali ou Ubuntu)</li>
            <li>Permissões de root ou sudo (necessárias para Nmap e captura de pacotes)</li>
        </ul>
    </div>

   <div class="section">
        <h2>Instalação</h2>
        <h3>1. Clone o Repositório</h3>
        <pre><code>git clone https://github.com/sucloudflare/Dark-Hacker-Pro.git
cd Dark-Hacker-Pro</code></pre>

   <h3>2. Crie um Ambiente Virtual</h3>
        <pre><code>python3 -m venv venv
source venv/bin/activate</code></pre>

   <h3>3. Instale as Dependências</h3>
        <p><strong>Nota para Kali Linux:</strong> Devido ao ambiente "externally managed", use o flag `--break-system-packages`:</p>
        <pre><code>pip install --break-system-packages -r requirements.txt</code></pre>
        <p>Se preferir evitar riscos, use <code>pipx install -e .</code> (instale <code>pipx</code> com <code>sudo apt install pipx</code>).</p>

   <h3>4. Instale Ferramentas Externas</h3>
        <p><strong>Ubuntu/Debian:</strong></p>
        <pre><code>sudo apt update
sudo apt install nmap python3-tk</code></pre>
        <p><strong>Kali Linux:</strong></p>
        <pre><code>sudo apt install python3-tk</code></pre>
        <p><strong>Dependências Python Adicionais (se necessário):</strong></p>
        <pre><code>pip install --break-system-packages python-nmap notify2 dbus-python && pip install --break-system-packages ttkthemes && pip install --break-system-packages ttkthemes scapy psutil xlsxwriter matplotlib sqlalchemy requests python-nmap notify2 dbus-python && </code></pre>

   <h3>5. Configure Permissões</h3>
        <pre><code>sudo ./venv/bin/python app_dark_hackerpro.py</code> && pip install --break-system-packages ttkthemes scapy psutil xlsxwriter matplotlib sqlalchemy requests python-nmap notify2 dbus-python
source venv/bin/activate
sudo ./venv/bin/python app_dark_hackerpro.py
sudo apt autoremove  # Opcional</pre>
    </div>

   <div class="section">
        <h2>Uso</h2>
        <h3>Iniciar o Aplicativo</h3>
        <pre><code>source venv/bin/activate
sudo ./venv/bin/python app_dark_hackerpro.py</code></pre>

   <h3>Interface Gráfica</h3>
        <ul>
            <li><strong>Dispositivos:</strong> Lista os dispositivos escaneados com detalhes.</li>
            <li><strong>Configurações:</strong> Ajuste opções como modo silencioso.</li>
            <li><strong>Logs:</strong> Exibe logs de execução.</li>
            <li><strong>Estatísticas:</strong> Mostra gráficos de dispositivos ativos/inativos.</li>
        </ul>

   <h3>Comandos Principais</h3>
        <ul>
            <li><strong>Escanear Agora:</strong> Inicia escaneamento manual.</li>
            <li><strong>Iniciar Automático:</strong> Escaneamento automático a cada 5 min.</li>
            <li><strong>Pausar:</strong> Pausa/resume o escaneamento.</li>
            <li><strong>Exportar:</strong> Salva dados em CSV, Excel ou JSON.</li>
        </ul>
        <h3>Atalhos</h3>
        <ul>
            <li>Ctrl + Q: Sair</li>
            <li>Ctrl + S: Escanear agora</li>
            <li>Ctrl + P: Pausar</li>
            <li>Ctrl + E: Exportar CSV</li>
            <li>Ctrl + X: Exportar Excel</li>
            <li>Ctrl + J: Exportar JSON</li>
        </ul>
    </div>

   <div class="section">
        <h2>Configurações</h2>
        <ul>
            <li>Escolha o IP inicial de escaneamento (ex.: 192.168.10.100).</li>
            <li>Ative modo silencioso para desativar notificações.</li>
        </ul>
    </div>

   <div class="section">
        <h2>Contribuições</h2>
        <p>Sinta-se à vontade para contribuir! Envie pull requests ou abra issues para sugestões e correções.</p>
    </div>

   <div class="section">
        <h2>Licença</h2>
        <p>Este projeto está sob a <strong>MIT License</strong> - veja o arquivo LICENSE para detalhes.</p>
    </div>

   <div class="section">
        <h2>Agradecimentos</h2>
        <ul>
            <li>Inspirado em ferramentas como Nmap e Wireshark.</li>
            <li>Dependências baseadas em Scapy, SQLAlchemy e outras.</li>
        </ul>
    </div>

   <div class="section">
        <h2>Solução para Problemas - Se Travar na Análise de TCP</h2>
        <h3>Possíveis Causas</h3>
        <ul>
            <li><strong>Dispositivo Ativo com Resposta Lenta:</strong> O dispositivo (ex.: 192.168.10.100) pode estar ativo, mas respondendo lentamente devido a alta carga, firewall ativo ou configuração de portas que exige mais tempo para análise pelo Nmap.</li>
            <li><strong>Firewall ou Filtragem:</strong> Um firewall no dispositivo ou na rede pode estar bloqueando ou retardando as requisições, causando timeouts.</li>
            <li><strong>Portas em Estado Intermediário:</strong> Portas "filtered" ou "closed" podem exigir mais tentativas, aumentando o tempo de escaneamento.</li>
            <li><strong>Problema de Conexão:</strong> Instabilidade, latência ou perda de pacotes pode afetar apenas esse IP.</li>
            <li><strong>Configuração do Nmap:</strong> A varredura padrão (1-1024) pode não ser otimizada, causando atrasos.</li>
        </ul>
        <h3>Solução</h3>
        <ul>
            <li>Ajuste a função <code>get_tcp_info</code> no código para usar opções mais rápidas: <code>nm.scan(ip, '1-100', arguments='-T4 --max-retries 2')</code>.</li>
            <li>Teste manualmente com: <code>sudo nmap -p 1-1024 -T4 192.168.10.100</code>.</li>
            <li>Reinicie o escaneamento após ajustar.</li>
        </ul>
    </div>

   <hr>
    <p class="small">Última atualização: 13/06/2025 - 20:30 (-03)</p>
