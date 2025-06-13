import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import ttkthemes
import datetime
import os
import csv
import json
import asyncio
from ipaddress import ip_network
import subprocess
import threading
import psutil
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import xlsxwriter
import notify2
from scapy.all import ARP, Ether, srp, sniff
import nmap
from sqlalchemy.orm import declarative_base
from sqlalchemy import create_engine, Column, Integer, String, Text
from sqlalchemy.orm import sessionmaker

# --- Configuração do Banco de Dados ---
Base = declarative_base()

class Device(Base):
    __tablename__ = 'devices'
    id = Column(Integer, primary_key=True)
    ip = Column(String)
    ping = Column(String)
    mac = Column(String)
    scan_time = Column(String)
    traffic = Column(Integer)
    tcp_info = Column(Text)
    ipv4_info = Column(Text)
    ipv6_info = Column(Text)
    dns_info = Column(Text)
    proxy_vpn_info = Column(Text)
    os_info = Column(String)
    hardware_info = Column(String)
    browser_info = Column(String)
    location = Column(String)
    vulnerabilities = Column(Text)
    alerts = Column(Text)
    device_type = Column(String)
    uptime = Column(String)
    hostname = Column(String)
    network_speed = Column(String)
    firewall_status = Column(String)
    antivirus_status = Column(String)
    user_count = Column(Integer)
    process_count = Column(Integer)
    disk_usage = Column(String)
    memory_usage = Column(String)
    cpu_usage = Column(String)

engine = create_engine('sqlite:///devices.db')
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

# --- Funções utilitárias ---
def log_event(msg):
    with open("network_scanner.log", "a", encoding="utf-8") as f:
        f.write(f"{datetime.datetime.now().isoformat()} - {msg}\n")

def get_subnets():
    return ["192.168.10.0/24", "192.168.1.0/24"]

async def scan_device(ip, semaphore, app, start_ip, limit=24):
    async with semaphore:
        current_ip_int = int(str(ip).split('.')[-1])
        if current_ip_int < start_ip or app.scanned_count.get() >= limit:
            app.after(0, lambda: app.update_progress(str(ip), None, "Ignorando IP fora do intervalo"))
            return None
        
        try:
            app.after(0, lambda: app.update_scan_progress(f"Processando {str(ip)} - Iniciando ping..."))
            ping = ping_device(str(ip))
            device = {
                "ip": str(ip), "ping": ping, "mac": "N/A", "scan_time": datetime.datetime.now().isoformat(),
                "traffic": estimate_traffic(str(ip)), "tcp_info": "", "ipv4_info": "", "ipv6_info": "",
                "dns_info": "", "proxy_vpn_info": "", "os_info": "", "hardware_info": "",
                "browser_info": "", "location": "", "vulnerabilities": "", "alerts": "",
                "device_type": "", "uptime": "", "hostname": "", "network_speed": "",
                "firewall_status": "", "antivirus_status": "", "user_count": 0,
                "process_count": 0, "disk_usage": "", "memory_usage": "", "cpu_usage": ""
            }
            
            if ping == "Ativo":
                app.after(0, lambda: app.update_scan_progress(f"{str(ip)} - Obtendo MAC..."))
                device["mac"] = get_mac_address(str(ip))
                
                app.after(0, lambda: app.update_scan_progress(f"{str(ip)} - Escaneando portas TCP..."))
                device["tcp_info"] = get_tcp_info(str(ip))
                
                app.after(0, lambda: app.update_scan_progress(f"{str(ip)} - Coletando info IPv4..."))
                device["ipv4_info"] = get_ipv4_info(str(ip))
                device["device_type"], device["uptime"], device["hostname"] = get_device_details(str(ip))
                device["network_speed"] = get_network_speed()
                device["firewall_status"] = get_firewall_status()
                device["antivirus_status"] = get_antivirus_status()
                
                app.after(0, lambda: app.update_scan_progress(f"{str(ip)} - Coletando info IPv6..."))
                device["ipv6_info"] = get_ipv6_info(str(ip))
                
                app.after(0, lambda: app.update_scan_progress(f"{str(ip)} - Obtendo info DNS..."))
                device["dns_info"] = get_dns_info(str(ip))
                
                app.after(0, lambda: app.update_scan_progress(f"{str(ip)} - Verificando proxy/VPN..."))
                device["proxy_vpn_info"] = get_proxy_vpn_info(str(ip))
                
                app.after(0, lambda: app.update_scan_progress(f"{str(ip)} - Detectando OS..."))
                device["os_info"] = get_os_info(str(ip))
                
                app.after(0, lambda: app.update_scan_progress(f"{str(ip)} - Coletando info de hardware..."))
                device["hardware_info"] = get_hardware_info()
                device["user_count"], device["process_count"], device["disk_usage"], device["memory_usage"], device["cpu_usage"] = get_system_metrics()
                
                app.after(0, lambda: app.update_scan_progress(f"{str(ip)} - Verificando vulnerabilidades..."))
                device["vulnerabilities"] = get_vulnerabilities(str(ip))
                
                app.after(0, lambda: app.update_scan_progress(f"{str(ip)} - Checando alertas..."))
                device["alerts"] = get_alerts(str(ip))
            
            app.after(0, lambda: app.update_progress(str(ip), device, f"Concluído processamento de {str(ip)}"))
            app.scanned_count.set(app.scanned_count.get() + 1)
        except Exception as e:
            app.after(0, lambda err=e: app.update_scan_progress(f"Erro em {str(ip)}: {str(err)}"))
            log_event(f"Erro em {str(ip)}: {e}")
        return device if ping else None

async def scan_network_with_async(subnet, app, start_ip, limit=24):
    devices = []
    try:
        total_hosts = min(limit, sum(1 for _ in ip_network(subnet, strict=False).hosts()) - start_ip + 1)
        app.after(0, lambda: app.progress_var.set(0))
        app.after(0, lambda: app.status_bar.config(text=f"Escaneando {subnet} a partir de .{start_ip} ({total_hosts} IPs)"))
        app.scanned_count.set(0)
        semaphore = asyncio.Semaphore(20)
        tasks = [scan_device(str(ip), semaphore, app, start_ip, limit) for ip in ip_network(subnet, strict=False).hosts() if int(str(ip).split('.')[-1]) >= start_ip]
        results = await asyncio.gather(*tasks)
        devices = [r for r in results if r is not None]
        log_event(f"Escaneamento em {subnet} concluído a partir de .{start_ip}. Dispositivos: {len(devices)}")
    except Exception as e:
        app.after(0, lambda err=e: app.update_scan_progress(f"Erro geral: {str(err)}"))
        log_event(f"Erro em {subnet}: {e}")
    app.after(0, lambda: app.status_bar.config(text=f"Escaneamento concluído às {datetime.datetime.now().strftime('%H:%M:%S')}"))
    return devices

def ping_device(ip):
    try:
        cmd = ['ping', '-c', '1', '-W', '1', ip]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return "Ativo" if result.returncode == 0 else "Inativo"
    except Exception as e:
        log_event(f"Erro no ping de {ip}: {e}")
        return None

def get_mac_address(ip):
    try:
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=1, verbose=False)[0]
        return result[0][1].hwsrc if result else "N/A"
    except Exception:
        return "N/A"

def estimate_traffic(ip):
    return psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv if ping_device(ip) == "Ativo" else 0

def get_tcp_info(ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, '1-1024')
        tcp_ports = [f"{port}/{nm[ip]['tcp'][port]['state']}" for port in nm[ip]['tcp'] if nm[ip]['tcp'][port]['state'] == 'open']
        return f"TCP Ports: {', '.join(tcp_ports)}" if tcp_ports else "Nenhum porto TCP aberto"
    except Exception as e:
        log_event(f"Erro TCP scan para {ip}: {e}")
        return "Erro na varredura TCP"

def get_ipv4_info(ip):
    try:
        gateway = subprocess.check_output(['ip', 'route'], text=True).split()[2]
        return f"IPv4: {ip}, Subnet: 255.255.255.0, Gateway: {gateway}"
    except Exception:
        return f"IPv4: {ip}, Subnet: 255.255.255.0, Gateway: Desconhecido"

def get_ipv6_info(ip):
    try:
        return f"IPv6: {subprocess.check_output(['ip', '-6', 'addr'], text=True).split()[1]}"
    except Exception:
        return "IPv6: Não detectado"

def get_dns_info(ip):
    try:
        return f"DNS: {subprocess.check_output(['cat', '/etc/resolv.conf'], text=True).split()[1]}"
    except Exception:
        return "DNS: Não detectado"

def get_proxy_vpn_info(ip):
    try:
        # Simples verificação baseada em roteamento (requer análise mais avançada para precisão)
        routes = subprocess.check_output(['ip', 'route'], text=True).splitlines()
        return "Proxy/VPN: Detectado" if any("tun" in route or "vpn" in route for route in routes) else "Proxy/VPN: Não detectado"
    except Exception:
        return "Proxy/VPN: Erro"

def get_os_info(ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, '1-1024', arguments='-O')
        return nm[ip].get('osmatch', [{'name': 'Desconhecido'}])[0]['name']
    except Exception:
        return "OS: Desconhecido"

def get_hardware_info():
    try:
        return f"Hardware: {psutil.cpu_count()} CPUs, {psutil.virtual_memory().total / 1024 / 1024:.2f} MB RAM"
    except Exception:
        return "Hardware: Desconhecido"

def get_browser_info():
    try:
        # Requer análise de tráfego HTTP para detecção real (simplificado aqui)
        return "Browser: Não detectado"  # Expanda com Sniffing HTTP se necessário
    except Exception:
        return "Browser: Erro"

def get_location(ip):
    try:
        # Usa API externa (exemplo genérico, substitua por uma API real como ipinfo.io)
        import requests
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        return f"Location: {response.get('city', 'Desconhecido')}, {response.get('country', 'Desconhecido')}"
    except Exception:
        return "Location: Desconhecido"

def get_vulnerabilities(ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, '1-1024', arguments='-sV --script vuln')
        vulns = nm[ip].get('script', {})
        return f"Vulnerabilidades: {'; '.join(vulns.keys())}" if vulns else "Nenhuma vulnerabilidade detectada"
    except Exception as e:
        log_event(f"Erro na detecção de vulnerabilidades para {ip}: {e}")
        return "Erro na detecção de vulnerabilidades"

def get_alerts(ip):
    try:
        # Detecção básica de ARP spoofing ou tráfego anormal
        def arp_monitor_callback(pkt):
            if ARP in pkt and pkt[ARP].op in (1, 2):  # ARP Request ou Reply
                if pkt[ARP].psrc != ip and pkt[ARP].pdst == ip:
                    return f"Alerta: Possível ARP Spoofing de {pkt[ARP].psrc}"
            return None

        packets = sniff(count=50, filter=f"host {ip}", timeout=5, prn=arp_monitor_callback)
        alerts = [alert for alert in packets if alert]
        return "; ".join(alerts) if alerts else "Nenhum alerta detectado"
    except Exception as e:
        log_event(f"Erro na detecção de alertas para {ip}: {e}")
        return "Erro na detecção de alertas"

def get_device_details(ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, '1-1024', arguments='-O')
        osmatch = nm[ip].get('osmatch', [{'name': 'Desconhecido'}])[0]
        return (nm[ip].get('vendor', {}).get(ip, 'Desconhecido'), "Uptime: Não disponível", f"Hostname: {osmatch.get('name', 'Desconhecido')}")
    except Exception:
        return "Desconhecido", "Desconhecido", "Desconhecido"

def get_network_speed():
    try:
        # Estimativa simples baseada em testes de ping
        start_time = time.time()
        subprocess.run(['ping', '-c', '10', '8.8.8.8'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        end_time = time.time()
        return f"{(10 / (end_time - start_time)):.2f} Mbps (estimado)"
    except Exception:
        return "Desconhecido"

def get_firewall_status():
    try:
        # Verifica se o iptables está ativo
        result = subprocess.run(['sudo', 'iptables', '-L'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return "Ativo" if "Chain" in result.stdout else "Inativo"
    except Exception:
        return "Desconhecido"

def get_antivirus_status():
    try:
        # Verifica presença de processos de antivírus comuns
        processes = [p.info['name'] for p in psutil.process_iter(['name']) if 'clamav' in p.info['name'].lower()]
        return "Ativo (ClamAV)" if processes else "Inativo"
    except Exception:
        return "Desconhecido"

def get_system_metrics():
    try:
        return psutil.users().__len__(), len(psutil.process_iter()), f"{psutil.disk_usage('/').percent}%", f"{psutil.virtual_memory().percent}%", f"{psutil.cpu_percent()}%"
    except Exception:
        return 0, 0, "Desconhecido", "Desconhecido", "Desconhecido"

# --- Classe principal ---
class NetworkScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.devices = []
        self.scan_history = []
        self.title("Dark Hacker Pro v6.0")
        self.geometry("1200x800")
        self.minsize(800, 600)
        self.progress_var = tk.DoubleVar()
        self.scanned_count = tk.IntVar(value=0)
        self.monitor_thread = None
        self.scan_thread = None
        self.running = True
        self.paused = False
        self.subnets = get_subnets()
        self.current_subnet = self.subnets[0]
        self.silent_mode = False
        self.start_ip_options = {"192.168.10.1": 1, "192.168.10.100": 100, "192.168.1.0": 0}
        self.start_ip = tk.StringVar(value="192.168.10.100")
        self.setup_ui()
        self.update_scan_progress("Iniciando aplicação Dark Hacker Pro v6.0...")
        self.bind_shortcuts()
        self.start_background_tasks()

    def setup_ui(self):
        self.style = ttkthemes.ThemedStyle(self)
        self.style.set_theme("arc")
        self.update_theme()
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(pady=10, expand=True, fill="both")

        # Aba Dispositivos
        self.devices_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.devices_frame, text="Dispositivos")
        self.device_text = tk.Text(self.devices_frame, width=100, height=15, bg="#34495E", fg="#ECF0F1")
        self.device_text.pack(padx=10, pady=5, fill="both", expand=True)
        self.scan_progress_text = tk.Text(self.devices_frame, width=100, height=5, bg="#2C3E50", fg="#ECF0F1")
        self.scan_progress_text.pack(padx=10, pady=5, fill="both", expand=True)
        self.control_frame = ttk.Frame(self.devices_frame)
        self.control_frame.pack(pady=5, fill="x")
        ttk.Button(self.control_frame, text="Escanear Agora", command=self.manual_scan).pack(side="left", padx=5)
        ttk.Button(self.control_frame, text="Iniciar Automático", command=self.start_auto_scan_thread).pack(side="left", padx=5)
        ttk.Button(self.control_frame, text="Pausar", command=self.toggle_pause).pack(side="left", padx=5)
        self.progress_bar = ttk.Progressbar(self.control_frame, variable=self.progress_var, mode="determinate")
        self.progress_bar.pack(side="left", padx=5, fill="x", expand=True)
        ttk.Button(self.control_frame, text="Exportar CSV", command=self.export_to_csv).pack(side="left", padx=5)
        ttk.Button(self.control_frame, text="Exportar Excel", command=self.export_to_excel).pack(side="left", padx=5)
        ttk.Button(self.control_frame, text="Exportar JSON", command=self.export_to_json).pack(side="left", padx=5)
        ttk.OptionMenu(self.control_frame, self.start_ip, self.start_ip.get(), *self.start_ip_options.keys(), command=self.update_start_ip).pack(side="left", padx=5)

        # Aba Configurações
        self.config_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.config_frame, text="Configurações")
        ttk.Checkbutton(self.config_frame, text="Modo Silencioso", command=self.toggle_silent, variable=tk.BooleanVar(value=self.silent_mode)).pack(pady=5)
        ttk.Button(self.config_frame, text="Tutorial", command=self.show_tutorial).pack(pady=5)

        # Aba Logs
        self.logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_frame, text="Logs")
        self.logs_text = tk.Text(self.logs_frame, width=100, height=20, bg="#34495E", fg="#ECF0F1")
        self.logs_text.pack(padx=10, pady=10, fill="both", expand=True)

        # Aba Estatísticas
        self.stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.stats_frame, text="Estatísticas")
        self.fig, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.stats_frame)
        self.canvas.get_tk_widget().pack(pady=10, fill="both", expand=True)

        self.status_bar = ttk.Label(self, text="Inicializando...", anchor="w", background="#2C3E50", foreground="#ECF0F1")
        self.status_bar.pack(side="bottom", fill="x", padx=10, pady=5)

    def update_start_ip(self, value):
        self.start_ip.set(value)

    def start_auto_scan_thread(self):
        if not self.paused:
            self.status_bar.config(text="Iniciando escaneamento automático...")
            log_event("Iniciando escaneamento automático em thread")
            self.scan_thread = threading.Thread(target=self.run_auto_scan, daemon=True)
            self.scan_thread.start()

    def run_auto_scan(self):
        while self.running and not self.paused:
            for subnet in self.subnets:
                self.current_subnet = subnet
                start_ip_value = self.start_ip_options[self.start_ip.get()]
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                devices = loop.run_until_complete(scan_network_with_async(subnet, self, start_ip_value, 24))
                loop.close()
                self.after(0, lambda: setattr(self, 'devices', devices))
                self.after(0, self.update_display)
                self.after(0, self.update_stats)
                self.after(0, self.check_intruders)
                if self.devices and not self.silent_mode:
                    self.after(0, play_sound)
                    self.after(0, lambda: show_notification(f"Escaneamento em {subnet} concluído!"))
                time.sleep(300)

    def manual_scan(self):
        if not self.paused:
            async def scan():
                self.status_bar.config(text=f"Escaneando {self.current_subnet} a partir de .{self.start_ip_options[self.start_ip.get()]}...")
                self.progress_var.set(0)
                self.devices = await scan_network_with_async(self.current_subnet, self, self.start_ip_options[self.start_ip.get()], 24)
                self.update_display()
                self.update_stats()
                self.check_intruders()
                if self.devices and not self.silent_mode:
                    play_sound()
                    show_notification("Escaneamento manual concluído!")

            asyncio.run(scan())

    def toggle_pause(self):
        self.paused = not self.paused
        self.status_bar.config(text=f"{'Pausado' if self.paused else 'Continuando...'}" if self.paused else f"Escaneamento {'pronto' if not self.devices else 'em andamento'}")

    def update_subnet(self, value):
        self.current_subnet = value
        self.status_bar.config(text=f"Subnet atualizado para {self.current_subnet}")

    def load_devices_from_db(self):
        session = Session()
        self.devices = [{"ip": d.ip, "ping": d.ping, "mac": d.mac, "scan_time": d.scan_time, "traffic": d.traffic,
                        "tcp_info": d.tcp_info, "ipv4_info": d.ipv4_info, "ipv6_info": d.ipv6_info,
                        "dns_info": d.dns_info, "proxy_vpn_info": d.proxy_vpn_info, "os_info": d.os_info,
                        "hardware_info": d.hardware_info, "browser_info": d.browser_info, "location": d.location,
                        "vulnerabilities": d.vulnerabilities, "alerts": d.alerts, "device_type": d.device_type,
                        "uptime": d.uptime, "hostname": d.hostname, "network_speed": d.network_speed,
                        "firewall_status": d.firewall_status, "antivirus_status": d.antivirus_status,
                        "user_count": d.user_count, "process_count": d.process_count, "disk_usage": d.disk_usage,
                        "memory_usage": d.memory_usage, "cpu_usage": d.cpu_usage}
                       for d in session.query(Device).all()]
        session.close()
        self.update_display()

    def save_device_to_db(self, device):
        session = Session()
        existing = session.query(Device).filter_by(ip=device["ip"]).first()
        if not existing:
            new_device = Device(**device)
            session.add(new_device)
        else:
            for key, value in device.items():
                setattr(existing, key, value)
        session.commit()
        session.close()

    def update_progress(self, ip, device, status_msg):
        if not self.paused and hasattr(self, 'device_text') and self.device_text.winfo_exists():
            current = self.progress_var.get()
            self.progress_var.set(current + 1)
            if device:
                self.device_text.insert(tk.END, f"IP: {ip}\n"
                    f"Ping: {device['ping']}\nMAC: {device['mac']}\nScan Time: {device['scan_time']}\n"
                    f"Traffic: {device['traffic']/1024/1024:.2f} MB\nTCP Info: {device['tcp_info']}\n"
                    f"IPv4 Info: {device['ipv4_info']}\nIPv6 Info: {device['ipv6_info']}\nDNS Info: {device['dns_info']}\n"
                    f"Proxy/VPN: {device['proxy_vpn_info']}\nOS: {device['os_info']}\nHardware: {device['hardware_info']}\n"
                    f"Browser: {device['browser_info']}\nLocation: {device['location']}\n"
                    f"Device Type: {device['device_type']}\nUptime: {device['uptime']}\nHostname: {device['hostname']}\n"
                    f"Network Speed: {device['network_speed']}\nFirewall: {device['firewall_status']}\n"
                    f"Antivirus: {device['antivirus_status']}\nUser Count: {device['user_count']}\n"
                    f"Process Count: {device['process_count']}\nDisk Usage: {device['disk_usage']}\n"
                    f"Memory Usage: {device['memory_usage']}\nCPU Usage: {device['cpu_usage']}\n"
                    f"Vulnerabilidades: {device['vulnerabilities']}\nAlertas: {device['alerts']}\n{'-'*50}\n")
                self.scan_history.append(device)
                self.save_device_to_db(device)
            else:
                self.device_text.insert(tk.END, f"Escaneado: {ip} - Inativo\n{'-'*50}\n")
            self.device_text.see(tk.END)
            self.update_scan_progress(status_msg)

    def update_scan_progress(self, message):
        if hasattr(self, 'scan_progress_text') and self.scan_progress_text.winfo_exists():
            self.scan_progress_text.delete(1.0, tk.END)
            self.scan_progress_text.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {message}\n")
            self.scan_progress_text.see(tk.END)

    def update_display(self):
        if hasattr(self, 'device_text') and self.device_text.winfo_exists():
            self.device_text.delete(1.0, tk.END)
            header = f"{'IP':<15} | {'Ping':<8} | {'Scan Time':<19}\n"
            self.device_text.insert(tk.END, header + "─" * 50 + "\n")
            for device in self.devices:
                line = f"{device['ip']:<15} | {device['ping']:<8} | {device['scan_time']:<19}\n"
                self.device_text.insert(tk.END, line)
                self.device_text.insert(tk.END, f"MAC: {device['mac']}\nTraffic: {device['traffic']/1024/1024:.2f} MB\nTCP Info: {device['tcp_info']}\n"
                    f"IPv4 Info: {device['ipv4_info']}\nIPv6 Info: {device['ipv6_info']}\nDNS Info: {device['dns_info']}\n"
                    f"Proxy/VPN: {device['proxy_vpn_info']}\nOS: {device['os_info']}\nHardware: {device['hardware_info']}\n"
                    f"Browser: {device['browser_info']}\nLocation: {device['location']}\nDevice Type: {device['device_type']}\n"
                    f"Uptime: {device['uptime']}\nHostname: {device['hostname']}\nNetwork Speed: {device['network_speed']}\n"
                    f"Firewall: {device['firewall_status']}\nAntivirus: {device['antivirus_status']}\n"
                    f"User Count: {device['user_count']}\nProcess Count: {device['process_count']}\n"
                    f"Disk Usage: {device['disk_usage']}\nMemory Usage: {device['memory_usage']}\nCPU Usage: {device['cpu_usage']}\n"
                    f"Vulnerabilidades: {device['vulnerabilities']}\nAlertas: {device['alerts']}\n{'-'*50}\n")
            self.device_text.see(tk.END)

    def update_stats(self):
        if hasattr(self, 'ax') and hasattr(self, 'canvas'):
            self.ax.clear()
            ping_counts = {"Ativo": 0, "Inativo": 0}
            for d in self.devices:
                if d["ping"] in ping_counts:
                    ping_counts[d["ping"]] += 1
            self.ax.bar(ping_counts.keys(), ping_counts.values(), color=["#00FF00", "#FF0000"])
            self.ax.set_title("Estatísticas de Ping")
            self.canvas.draw()

    def check_intruders(self):
        known_ips = set(d["ip"] for d in self.scan_history[-100:])
        new_ips = set(d["ip"] for d in self.devices) - known_ips
        if new_ips and not self.silent_mode:
            play_sound()
            show_notification(f"Intruso detectado: {', '.join(new_ips)}")

    def export_to_csv(self):
        if self.devices:
            with filedialog.asksaveasfile(defaultextension=".csv", filetypes=[("CSV files", "*.csv")]) as f:
                if f:
                    writer = csv.DictWriter(f, fieldnames=list(self.devices[0].keys()))
                    writer.writeheader()
                    writer.writerows(self.devices)
                    self.status_bar.config(text="Exportado para CSV com sucesso!")
        else:
            self.status_bar.config(text="Nenhum dado para exportar!")

    def export_to_excel(self):
        if self.devices:
            with filedialog.asksaveasfile(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")]) as f:
                if f:
                    workbook = xlsxwriter.Workbook(f.name)
                    worksheet = workbook.add_worksheet()
                    headers = list(self.devices[0].keys())
                    for col, header in enumerate(headers):
                        worksheet.write(0, col, header)
                    for row, device in enumerate(self.devices, 1):
                        for col, value in enumerate(headers):
                            worksheet.write(row, col, str(device[value]))
                    workbook.close()
                    self.status_bar.config(text="Exportado para Excel com sucesso!")
        else:
            self.status_bar.config(text="Nenhum dado para exportar!")

    def export_to_json(self):
        if self.devices:
            with filedialog.asksaveasfile(defaultextension=".json", filetypes=[("JSON files", "*.json")]) as f:
                if f:
                    json.dump(self.devices, f, indent=4)
                    self.status_bar.config(text="Exportado para JSON com sucesso!")
        else:
            self.status_bar.config(text="Nenhum dado para exportar!")

    def update_theme(self):
        current_hour = datetime.datetime.now().hour
        self.style.theme_use("arc" if 6 <= current_hour < 18 else "black")

    def toggle_silent(self):
        self.silent_mode = not self.silent_mode
        self.status_bar.config(text=f"Modo Silencioso {'Ativado' if self.silent_mode else 'Desativado'}")

    def show_tutorial(self):
        tutorial = "Tutorial - Dark Hacker Pro v6.0\n1. Escaneie com 'Escanear Agora'.\n2. Escolha o IP inicial no menu.\n3. Use 'Pausar' para interromper.\n4. Exporte dados com CSV, Excel ou JSON.\nNota: Requer sudo para Nmap e permissões de rede."
        messagebox.showinfo("Tutorial", tutorial)

    def bind_shortcuts(self):
        self.bind('<Control-q>', lambda e: self.quit_app())
        self.bind('<Control-s>', lambda e: self.manual_scan())
        self.bind('<Control-p>', lambda e: self.toggle_pause())
        self.bind('<Control-e>', lambda e: self.export_to_csv())
        self.bind('<Control-x>', lambda e: self.export_to_excel())
        self.bind('<Control-j>', lambda e: self.export_to_json())

    def start_background_tasks(self):
        self.monitor_thread = threading.Thread(target=self.monitor_system, daemon=True)
        self.monitor_thread.start()
        threading.Thread(target=self.backup_data, daemon=True).start()

    def backup_data(self):
        with open("backup.json", "w") as f:
            json.dump(self.scan_history, f, indent=2)

    def monitor_system(self):
        while self.running:
            try:
                cpu_usage = psutil.cpu_percent()
                self.after(0, lambda: self.status_bar.config(text=f"{self.status_bar.cget('text').split('|')[0]} | CPU: {cpu_usage}% | {datetime.datetime.now().strftime('%H:%M:%S')}"))
                time.sleep(5)
            except Exception as e:
                log_event(f"Erro no monitor_system: {e}")
                break

    def quit_app(self):
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        if hasattr(self, 'scan_thread') and self.scan_thread:
            self.scan_thread.join(timeout=2)
        self.destroy()

def play_sound():
    try:
        notify2.init("Scanner")
        n = notify2.Notification("Alerta", "Escaneamento concluído ou intruso detectado!", "dialog-information")
        n.show()
    except Exception:
        pass

def show_notification(message):
    try:
        notify2.init("Scanner")
        n = notify2.Notification("Notificação", message, "dialog-information")
        n.show()
    except Exception:
        pass

if __name__ == "__main__":
    app = NetworkScannerApp()
    app.protocol("WM_DELETE_WINDOW", app.quit_app)
    app.mainloop()