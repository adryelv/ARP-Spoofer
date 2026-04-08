# 🔐 ARP Spoofer & Network Sniffer (Python)
![Python](https://img.shields.io/badge/Python-3.x-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Educational-orange)

Ferramenta educacional desenvolvida em Python utilizando **Scapy**, criada para demonstrar e estudar ataques **Man-in-the-Middle (MITM)** em redes locais de laboratório.

> ⚠️ Este projeto foi desenvolvido **exclusivamente para fins educacionais** e deve ser utilizado apenas em ambientes controlados e autorizados.

---

## 🧠 Sobre o projeto

Este script automatiza um ataque de **ARP Poisoning** entre um dispositivo alvo e o gateway da rede, permitindo interceptar e analisar o tráfego em tempo real.

Durante o processo, a ferramenta posiciona a máquina atacante como intermediária na comunicação, possibilitando a observação de pacotes e consultas DNS.

O objetivo é proporcionar aprendizado prático sobre:
- Redes TCP/IP
- Segurança ofensiva
- Funcionamento de ataques MITM
- Sniffing de pacotes com Python

---

## ⚙️ Funcionalidades

### 🔹 ARP Spoofing automatizado
- Envenenamento da tabela ARP da vítima e do gateway
- Envio contínuo de pacotes ARP falsos
- Manutenção automática do ataque em loop

### 🔹 Ativação automática de IP Forwarding (Linux)
Habilita o encaminhamento de pacotes para permitir o funcionamento correto do MITM.

### 🔹 Network Sniffer integrado
Captura e exibe o tráfego em tempo real durante o ataque:

- 🌐 DNS Queries capturadas
- 🌐 DNS Responses capturadas
- 📡 Protocolos monitorados:
  - TCP
  - UDP
  - ICMP

### 🔹 Execução multi-thread
A ferramenta executa simultaneamente:
- Thread 1 → ARP Spoofing
- Thread 2 → Packet Sniffing

### 🔹 Restauração da rede
Ao encerrar o script:
- Pacotes ARP legítimos são enviados
- A tabela ARP da rede é restaurada automaticamente

---

## 🛠️ Tecnologias utilizadas

- Python 3
- Scapy
- Threading
- Sniffing de pacotes
- Redes TCP/IP

---

## 💻 Requisitos

- Linux (recomendado Kali Linux / Ubuntu)
- Python 3
- Acesso root/sudo
- Ambiente de laboratório autorizado

---

## 🧪 Exemplo de saída
```markdown
[+] IP Forwarding ativado
[+] ARP Spoofing INICIADO
    Vítima    : 192.168.0.208
    Gateway   : 192.168.0.1
    Interface : wlp2s0
================================================================================
[+] Sniffer iniciado (capturando tráfego de 192.168.0.208
[+] Pressione Ctrl+C para parar o ataque

[DNS Query] 192.168.0.208 → 8.8.8.8 | google.com
[DNS Answer] 8.8.8.8 → 192.168.0.208 | google.com
[TCP] 192.168.0.208 → 172.217.29.14
```

---

## 📦 Instalação

Clone o repositório:

```bash
git clone https://github.com/adryelv/ARP-Spoofer.git
cd ARP-Spoofer
```

## Instale as dependências:
```bash
pip3 install -r requirements.txt
```
## Execute com privilégios de administrador/root:
```bash
sudo python ARP-Spoofer.py <target_ip> <gateway_ip> <interface>
```

## ⚠️ Aviso legal

Este projeto é destinado exclusivamente para fins educacionais e testes em ambientes autorizados.

O uso desta ferramenta em redes sem permissão é ilegal e pode violar leis locais.
O autor não se responsabiliza por uso indevido.
