"""
ÇALIŞTIRMA TALİMATLARI:

1. Sanal Ortamı (venv) Aktif Etmek İçin:
   Windows (PowerShell): .venv\Scripts\Activate.ps1
   Windows (CMD): .venv\Scripts\activate.bat

2. Gerekli Kütüphaneleri Kurmak İçin (Eğer kurulu değilse):
   pip install scapy

3. Scripti Çalıştırmak İçin (Yönetici İzni Gerekebilir):
   python main.py

4. Belirli bir protokolü filtreleyerek çalıştırmak isterseniz:
   python main.py --proto tcp
   python main.py --proto udp
   python main.py --proto "port 80"
"""

import argparse
import sys
from scapy.all import sniff, IP, TCP, UDP

def parse_packet_yusuf(packet):
    """
    Yusuf Dalmış'ın Modülü: Ham paketlerin katmanlarını (IP, Port, TCP/UDP)
    ayrıştırıp temiz ve okunabilir bir metin formatına getiren parser.
    """
    parsed_data = {}
    if IP in packet:
        parsed_data['src_ip'] = packet[IP].src
        parsed_data['dst_ip'] = packet[IP].dst
        parsed_data['protocol'] = 'UNKNOWN'
        parsed_data['src_port'] = None
        parsed_data['dst_port'] = None
        parsed_data['payload'] = ''
        parsed_data['raw_payload'] = b''

        if packet.haslayer(TCP):
            parsed_data['protocol'] = 'TCP'
            parsed_data['src_port'] = packet[TCP].sport
            parsed_data['dst_port'] = packet[TCP].dport
            parsed_data['raw_payload'] = bytes(packet[TCP].payload)
        elif packet.haslayer(UDP):
            parsed_data['protocol'] = 'UDP'
            parsed_data['src_port'] = packet[UDP].sport
            parsed_data['dst_port'] = packet[UDP].dport
            parsed_data['raw_payload'] = bytes(packet[UDP].payload)

        if parsed_data['raw_payload']:
            parsed_data['payload'] = parsed_data['raw_payload'].decode('utf-8', errors='ignore').strip()

        # Temiz metin formatında ekrana yazdırma
        print("\n" + "="*60)
        print(" [ YUSUF DALMIŞ ] - PARSER".center(60))
        print("\n")
        print(f"| Protokol : {parsed_data['protocol']}")
        print(f"| Kaynak   : {parsed_data['src_ip']}:{parsed_data['src_port'] if parsed_data['src_port'] else 'N/A'}")
        print(f"| Hedef    : {parsed_data['dst_ip']}:{parsed_data['dst_port'] if parsed_data['dst_port'] else 'N/A'}")
        
        clean_payload = parsed_data['payload'][:80].replace('\n', ' ') + ("..." if len(parsed_data['payload']) > 80 else "")
        print(f"| Veri     : {clean_payload if clean_payload else '[BOŞ VEYA OKUNAMIYOR]'}")
        print("="*60 + "\n")

        return parsed_data
    return None

def packet_callback(packet):
    if IP in packet:
        # --- Nejdet'in Modülü: Ham Paket Yakalama ---
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        print("\n[NEJDET] HAM PAKET YAKALANDI")
        print(f"    Kaynak IP: {src_ip} -> Hedef IP: {dst_ip} | Protokol No: {proto}")
        
        if packet.haslayer(TCP):
            print(f"    Katman: TCP | Raw Payload: {bytes(packet[TCP].payload)[:50]}")
        elif packet.haslayer(UDP):
            print(f"    Katman: UDP | Raw Payload: {bytes(packet[UDP].payload)[:50]}")
        else:
            print(f"    Raw Packet Bytes: {bytes(packet)[:50]}...")
            
        # ---  Paket Ayrıştırma ---
        parsed_packet = parse_packet_yusuf(packet)
        # İleride Afsec in ids motoru bu 'parsed_packet' değişkenini kullanacak.

def main():
    # --- Nejdet'in Modülü: Ham Paket Yakalama ---
    parser = argparse.ArgumentParser(description="Canlı Paket Yakalama Motoru")
    parser.add_argument('--proto', type=str, help="Filtrelenecek protokol veya BPF ifadesi (Örn: tcp, udp, 'port 53')", default="")
    args = parser.parse_args()

    bpf_filter = args.proto.lower()
    print(f"[*] Dinleme başlatılıyor... Aktif Filtre: '{bpf_filter if bpf_filter else 'HEPSİ'}'")
    print("[*] Paketleri görmek için ağda trafik oluşturun (Ctrl+C ile durdurabilirsiniz).\n")

    try:
        sniff(filter=bpf_filter, prn=packet_callback, store=0)
    except PermissionError:
        print("[-] HATA: Ağ kartını dinlemek için bu scripti 'sudo' (Yönetici) olarak çalıştırmalısınız!")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Bir hata oluştu: {e}")

if __name__ == "__main__":
    main()