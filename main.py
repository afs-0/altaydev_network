"""
ÇALIŞTIRMA TALİMATLARI:

1. Sanal Ortamı (venv) kurun

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

def ahmet_ids_engine(parsed_data):
    """
    Ahmet Faruk'un Modülü: Basit Siber Güvenlik Kuralları Motoru (IDS).
    Yusuf'un ayrıştırdığı verileri alır, şüpheli veya şifresiz trafiği tespit eder.
    Bir sonraki aşama için uygun bir sözlük döndürür.
    """
    if not parsed_data:
        return None
        
    alert_triggered = False
    alert_reasons = []
    
    # Kural 1: Şifresiz/Tehlikeli Port Kontrolü (Örn: HTTP=80, FTP=21, Telnet=23)
    unencrypted_ports = [80, 21, 23]
    if parsed_data.get('dst_port') in unencrypted_ports or parsed_data.get('src_port') in unencrypted_ports:
        alert_triggered = True
        alert_reasons.append(f"ŞİFRESİZ TRAFİK (Port {parsed_data['dst_port'] or parsed_data['src_port']})")
        
    # Kural 2: Payload içinde şüpheli kelime tespiti (Cleartext credentials vb.)
    suspicious_keywords = ['password', 'passwd', 'login', 'admin', 'root']
    payload_lower = parsed_data.get('payload', '').lower()
    
    for keyword in suspicious_keywords:
        if keyword in payload_lower:
            alert_triggered = True
            alert_reasons.append(f"ŞÜPHELİ KELİME TESPİTİ ('{keyword}')")
            break # Bir tane bulması yeterli
    
    # Veri oluşturma
    enriched_data = parsed_data.copy()
    enriched_data['is_alert'] = alert_triggered
    enriched_data['alert_reasons'] = alert_reasons
    
    # Eğer alarm tetiklendiyse ekrana terminal renk kodlarıyla kırmızı bas
    if alert_triggered:
        # \033[91m = Kırmızı Metin, \033[0m = Rengi Sıfırla
        print("\033[91m" + "!!!" + "="*54 + "!!!")
        print("!!! [ AHMET FARUK ] - IDS ALARMI !!!".center(60))
        print(f"!!! Sebep : {', '.join(alert_reasons)}")
        print(f"!!! Hedef : {parsed_data['dst_ip']}:{parsed_data['dst_port']}")
        print("!!!" + "="*54 + "!!!\033[0m\n")

    return enriched_data

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

	# -- IDS --
        if parsed_packet:
            ids_result = ahmet_ids_engine(parsed_packet)

def main():
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
