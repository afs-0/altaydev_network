import asyncio
import json
import sys
from collections import deque
from datetime import datetime
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.align import Align

toplam_paket = 0
tcp_sayaci = 0
udp_sayaci = 0
anlik_pps = 0
son_tehdit_durumu = "VERİ BEKLENİYOR..."
son_guncelleme = "-"
pps_gecmisi = deque([0]*40, maxlen=40)

DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 5006

class DashboardReceiverProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data, addr):
        global toplam_paket, tcp_sayaci, udp_sayaci, anlik_pps, son_tehdit_durumu, son_guncelleme
        try:
            veri = json.loads(data.decode('utf-8'))
            toplam_paket += 1
            
            protocol = veri.get('protocol', 'OTHER').upper()
            if "TCP" in protocol:
                tcp_sayaci += 1
            elif "UDP" in protocol:
                udp_sayaci += 1
                
            is_alert = veri.get('is_alert', False)
            if is_alert:
                reasons = veri.get('alert_reasons', ['ŞÜPHELİ AKTİVİTE'])
                son_tehdit_durumu = f"ŞÜPHELİ PAKET ({', '.join(reasons)})"
            else:
                son_tehdit_durumu = "GÜVENLİ TRAFİK"
                
            anlik_pps += 1
            son_guncelleme = datetime.now().strftime("%H:%M:%S")
        except Exception:
            pass

def grafik_olustur(gecmis, yukseklik=8):
    if not gecmis:
        return ""
    en_yuksek = max(gecmis)
    en_yuksek = en_yuksek if en_yuksek > 0 else 1
    satirlar = []
    bloklar = [' ', ' ', '▂', '▃', '▄', '▅', '▆', '▇', '█']
    
    for y in range(yukseklik, 0, -1):
        satir = ""
        for deger in gecmis:
            sekizlik_dilim = int((deger / en_yuksek) * yukseklik * 8)
            if sekizlik_dilim >= y * 8:
                satir += "[cyan]█[/cyan]"
            elif sekizlik_dilim <= (y - 1) * 8:
                satir += " "
            else:
                idx = sekizlik_dilim - (y - 1) * 8
                satir += f"[cyan]{bloklar[idx]}[/cyan]"
        satirlar.append(satir)
    
    satirlar.append("[dim]" + "─" * len(gecmis) + "[/dim]")
    return "\n".join(satirlar)

def pano_olustur() -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="baslik", size=3),
        Layout(name="govde")
    )
    
    layout["govde"].split_row(
        Layout(name="sol_tablo", ratio=1),
        Layout(name="sag_grafik", ratio=1)
    )
    
    layout["baslik"].update(Panel(Align.center("[bold cyan]SİBER TELESKOP - CANLI AĞ TELEMETRİSİ[/bold cyan]"), style="on black"))
    
    tablo = Table(show_header=True, header_style="bold magenta", expand=True)
    tablo.add_column("Metrik / Protokol", justify="left")
    tablo.add_column("Anlık / Toplam Değer", justify="right", style="green")
    
    son_pps_degeri = pps_gecmisi[-1] if pps_gecmisi else 0
    pps_renk = "[bold red]" if son_pps_degeri > 40 else "[bold yellow]"
    
    tablo.add_row("Hız (Paket/Saniye - PPS)", f"{pps_renk}{son_pps_degeri}[/]")
    tablo.add_row("Toplam İşlenen Paket", f"[bold white]{toplam_paket}[/bold white]")
    tablo.add_row("TCP Paketleri", f"[bold blue]{tcp_sayaci}[/bold blue]")
    tablo.add_row("UDP Paketleri", f"[bold dark_orange]{udp_sayaci}[/bold dark_orange]")
    
    tehdit_renk = "[bold red]" if "ŞÜPHELİ" in son_tehdit_durumu else "[bold green]"
    if son_tehdit_durumu == "VERİ BEKLENİYOR...":
        tehdit_renk = "[bold white]"
        
    tablo.add_row("Ağ Durumu", f"{tehdit_renk}{son_tehdit_durumu}[/]")
    tablo.add_row("Son Güncelleme", son_guncelleme)
    
    layout["sol_tablo"].update(Panel(tablo, title="[yellow]Gerçek Zamanlı Trafik Sayaçları[/yellow]"))
    
    grafik_metni = grafik_olustur(pps_gecmisi, yukseklik=8)
    layout["sag_grafik"].update(Panel(Align.center(grafik_metni, vertical="middle"), title="[cyan]Ağ Trafik Geçmişi (PPS)[/cyan]"))
    
    return layout

async def pps_hesaplayici():
    global anlik_pps
    while True:
        await asyncio.sleep(1.0)
        pps_gecmisi.append(anlik_pps)
        anlik_pps = 0

async def main():
    loop = asyncio.get_running_loop()
    
    try:
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: DashboardReceiverProtocol(),
            local_addr=(DASHBOARD_HOST, DASHBOARD_PORT)
        )
    except Exception as e:
        print(f"[-] Dashboard soketi baslatilamadi: {e}")
        sys.exit(1)

    asyncio.create_task(pps_hesaplayici())

    print("Dashboard başlatılıyor... Veri bekleniyor...")
    with Live(pano_olustur(), refresh_per_second=4, screen=True) as live:
        try:
            while True:
                live.update(pano_olustur())
                await asyncio.sleep(0.25)
        except asyncio.CancelledError:
            pass
        finally:
            transport.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)