import asyncio
import json
import sys

HOST = "127.0.0.1"
PORT = 5005
DASHBOARD_PORT = 5006

class BeyzaUDPServerProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
        print(f"[*] [BEYZA UDP SERVER] Dinleme baslatildi -> {HOST}:{PORT}")
        print(f"[*] Veriler {HOST}:{DASHBOARD_PORT} adresine aktarilacak.\n")

    def datagram_received(self, data, addr):
        asyncio.create_task(self.process_incoming_packet(data, addr))

    async def process_incoming_packet(self, data, addr):
        try:
            decoded_string = data.decode('utf-8')
            json_data = json.loads(decoded_string)
            self.forward_to_selim_dashboard(data)
        except json.JSONDecodeError:
            pass
        except Exception:
            pass

    def forward_to_selim_dashboard(self, raw_data):
        try:
            self.transport.sendto(raw_data, (HOST, DASHBOARD_PORT))
        except Exception:
            pass

async def main():
    loop = asyncio.get_running_loop()
    try:
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: BeyzaUDPServerProtocol(),
            local_addr=(HOST, PORT)
        )
    except Exception as e:
        print(f"[-] Sunucu baslatilamadi: {e}")
        sys.exit(1)

    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        print("\n[-] Sunucu kapatiliyor...")
    finally:
        transport.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)