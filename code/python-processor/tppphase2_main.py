import asyncio
from nats.aio.client import Client as NATS
import os
from scapy.all import Ether, IP, TCP

# This function will update the TCP checksum for the packet
# Without this, TCP doesn't work
def update_tcp_checksum(packet):
    if TCP in packet:
        del packet[TCP].chksum  # Delete the checksum field
        packet[TCP].chksum = None  # Set it to None, forcing Scapy to recompute it
    return packet

async def run():
    nc = NATS()

    nats_url = os.getenv("NATS_SURVEYOR_SERVERS", "nats://nats:4222")
    await nc.connect(nats_url)

    async def message_handler(msg):
        subject = msg.subject
        data = msg.data
        # print(f"\nReceived a message on '{subject}' ({len(data)} bytes)")
        try:
            packet = Ether(data)
            if IP in packet:
                ip_layer = packet[IP]

                if TCP in ip_layer:
                    tcp_layer = ip_layer[TCP]
                    flags = tcp_layer.sprintf("%TCP.flags%")
                    # print(f" - TCP sport: {tcp_layer.sport}, dport: {tcp_layer.dport}")
                    # print(f" - TCP flags: {flags} ➜ ", end="")
                    """
                    if flags == "S":
                        print("SYN (start of connection)")
                    elif flags == "SA":
                        print("SYN-ACK (response to SYN)")
                    elif flags == "A":
                        print("ACK (acknowledgement)")
                    elif flags == "U":
                        print("URG (urgent data)")
                    else:
                        print("Other TCP flags")
                    """
                    if "R" in flags:
                        # print(" - RST (reset connection)")
                        return  # early return if RST flag is present, disturbs the connection
                    # Update the TCP checksum before forwarding
                    packet = update_tcp_checksum(packet)
                else:
                    pass
                    # print(" - Not a TCP packet")
            else:
                pass
                # print(" - Not an IP packet")
        except Exception as e:
            print(f"Failed to parse packet: {e}")

        # Publish the received message to outpktsec and outpktinsec
        out_topic = "outpktinsec" if subject == "inpktsec" else "outpktsec"
        # print(f"Forwarding to {out_topic}")
        await nc.publish(out_topic, bytes(packet))  # Convert the packet back to bytes

    # Subscribe to topics
    await nc.subscribe("inpktsec", cb=message_handler)
    await nc.subscribe("inpktinsec", cb=message_handler)

    print("Subscribed to inpktsec and inpktinsec topics")

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("Disconnecting...")
        await nc.close()

if __name__ == '__main__':
    asyncio.run(run())
