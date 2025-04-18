import asyncio
from nats.aio.client import Client as NATS
import os, random
from scapy.all import Ether

async def run():
    nc = NATS()

    nats_url = os.getenv("NATS_SURVEYOR_SERVERS", "nats://nats:4222")
    await nc.connect(nats_url)

    async def message_handler(msg):
        subject = msg.subject
        data = msg.data #.decode()
        print(f"Received a message on '{subject}'")
        packet = Ether(data)
        #print(packet.show())
        # Publish the received message to outpktsec and outpktinsec
        #delay = random.expovariate(1 / 5e-6)
        #await asyncio.sleep(delay)
        if subject == "inpktsec":
            print(f"Sending to outpktinsec: {len(data)} bytes")
            await nc.publish("outpktinsec", msg.data)
        else:
            print(f"Sending to outpktsec: {len(data)} bytes")
            await nc.publish("outpktsec", msg.data)
   
    # Subscribe to inpktsec and inpktinsec topics
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