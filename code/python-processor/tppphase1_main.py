import asyncio
from nats.aio.client import Client as NATS
import os, random
from scapy.all import Ether

async def run():
    nc = NATS()

    nats_url = os.getenv("NATS_SURVEYOR_SERVERS", "nats://nats:4222")
    await nc.connect(nats_url)

    mean_delay_values = [1e-6, 1e-5, 1e-4, 1e-3, 1e-2]
    packet_counter = 0
    current_delay_index = 0
    async def message_handler(msg):
        nonlocal packet_counter, current_delay_index
        subject = msg.subject
        data = msg.data #.decode()
        #print(f"Received a message on '{subject}': {data}")
        packet = Ether(data)
        #print(packet.show())

        # Publish the received message to outpktsec and outpktinsec
        #delay = random.expovariate(1 / 5e-6)
        #await asyncio.sleep(delay)
        current_mean = mean_delay_values[current_delay_index]
        delay = random.expovariate(1 / current_mean)
        await asyncio.sleep(delay)

        if subject == "inpktsec":
            await nc.publish("outpktinsec", msg.data)
        else:
            await nc.publish("outpktsec", msg.data)
        
        packet_counter += 1
        # print(f"Packet {packet_counter} sent with delay {delay*1e6:.1f} microseconds")
        if packet_counter >= 40: # 2 * 20 : Number of packets to send before changing the mean delay
            packet_counter = 0
            if(current_delay_index == len(mean_delay_values) - 1):
                print("All mean delays tested. Disconnecting...")
                await nc.close()
            current_delay_index += 1
            # print(f"Changing mean delay to {mean_delay_values[current_delay_index]*1e6:.3f} microseconds")

    await nc.subscribe("inpktsec", cb=message_handler)
    await nc.subscribe("inpktinsec", cb=message_handler)

    print("Subscribed to inpktsec and inpktinsec topics")
    # print(f"Initial mean delay: {mean_delay_values[0]*1e6:.1f} microseconds")
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("Disconnecting...")
        await nc.close()

if __name__ == '__main__':
    asyncio.run(run())