import asyncio
import logging

from reopenwebnet import messages
from reopenwebnet.client import OpenWebNetClient

logging.basicConfig(level=logging.DEBUG)

HOST = "192.168.68.61"
PORT = 20000
PASSWORD = "123456a"
LIGHT_WHERE = "11"


async def schedule_stop(delay):
    return asyncio.ensure_future(asyncio.sleep(delay))


async def main():
    def on_event(*args):
        print("got event", args)

    client = OpenWebNetClient(HOST, PORT, PASSWORD, messages.CMD_SESSION)
    await client.start()
    await asyncio.sleep(4)

    # Play with the lights
    for i in range(5):
        await light_on(client)
        await asyncio.sleep(1)
        await light_off(client)
        await asyncio.sleep(1)


async def light_off(client):
    print("Light off")
    client.send_message(messages.NormalMessage(1, 0, LIGHT_WHERE))


async def light_on(client):
    print("Light on")
    client.send_message(messages.NormalMessage(1, 1, LIGHT_WHERE))

import platform
if platform.system()=='Windows':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
asyncio.run(main())
