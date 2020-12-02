import asyncio
import os
import random
import sys
from concurrent.futures.thread import ThreadPoolExecutor

from EncLib import Encryption
from format import BasicGenerator, CommandPacker, RequestType, PrepareUploadCommand, ProcessPacket


class ClientGenerator(BasicGenerator):
    pass

async def ainput(prompt: str = ""):
    with ThreadPoolExecutor(1, "AsyncInput", lambda x: print(x, end="", flush=True), (prompt,)) as executor:
        return (await asyncio.get_event_loop().run_in_executor(
            executor, sys.stdin.readline
        )).rstrip()





class Client:
    def __init__(self):
        self.key = "my secure key"
        self.otk = ClientGenerator.generate_otk(default=True)

    def run(self):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(client.start())

    async def start(self):
        await self.connect()
        await asyncio.gather(self.handle_async_commands(), self.handle_c_commands())

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection('127.0.0.1', 20013)
        await self.set_random_otk()

    async def receive(self):
        return await self.reader.read(100)

    async def send(self, message):
        print("request: ", [int(x) for x in bytes(message)])
        self.writer.write(bytes(message))
        await self.writer.drain()

    async def set_random_otk(self):
        command = CommandPacker(header=RequestType.RUN_METHOD, command="")
        packed = command.pack(self.key, otk=self.otk)
        await self.send(packed)
        self.otk = command.next_otk

    async def handle_server_message(self, message):
        print(f"response: {message}")

    async def handle_client_message(self, message):
        print(f"command to send: {message}")
        command = CommandPacker(header=RequestType.RUN_METHOD, command=message)
        if command.client_sided():
            # do stuff
            return "client_side"
        packed = command.pack(self.key, self.otk)
        await self.send(packed)
        self.otk = command.next_otk
        return "server_side_request"

    async def handle_c_commands(self):
        while 1:
            print("get user input")
            request = input("request >>> ")
            print("resquest:", request)
            if await self.handle_client_message(request) == "server_side_request":
                print("waiting for server to respond")
                data = await self.receive()
                print("got response")
                await self.handle_server_message(data)
            else:
                print("client side request")

    async def handle_async_commands(self):

        while 0:
            data = await ainput()
            await self.handle_client_message(data)

    def read_in_chunks(self, file_object, chunk_size=1024):

        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    async def upload_file(self, path):
        pid = ClientGenerator.generate_pid()
        commandPacker = PrepareUploadCommand(path=path, proc_id=pid)
        command = commandPacker.pack(key=self.key, otk=self.otk)
        await self.send(command)

        for chunk in self.read_in_chunks(path, chunk_size=commandPacker.chunk_size):
            commandPacker = ProcessPacket(payload=chunk, proc_id=pid)
            command = commandPacker.pack(key=self.key, otk=self.otk)
            await self.send(command)



client = Client()
client.run()
