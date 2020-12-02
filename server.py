import asyncio, socket
import random

from EncLib import Encryption
from format import CommandUnpacker, ONETIME_KEY_LENGTH, RequestType

default_otk = bytearray([1 for _ in range(ONETIME_KEY_LENGTH)])


def gather_bytes(*bytes):
    [print(byte, byte << (i * 8)) for i, byte in enumerate(bytes)]
    return sum([byte << (i * 8) for i, byte in enumerate(bytes)])


def split_to_bytes(num: int):
    out = bytearray()
    while num > 255:
        b = num % 255
        out.append(b)
        num = num//255
        print(num)
    out.append(num)
    [print(int(x)) for x in out]
    return out


class TransferProcess:
    def __init__(self, proc_id, total_parts, chunk_size, filename):
        self.filename = filename
        self.proc_id = proc_id
        self.total_parts = total_parts
        self.chunk_size = chunk_size
        self.current_chunk = 0
        self.data_buffer = bytearray()

    def save_chunk(self, chunk):
        self.data_buffer.extend(chunk)
        self.current_chunk += 1


class CommandHandler:
    def run(self, args):
        self.transfer_processes = []
        response = self.__getattribute__(args[0])(args[1:])
        if not response:
            raise Exception(f"server did not return valid response. call was: {args}")
        return response

    @staticmethod
    def test(args):
        print(f"run test method with args {args}")
        return f"success: {args}".encode()

    @staticmethod
    def prepare_upload(args):
        pass

    @staticmethod
    def process_packet(request):
        pass


class Server:
    def __init__(self):
        self.onetime_key = default_otk
        self.key = "my secure key"
        self.cHandler = CommandHandler()

    async def handle_client(self, reader, writer):
        while True:
            request = await reader.read(2048)
            response = self.handle_request(request)
            if response:
                print("responding: ", response)
                writer.write(response)
                await writer.drain()

    def handle_request(self, data: bytes):
        """:return encoded response"""
        command = CommandUnpacker(data)
        header, args, self.onetime_key = command.unpack(self.key, self.onetime_key)
        return self.cHandler.run(args) # self.dispatch_requests(header, args)

    def dispatch_requests(self, header, args):

        if header == RequestType.RUN_METHOD:
            pass

        if header == RequestType.PREPARE_FILE_UPLOAD:
            pass

        if header == RequestType.PREPARE_FILE_DOWNLOAD:
            pass

        if header == RequestType.DATA_TRANSFER:
            pass

    async def start(self):
        server = await asyncio.start_server(self.handle_client, '0.0.0.0', 20013)
        async with server:
            await server.serve_forever()

    def run(self):
        print("server started")
        asyncio.run(self.start())


server = Server()
server.run()
