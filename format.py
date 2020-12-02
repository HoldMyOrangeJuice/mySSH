import random
from EncLib import Encryption
from server import gather_bytes

ONETIME_KEY_LENGTH = 8
PROC_ID_LENGTH = 4
MAX_PACKET_COUNT_LENGTH = 2
FILESIZE = 8

PROCESS_PAYLOAD_LENGTH = None


def client(func):
    print(inspect.stack()[1].function)


class ProtocolManager:
    PREPARE_UPLOAD = "prepare_upload"
    PROCESS_PACKET = "process_packet"

    constants = {PREPARE_UPLOAD: 1,
                 PROCESS_PACKET: 2}

    protocols = {
        PREPARE_UPLOAD:
            [("filename", "string"), ("filesize", 8), ("chunksize", 2), ("pid", 4)],
        PROCESS_PACKET:
            [("index", ...), ("payload", ...), ("pid", 4)]
    }

    @classmethod
    def get_constant(cls, method):
        return cls.constants.get(method)

    @staticmethod
    def get_handler(constant):
        for key in ServerExecutor.constants.keys():
            if ServerExecutor.constants[key] == constant:
                return key

    @staticmethod
    def get_protocol(constant:int):
        return ProtocolManager.protocols.get(ProtocolManager.get_handler(constant))


# implementation
class CommandUnpacker:
    """ what this shit does is decrypts and unpacks command
     from bytes to human readable strings and ints """
    def __init__(self, args):
        # bytes
        self.raw_command = args

    def unpack(self, key, one_time):
        """ :return args, onetime key """
        header, args, onetime = self.decompress(self.decrypt(key, one_time))
        return header, args, onetime

    def decrypt(self, key, one_time):
        enc_lib = Encryption(key)
        enc_lib.modify_key("".join([chr(x) for x in one_time]))
        r = bytes(enc_lib.decrypt_bytes(self.raw_command))
        return r

    @staticmethod
    # a.k.a label args
    def decompress_with_protocol(protocol: list, data: bytearray):
        """ :returns dict of labeled args created with protocol """
        labeled_args = {}
        i = 0
        for name, size in protocol:
            if isinstance(size, str):
                string = ""
                while 1:
                    c = data[i]
                    if c == 0:
                        i += 1
                        break
                    i += 1
                    string += c
                labeled_args[name] = string
            if isinstance(size, int):
                num = gather_bytes(data[i: i+size])
                i += size
                labeled_args[name] = num

        return labeled_args, i

    @staticmethod
    def decompress(decrypted):
        header = decrypted[0]
        args, end_idx = CommandUnpacker.decompress_with_protocol(protocol=ProtocolManager.get_protocol(header),
                                                                 data=decrypted[1:])
        onetime_key = decrypted[end_idx:end_idx + ONETIME_KEY_LENGTH]
        return header, args, onetime_key


class BasicGenerator:

    @staticmethod
    def generate_otk(default=False):
        b = bytearray()
        for _ in range(ONETIME_KEY_LENGTH):
            b.append(random.randrange(256) if not default else 1)
        return b

    @staticmethod
    def generate_pid():
        return random.randrange(10000)


class Request:
    def __init__(self, header, **kwargs):
        """ :param kwargs args with names """
        self.header = header
        self.args = kwargs
        self.client_commands = ["skip"]

    def get_executor(self):
        return self.header

    @staticmethod
    def from_string(s):
        cmd_args = s.split(" ")
        return Request(header=ServerExecutor.get_constant(cmd_args[0]), args=cmd_args[1:])

    def client_sided(self):
        return self.get_executor() in self.client_commands


class CommandPacker:
    def __init__(self, command: Request, next_otk=ClientGenerator.generate_otk(default=False)):
        self.next_otk = next_otk
        self.request = command

    def pack(self, key, otk):
        return self.encrypt(self.compress(), key, otk=otk)

    def encrypt(self, compressed, key, otk):
        enc_lib = Encryption(key)
        enc_lib.modify_key("".join([chr(x) for x in otk]))
        return enc_lib.encrypt_bytes(compressed)

    def compress_with_protocol(self):
        protocol = ProtocolManager.get_protocol(ProtocolManager.get_constant(self.request.header))
        packed_args = bytearray()

        for arg in protocol:
            name, size = arg
            value = kwargs.get(name)
            if value is None:
                raise ValueError(f"argument {name} not specified in request of type {header}")

            if isinstance(size, str):
                buffer = bytearray()
                for c in value:
                    buffer.append(ord(c))
                buffer.append(0)
            else:
                buffer = split_to_bytes(value, size=size)

            packed_args.extend(buffer)
        return packed_args

    def compress(self):

        packed_args = self.compress_with_protocol()
        compressed_command = bytearray()

        compressed_command.append(self.request.header)
        compressed_command.extend(packed_args)
        compressed_command.extend(self.next_otk)

        return compressed_command


class CommandForServer:
    @abstract
    def pack(self, key, otk):
        raise NotImplementedError()


class ProcessManager:
    running_processes = []

    @staticmethod
    def add(pr: ContinuousProcess):
        running_processes.append(pr)

    @staticmethod
    def remove(pr: ContinuousProcess):
        running_processes.remove(pr)


class ContinuousProcess:
    def __init__(self, process_id):
        self.process_id = process_id
        self.total_packet_count = None
        self.progress = 0
        self.verified_progress = 0
        self.buffer = None
        ProcessManager.add(self)

    def end(self):
        ProcessManager.remove(self)


class UploadProcess(ContinuousProcess):
    def __init__(self, process_id):
        super().__init__(process_id)

    def send_chunk(self, i: int):
        pass


class DownloadProcess(ContinuousProcess):
    def __init__(self, process_id):
        super().__init__(process_id)

    def save_chunk(self, data, i):
        with open(self.buffer, "r+")as f:
            f.read()
            f.write(data)


@client
class PrepareUploadCommand(CommandForServer):

    def __init__(self, path, proc_id, chunk_size=2048):
        self.proc_id = proc_id
        self.chunk_size = chunk_size
        filename = os.path().split(path)[-1]
        filesize = os.path().get_size(path)
        req = Request(header=ServerExecutor.PREPARE_UPLOAD,
                      args=[filename, filesize, chunk_size, proc_id])
        self.command_packer = CommandPacker(req)

        UploadProcess(self.proc_id)

    def pack(self, key, otk):
        return self.command_packer.pack(key, otk)


class ProcessPacket(CommandForServer):
    """ this class represents packet with data of some continuous process
    that sends more than one packet. The thing about those is that it must have
    pid argument """
    def __init__(self, payload, proc_id, index=0):
        req = Request(header=ServerExecutor.PROCESS_PACKET, index=index, payload=payload, pid=proc_id)
        self.command_packer = CommandPacker(req)

    def pack(self, key, otk):
        return self.command_packer.pack(key, otk)


class PrepareDownloadProcess(CommandForServer):
    def __init__(self):
        pass
