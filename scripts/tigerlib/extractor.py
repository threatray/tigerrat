import re
import io
import sys
import struct
import pefile
import base64 as b64
from capstone import *
from Crypto.Cipher import DES


class Extractor(object):
    def __init__(self, filename):
        with open(filename, 'rb') as f:
            self.data = f.read()

    def detect(self):
        raise Exception('it must be implemented by child class')

    def extract(self):
        raise Exception('it must be implemented by child class')


class ExtractorSecondStage(Extractor):
    def decrypt_string(self, enc_string):
        string = ''
        decode = b64.b64decode(enc_string)
        decode_len = len(decode)
        eax = 0x57219043
        r11b = 0x84
        r9 = 0x9A9A2C2

        for i in decode:
            cl = i
            al = eax & 0xFF
            r9b = r9 & 0xFF
            r9d = r9 & 0xFFFFFFFF
            cl = (((cl ^ r9b) ^ al) ^ r11b)
            string += chr(cl)
            cl = al & r11b
            dl = (al ^ r11b) & r9b
            r11b = dl ^ cl
            r9 = (((((r9 * 8) ^ r9d) & 0x7F8) << 0x14) | (r9d >> 0x8) ) & 0xFFFFFFFF
            eax = ((((((((eax * 2) ^ eax) << 4 ) ^ eax) & 0xFFFFFF80) ^ (eax << 7)) << 0x11) | (eax >> 0x8)) & 0xFFFFFFFF

        return string

    def detect(self):
        return True if re.search(br'(bYR\+[a-zA-Z0-9/\+=]+)', self.data) else False

    def extract(self):
        config = {}
        cncs = []
        aux_data = self.data
        match = re.search(br'(bYR\+[a-zA-Z0-9/\+=]+)', aux_data)
        while match:
            panel = self.decrypt_string(match.groups()[0])
            cncs.append(panel)
            aux_data = aux_data[match.end():]
            match = re.search(br'(bYR\+[a-zA-Z0-9/\+=]+)', aux_data)

        config['cncs'] = cncs
        return config


class ExtractorThirdStagex64(Extractor):
    DETECTION_PATTERN = br'\x48\x89\x5E\x18\xC7\x45.....\xC7\x45......{2,3}\x08'
    DES_KEY_PATTERN = br'\x48\x89\x5E\x18\xC7\x45.(....)\xC7\x45.(....).{2,3}\x08'
    CNCS_PATTERN = br'\x41\xB8([\x10\x18])\x00\x00\x00\x48..(....).{4,15}\x48\x89'

    def detect(self):
        return True if re.search(self.DETECTION_PATTERN, self.data) else False

    def get_des_key(self):
        chunk1, chunk2 = re.search(self.DES_KEY_PATTERN, self.data).groups()
        return chunk1 + chunk2

    def get_rc4_key(self):
        match = re.search(br'\x48\x89\x5E\x10\xC7\x45.(....)', self.data)
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        key = b''
        for i in md.disasm(self.data[match.start():], 0x100):
            if i.mnemonic != 'mov':
                break
            candidate = i.op_str.split(', ')[1]
            try:
                literal = int(candidate, 16)
            except:
                continue
            if 'ecx' in i.op_str:
                key_size = literal
            key += struct.pack("=L", literal)
        return key[:key_size]

    def decrypt_string(self, enc_string):
        if not self.key:
            self.key = self.get_des_key()
        cipher = DES.new(self.key, DES.MODE_ECB)
        return cipher.decrypt(enc_string)
    
    def get_ips(self, data, variant):
        ips = []
        stream = io.BytesIO(data)
        ip = self.decrypt_string(stream.read(0x10 if variant == 0x10 else 0x18))
        ip = ip.split(b'\x00')[0]
        ips.append(ip.decode('utf-8'))
        ip = self.decrypt_string(stream.read(0x10 if variant == 0x10 else 0x18))
        ip = ip.split(b'\x00')[0]
        ips.append(ip.decode('utf-8'))
        ip = self.decrypt_string(stream.read(0x08))
        ip = ip.split(b'\x00')[0]
        ips.append(ip.decode('utf-8'))
        ip = self.decrypt_string(stream.read(0x10))
        ip = ip.split(b'\x00')[0]
        ips.append(ip.decode('utf-8'))
        return ips

    def get_ips_offset(self, match):
        pe = pefile.PE(data=self.data)
        rva = struct.unpack("=L", match.groups()[1])[0] 

        start = match.start() + 6 
        return pe.get_offset_from_rva(pe.get_rva_from_offset(start) + rva + 7)

    def extract(self):
        self.key = self.get_des_key()
        match = re.search(self.CNCS_PATTERN, self.data)
        enc_string_offset = self.get_ips_offset(match) 
        variant = struct.unpack("B", match.groups()[0])[0]

        config = {}
        config['ips'] = self.get_ips(self.data[enc_string_offset:], variant)
        config['des_key'] = self.key
        config['rc4_key'] = self.get_rc4_key()
        return config 


class ExtractorThirdStagex86(ExtractorThirdStagex64):
    DETECTION_PATTERN = br'\x89\x7E\x0C.{,4}\xC7\x45.....\xC7\x45......{2,3}\x08'
    DES_KEY_PATTERN = br'\x89\x7E\x0C.{,4}\xC7\x45.(....)\xC7\x45.(....).{2,3}\x08'
    CNCS_PATTERN = br'\x6A([\x10\x18])\x68(....)\x8B.\x8B..\xFF'

    def get_rc4_key(self):
        match = re.search(br'\x89\x7E\x08\x6A.\xC7\x45.(....)', self.data)
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        key = b''
        for i in md.disasm(self.data[match.start():], 0x100):
            if i.mnemonic == 'call':
                break
            if 'push' in i.mnemonic:
                key_size = int(i.op_str, 16)
                continue
            candidate = i.op_str.split(', ')[1]
            try:
                literal = int(candidate, 16)
            except:
                continue
            key += struct.pack("=L", literal)
        return key[:key_size]

    def get_ips_offset(self, match):
        pe = pefile.PE(data=self.data)
        offset = struct.unpack("=L", match.groups()[1])[0] 
        return pe.get_offset_from_rva(offset - pe.OPTIONAL_HEADER.ImageBase)


class ExtractorFactory(object):
    EXTRACTORS = [
        ExtractorSecondStage,
        ExtractorThirdStagex64,
        ExtractorThirdStagex86,
    ]

    def get_extractor(self, filename):
        for cls in self.EXTRACTORS:
            instance = cls(filename)
            if instance.detect():
                return instance
        raise Exception(f'Could not get an extractor for {filename}')
