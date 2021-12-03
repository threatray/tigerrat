import io
import struct
import pefile
import string
import base64 as b64
import binascii


class AndarielAPTUnpacker(object):
    def __init__(self, filename):
        self.pe = pefile.PE(filename)
        self.file_size = len(self.pe.write())
        self.xor_key = None
        self.encoding = None

    def get_pe_file_size(self):
        pointer_to_raw_data = 0
        size_of_raw_data = 0
        for section in self.pe.sections:
            if section.PointerToRawData > pointer_to_raw_data:
                pointer_to_raw_data = section.PointerToRawData
                size_of_raw_data = section.SizeOfRawData

        return pointer_to_raw_data + size_of_raw_data

    def get_last_section(self):
        for section in self.pe.sections:
            continue
        section_name = section.Name.decode().replace('\x00', '')
        section_data = self.pe.write()[section.PointerToRawData: section.PointerToRawData + section.SizeOfRawData]
        return section_name, section_data

    def get_key_from_resource(self, resource):
        size = resource.directory.entries[0].data.struct.Size
        offset = resource.directory.entries[0].data.struct.OffsetToData
        data = io.BytesIO(self.pe.get_data(offset, size))
        data.read(0x50)
        data_size = struct.unpack("=L", data.read(4))[0]
        unknown1 = struct.unpack("=L", data.read(4))[0]
        unknown2 = struct.unpack("=L", data.read(4))[0]
        xor_key = data.read(16)
        return xor_key

    def load_from_section(self):
        last_section_name, last_section_data = self.get_last_section()
        buff_stream = io.BytesIO(last_section_data)
        data_size = struct.unpack('=L', buff_stream.read(4))[0]
        xor_key = buff_stream.read(16)
        data = buff_stream.read(data_size) 
        garbage = buff_stream.read()
        return xor_key, data

    def load_from_overlay(self):
        overlay = self.pe.get_overlay()
        buff_stream = io.BytesIO(overlay)
        data_size = struct.unpack('=L', buff_stream.read(4))[0]
        xor_key = buff_stream.read(16)
        buff_stream.read(1)
        data = buff_stream.read(data_size) 
        garbage = buff_stream.read()
        return xor_key, data

    def load_from_resources(self):
        data = bytearray()
        xor_key = None
        for rsrc in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if len(rsrc.directory.entries) < 5:
                continue
            resources = rsrc.directory.entries
            resources.sort(key=lambda a: a.id)
            xor_key = self.get_key_from_resource(resources[0])
            for entry in resources[1:]:
                size = entry.directory.entries[0].data.struct.Size
                offset = entry.directory.entries[0].data.struct.OffsetToData
                data += self.pe.get_data(offset, size)
        return xor_key, data

    def load_encrypted_payload(self):
        last_section_name, last_section_data = self.get_last_section()

        if self.pe.get_overlay() and len(self.pe.get_overlay()) > 0x1000:
            xor_key, data = self.load_from_overlay()
            self.payload_location = 'overlay'
        elif last_section_name != '.reloc':
            xor_key, data = self.load_from_section()
            self.payload_location = f'section({last_section_name})'
        else:
            xor_key, data = self.load_from_resources()
            self.payload_location = 'resources'

        return xor_key, data

    def decrypt_payload(self, data):
        for i in range(len(data)):
            data[i] = data[i] ^ self.xor_key[i % (len(self.xor_key) - 1) ] # possible bug they hardcoded this value to 15 but the key len is 16 that's why I substract 1

        return data

    # To study the garbage there are some dates in some samples
    def unpack(self):
        self.xor_key, data = self.load_encrypted_payload()
        #pe_size = self.get_pe_file_size()
        data = data.strip(b'\x00')
        if all(chr(char) in string.printable for char in data):
            try:
                decoded_data = bytearray(b64.b64decode(data))
            except binascii.Error:
                decoded_data = bytearray(b64.b64decode(data + b'='))
            self.encoding = 'Base64'
        else:
            decoded_data = bytearray(data)

        return self.decrypt_payload(decoded_data)
