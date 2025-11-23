#!/usr/bin/env python3

import argparse
import os
import sys

import binascii

import pandas as pd

def print_ba(ba: bytearray) -> None:
    for i in range(0, len(ba), 8):
        chunk = ba[i:i+8]
        print(binascii.hexlify(chunk, ' ', 1).decode())
    print()

_print_stuff = False

class h2g_validator:
    _packet_size = 1358
    _skip_lines = 25

    _packet_count = 0
    
    _f = None
    _f_size = 0
    _datapointer = 0

    _packet_max = -1

    _header_info = {'packet_number': [], 'fpga_ip': [], 'fpga_port': [], 'udp_tx_counter': [], 'data_pointer': []}
    _payload_info = {'packet_number': [], 'payload_number': [], 'magic_header': [], 'fpga_id': [], 'asic_id': [], 'payload_type': [],
                     'trigger_in_cnt': [],'trigger_out_cnt': [], 'event_cnt': [], 'timestamp': []}

    _df_header = None
    _df_payload = None

    _interactive = False

    def __init__(self, file_path: str, debuglevel: int = 0, interactive: bool = False, pandas: bool = False) -> None:
        self.file_path = file_path
        self.debuglevel = debuglevel
        self._interactive = interactive
        self._pandas = pandas
        self._f_size = os.path.getsize(file_path)
        self._f =  open(file_path, "rb")
        for _ in range(self._skip_lines):
            __ = self._f.readline()
        self._datapointer = self._f.tell()

    def validate_h2g_file(self) -> None:
        print("Starting H2G file validation...")
        print('      ', end='', flush=True)
        while True:
            if self._packet_count % 10000 == 0:
                print(f'\b\b\b\b\b\b{100*self._datapointer/self._f_size:5.2f}%', flush=True, end ='')
            self._f.seek(self._datapointer)
            packet = bytearray(self._f.read(self._packet_size))
            

            if not packet:
                print(f"End of file reached. Total chunks processed: {self._packet_count}. No issues found.")
                break
            if len(packet) != self._packet_size:
                print(f"Invalid chunk size at end of file: {len(packet)} bytes (expected {self._packet_size} bytes)")
                break

            self.parse_packet(bytearray(packet))

            self._packet_count += 1
            self._datapointer += self._packet_size

        if self._pandas:
            self._df_header = pd.DataFrame(self._header_info)
            _df_header_path = self.file_path + "_header_info.pkl"
            self._df_header.to_pickle(_df_header_path)
            print(f"Header information saved to { _df_header_path }")
            
            self._df_payload = pd.DataFrame(self._payload_info)
            _df_payload_path = self.file_path + "_payload_info.pkl"
            self._df_payload.to_pickle(_df_payload_path)
            print(f"Payload information saved to { _df_payload_path }")

    def parse_packet(self, packet: bytearray) -> None:
        header = packet[0:14]

        if _print_stuff:
            print_ba(header)

        payloads = [packet[14+i*192:14+(i+1)*192] for i in range(7)]

        self.parse_header(header)
        for ipayload, payload in enumerate(payloads):
            self.parse_payload(payload, ipayload)   

    def parse_header(self, header: bytearray) -> None:
        udp_tx_counter = int.from_bytes(header[0:4], byteorder='big')
        fpga_ip = header[5]
        fpga_port = header[6]
        
        if _print_stuff:
            print(f"UDP TX Counter: {udp_tx_counter}")
            print(f"FPGA IP: {fpga_ip}")
            print(f"FPGA Port: {fpga_port}")
            print()

        if self._pandas:
            self._header_info['packet_number'].append(self._packet_count)
            self._header_info['udp_tx_counter'].append(udp_tx_counter)
            self._header_info['fpga_ip'].append(fpga_ip)
            self._header_info['fpga_port'].append(fpga_port)
            self._header_info['data_pointer'].append(self._datapointer)

    def parse_payload(self, payload: bytearray, ipayload: int) -> None:
        
        if _print_stuff:
            print_ba(payload)

        magic_header = payload[0:2]
        if not ((magic_header == b'\xAA\x5A') or (magic_header == b'\x00\x00')):
            print()
            print("Invalid magic header in payload ", ipayload, " ", magic_header, ' packet: ', self._packet_count, ' data pointer: ', self._datapointer)
            
            print()
            print("pre-payload:")
            self._f.seek(self._datapointer+14+ipayload*192 - 32)
            print_ba(self._f.read(32))
            print("payload:")
            print_ba(payload)
            print("post-payload:")
            self._f.seek(self._datapointer+14+(ipayload+1)*192)
            print_ba(self._f.read(32))
            if self._interactive:
                _ = input("Press Enter to continue...")
            else:
                sys.exit(1)
        fpga_id = payload[2] >> 4
        asic_id = payload[2] & 0xF
        payload_type = payload[3]
        trigger_in_cnt = int.from_bytes(payload[4:8], byteorder='big')
        trigger_out_cnt = int.from_bytes(payload[8:12], byteorder='big')
        event_cnt = int.from_bytes(payload[12:16], byteorder='big')
        timestamp = int.from_bytes(payload[16:24], byteorder='big')
        reserved = payload[24:32]
        data = payload[32:192]
        if _print_stuff:
            print(f"magic_header: {binascii.hexlify(magic_header).decode()}")
            print(f"FPGA ID: {fpga_id}")
            print(f"ASIC ID: {asic_id}")
            print(f"Payload Type: {payload_type}")
            print(f"Trigger In Count: {trigger_in_cnt}")
            print(f"Trigger Out Count: {trigger_out_cnt}")
            print(f"Event Count: {event_cnt}")
            print(f"Timestamp: {timestamp}")
            print(f"Reserved: {binascii.hexlify(reserved).decode()}")
            print()

        if self._pandas:
            self._payload_info['packet_number'].append(self._packet_count)
            self._payload_info['payload_number'].append(ipayload)
            self._payload_info['magic_header'].append(binascii.hexlify(magic_header).decode())
            self._payload_info['fpga_id'].append(fpga_id)
            self._payload_info['asic_id'].append(asic_id)
            self._payload_info['payload_type'].append(payload_type)
            self._payload_info['trigger_in_cnt'].append(trigger_in_cnt)
            self._payload_info['trigger_out_cnt'].append(trigger_out_cnt)
            self._payload_info['event_cnt'].append(event_cnt)
            self._payload_info['timestamp'].append(timestamp)


    


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate H2G files")
    parser.add_argument("file_path", type=str, help="Path to the H2G file")
    parser.add_argument("--debuglevel", type=int, default=0, help="Set the debug level (default: 0)")
    parser.add_argument("--interactive", action='store_true', help="Enable interactive mode for detailed output on error")
    parser.add_argument("--pandas", action='store_true', help="Output pandas DataFrame pickles")
    args = parser.parse_args()
    
    val = h2g_validator(args.file_path, args.debuglevel, args.interactive, args.pandas)
    val.validate_h2g_file()
    sys.exit(0)

        