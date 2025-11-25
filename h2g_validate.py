#!/usr/bin/env python3

import argparse
import os
import sys

import binascii

import pandas as pd
import numpy as np

import crcmod

_print_stuff = True

def print_ba(ba: bytearray) -> None:
    for i in range(0, len(ba), 8):
        chunk = ba[i:i+8]
        print(binascii.hexlify(chunk, ' ', 1).decode())
    print()

_print_stuff = False

class header_buffer_array:
    def __init__(self, estimated_size=0) -> None:
        self.buffer_pointer = 0

        self.packet_number = np.zeros(estimated_size, dtype=np.uint64)
        self.fpga_ip = np.zeros(estimated_size, dtype=np.uint8)
        self.fpga_port = np.zeros(estimated_size, dtype=np.uint8)
        self.udp_tx_counter = np.zeros(estimated_size, dtype=np.uint32)
        self.data_pointer = np.zeros(estimated_size, dtype=np.uint64)
        self.payloads_valid = np.zeros(estimated_size, dtype=np.int8)
        self.first_aa5a_position = np.zeros(estimated_size, dtype=np.int16)
        self.h1_count = np.zeros(estimated_size, dtype=np.int8)
        self.h2_count = np.zeros(estimated_size, dtype=np.int8)
        self.h3_count = np.zeros(estimated_size, dtype=np.int8)
        self.crc_count = np.zeros(estimated_size, dtype=np.int8)

    def build_dict(self) -> dict:
        return {
            'packet_number': self.packet_number[0:self.buffer_pointer],
            'fpga_ip': self.fpga_ip[0:self.buffer_pointer],
            'fpga_port': self.fpga_port[0:self.buffer_pointer],
            'udp_tx_counter': self.udp_tx_counter[0:self.buffer_pointer],
            'data_pointer': self.data_pointer[0:self.buffer_pointer],
            'payloads_valid': self.payloads_valid[0:self.buffer_pointer],
            'first_aa5a_position': self.first_aa5a_position[0:self.buffer_pointer],
            'h1_count': self.h1_count[0:self.buffer_pointer],
            'h2_count': self.h2_count[0:self.buffer_pointer],
            'h3_count': self.h3_count[0:self.buffer_pointer],
            'crc_count': self.crc_count[0:self.buffer_pointer]
        }

class payload_buffer_array:
    def __init__(self, estimated_size=0) -> None:
        self.buffer_pointer = 0

        self.packet_number = np.zeros(estimated_size, dtype=np.uint64)
        self.payload_number = np.zeros(estimated_size, dtype=np.uint8)
        self.magic_header = np.zeros(estimated_size, dtype=np.uint16)
        self.first_aa5a_position = np.zeros(estimated_size, dtype=np.int16)
        self.fpga_id = np.zeros(estimated_size, dtype=np.uint8)
        self.asic_id = np.zeros(estimated_size, dtype=np.uint8)
        self.payload_type = np.zeros(estimated_size, dtype=np.uint8)
        self.trigger_in_cnt = np.zeros(estimated_size, dtype=np.uint32)
        self.trigger_out_cnt = np.zeros(estimated_size, dtype=np.uint32)
        self.event_cnt = np.zeros(estimated_size, dtype=np.uint32)
        self.timestamp = np.zeros(estimated_size, dtype=np.uint64)
        self.data_h3 = np.zeros(estimated_size, dtype=np.uint8)
        self.data_h2 = np.zeros(estimated_size, dtype=np.uint8)
        self.data_h1 = np.zeros(estimated_size, dtype=np.uint8)
        self.data_crc = np.zeros(estimated_size, dtype=np.uint8)

    def build_dict(self) -> dict:
        return {
            'packet_number': self.packet_number[0:self.buffer_pointer],
            'payload_number': self.payload_number[0:self.buffer_pointer],
            'magic_header': self.magic_header[0:self.buffer_pointer],
            'first_aa5a_position': self.first_aa5a_position[0:self.buffer_pointer],
            'fpga_id': self.fpga_id[0:self.buffer_pointer],
            'asic_id': self.asic_id[0:self.buffer_pointer],
            'payload_type': self.payload_type[0:self.buffer_pointer],
            'trigger_in_cnt': self.trigger_in_cnt[0:self.buffer_pointer],
            'trigger_out_cnt': self.trigger_out_cnt[0:self.buffer_pointer],
            'event_cnt': self.event_cnt[0:self.buffer_pointer],
            'timestamp': self.timestamp[0:self.buffer_pointer],
            'data_h3': self.data_h3[0:self.buffer_pointer],
            'data_h2': self.data_h2[0:self.buffer_pointer],
            'data_h1': self.data_h1[0:self.buffer_pointer],
            'data_crc': self.data_crc[0:self.buffer_pointer]
        }


class h2g_validator:
    _packet_size = 1358
    _skip_lines = 25

    _f = None
    _f_size = 0

    _datapointer = 0

    _packet_max = -1

    # _crc_polynomial = 0x04C11DB7
    # _crc_func = crcmod.mkCrcFun(_crc_polynomial, initCrc=0x0, rev=False, xorOut=0x0)

    # _header_info = {'packet_number': np.array([], dtype=np.uint64), 'fpga_ip': np.array([], dtype=np.uint8), 'fpga_port': np.array([], dtype=np.uint8), 'udp_tx_counter': np.array([], dtype=np.uint32), 'data_pointer': np.array([], dtype=np.uint64)}
    # _payload_info = {'packet_number': np.array([], dtype=np.uint64), 'payload_number': np.array([], dtype=np.uint8), 'magic_header': np.array([], dtype=np.uint16), 'fpga_id': np.array([], dtype=np.uint8), 'asic_id': np.array([], dtype=np.uint8), 'payload_type': np.array([], dtype=np.uint8),
    #                  'trigger_in_cnt': np.array([], dtype=np.uint32),'trigger_out_cnt': np.array([], dtype=np.uint32), 'event_cnt': np.array([], dtype=np.uint32), 'timestamp': np.array([], dtype=np.uint64)}

    _global_dict = {'packet_count': 0, 'packet_count_ip': {208: 0, 209: 0}, 'aa5a_failures_ip': {208: 0, 209: 0}}

    _df_header = None
    _df_payload = None

    _interactive = False



    def __init__(self, file_path, out_folder='', interactive=False, pandas=False, pandas_payloads=False, packet_max=-1, skip_lines=25) -> None:
        self._file_path = file_path
        self._out_folder = out_folder
        self._interactive = interactive
        self._pandas = pandas
        self._pandas_payloads = pandas_payloads
        self._packet_max = packet_max
        self._f_size = os.path.getsize(file_path)
        self._f =  open(file_path, "rb")
        
        for _ in range(self._skip_lines):
            __ = self._f.readline()
        self._datapointer = self._f.tell()
        print(f'datapointer after skipping header: {self._datapointer}')

        est_n_packets = (self._f_size - self._datapointer) // self._packet_size + 1
        est_n_payloads = est_n_packets * 7
        self._header_buffer = header_buffer_array(est_n_packets)
        self._payload_buffer = payload_buffer_array(est_n_payloads)

    def validate_h2g_file(self) -> None:
        print("Starting H2G file validation...")
        print('      ', end='', flush=True)
        chunk_size = 10 * 1024 * 1024  # 10 MB
        while True:
            if (self._packet_max) and (self._global_dict['packet_count'] >= self._packet_max):
                print(f"\nReached maximum packet limit of {self._packet_max}. Stopping processing.")
                break

            print(f'\b\b\b\b\b\b{100*self._datapointer/self._f_size:5.2f}%', flush=True, end ='')
            self._f.seek(self._datapointer)
            chunk = self._f.read(chunk_size)
            if not chunk:
                print(f"End of file reached.")
                break
            
            # Process multiple packets from chunk
            for i in range(0, len(chunk) - self._packet_size + 1, self._packet_size):
                
                packet = chunk[i:i+self._packet_size]
                self.parse_packet(bytearray(packet))

                
                

                self._global_dict['packet_count'] += 1
                self._global_dict['packet_count_ip'][self._header_buffer.fpga_ip[self._header_buffer.buffer_pointer-1]] += 1
                if self._header_buffer.first_aa5a_position[self._header_buffer.buffer_pointer-1] != 0:
                    self._global_dict['aa5a_failures_ip'][self._header_buffer.fpga_ip[self._header_buffer.buffer_pointer-1]] += 1

                self._datapointer += self._packet_size
            # End of processing packets in chunk

        
        print()
        print("H2G file parsing completed.")
        print(f'Total packets processed:')
        print(f"{self._global_dict['packet_count']} ")

        if self._pandas:
            self._df_header = pd.DataFrame(self._header_buffer.build_dict())

            if self._out_folder == '':
                _df_header_path = self._file_path + "_header_info.pkl"
            else:
                _df_header_path = os.path.join(self._out_folder, os.path.basename(self._file_path)) + "_header_info.pkl"
            
            self._df_header.to_pickle(_df_header_path)
            print(f"Header information saved to { _df_header_path }")

        if self._pandas_payloads:


            self._df_payload = pd.DataFrame(self._payload_buffer.build_dict())
            if self._out_folder == '':
                _df_payload_path = self._file_path + "_payload_info.pkl"
            else:
                _df_payload_path = os.path.join(self._out_folder, os.path.basename(self._file_path)) + "_payload_info.pkl"

            self._df_payload.to_pickle(_df_payload_path)
            print(f"Payload information saved to { _df_payload_path }")

        return self._global_dict

    def parse_packet(self, packet: bytearray) -> None:
        header = packet[0:14]

        
        payloads = [packet[14+i*192:14+(i+1)*192] for i in range(7)]

        for ipayload, payload in enumerate(payloads):
            self.parse_payload(payload, ipayload)

        self.parse_header(header)
        self._header_buffer.first_aa5a_position[self._header_buffer.buffer_pointer] = self._payload_buffer.first_aa5a_position[self._payload_buffer.buffer_pointer] # first payload only
        
        # n_payloads_valid is either sum of non-padding payloads valid or -1 if any payload is invalid
        n_payloads_valid = sum([self._payload_buffer.magic_header[self._payload_buffer.buffer_pointer + ipayload] == 0xAA5A for ipayload in range(7)]) if -1 not in [self._payload_buffer.magic_header[self._payload_buffer.buffer_pointer + ipayload] for ipayload in range(7)] else -1
        h1_count = sum([self._payload_buffer.data_h1[self._payload_buffer.buffer_pointer + ipayload] for ipayload in range(7)])
        h2_count = sum([self._payload_buffer.data_h2[self._payload_buffer.buffer_pointer + ipayload] for ipayload in range(7)])
        h3_count = sum([self._payload_buffer.data_h3[self._payload_buffer.buffer_pointer + ipayload] for ipayload in range(7)])
        crc_count = sum([self._payload_buffer.data_crc[self._payload_buffer.buffer_pointer + ipayload] for ipayload in range(7)])

        self._header_buffer.payloads_valid[self._header_buffer.buffer_pointer] = n_payloads_valid
        self._header_buffer.h1_count[self._header_buffer.buffer_pointer] = h1_count
        self._header_buffer.h2_count[self._header_buffer.buffer_pointer] = h2_count
        self._header_buffer.h3_count[self._header_buffer.buffer_pointer] = h3_count
        self._header_buffer.crc_count[self._header_buffer.buffer_pointer] = crc_count

        self._header_buffer.buffer_pointer += 1
        self._payload_buffer.buffer_pointer += 7

    def parse_header(self, header: bytearray) -> {}:
        udp_tx_counter = int.from_bytes(header[0:4], byteorder='big')
        fpga_ip = header[4]
        fpga_port = header[5]

        self._header_buffer.udp_tx_counter[self._header_buffer.buffer_pointer] = udp_tx_counter
        self._header_buffer.fpga_ip[self._header_buffer.buffer_pointer] = fpga_ip
        self._header_buffer.fpga_port[self._header_buffer.buffer_pointer] = fpga_port
        self._header_buffer.data_pointer[self._header_buffer.buffer_pointer] = self._datapointer
        self._header_buffer.packet_number[self._header_buffer.buffer_pointer] = self._global_dict['packet_count']
        

    def parse_payload(self, payload: bytearray, ipayload: int) -> {}:
        first_aa5a_position = payload.find(b'\xAA\x5A')

        magic_header = payload[0:2]

        allowed_magic_headers = [b'\xAA\x5A', b'\x00\x00'] if ipayload > 0 else [b'\xAA\x5A']

        if not (magic_header in allowed_magic_headers):
            if self._interactive:
                print()
                print("Invalid magic header in payload ", ipayload, " ", magic_header, ' packet: ', self._global_dict['packet_count'], ' data pointer: ', self._datapointer)
                
                # print()
                # print("pre-payload:")
                # self._datapointer -= self._packet_size
                # self._f.seek(self._datapointer+14+ipayload*192 - 32)
                # print_ba(self._f.read(32))
                # print("payload:")
                # print_ba(self._f.read(192))
                # print("post-payload:")
                # self._f.seek(self._datapointer+14+(ipayload+1)*192)
                # print_ba(self._f.read(32))

                # self._datapointer += self._packet_size
                
                print()
                print()
                print("pre-payload:")
                self._f.seek(self._datapointer+14+ipayload*192 - 32)
                print_ba(self._f.read(32))
                print("payload:")
                print_ba(payload)
                print("post-payload:")
                self._f.seek(self._datapointer+14+(ipayload+1)*192)
                print_ba(self._f.read(32))
                
                _ = input("Press Enter to continue...")

        if magic_header == b'\xAA\x5A':
            payload_valid = 1
        elif magic_header == b'\x00\x00':
            payload_valid = 0
        else:
            payload_valid= -1


        fpga_id = payload[2] >> 4
        asic_id = payload[2] & 0xF
        payload_type = payload[3]
        trigger_in_cnt = int.from_bytes(payload[4:8], byteorder='big')
        trigger_out_cnt = int.from_bytes(payload[8:12], byteorder='big')
        event_cnt = int.from_bytes(payload[12:16], byteorder='big')
        timestamp = int.from_bytes(payload[16:24], byteorder='big')
        reserved = payload[24:32]
        data = payload[32:192]

        data_daqh = int.from_bytes(data[0:4], byteorder='big')
        data_h3 = data_daqh >> 4 & 0x1
        data_h2 = data_daqh >> 5 & 0x1
        data_h1 = data_daqh >> 6 & 0x1

        self._payload_buffer.packet_number[self._payload_buffer.buffer_pointer + ipayload] = self._global_dict['packet_count']
        self._payload_buffer.payload_number[self._payload_buffer.buffer_pointer + ipayload] = ipayload
        self._payload_buffer.magic_header[self._payload_buffer.buffer_pointer + ipayload] = int.from_bytes(magic_header, byteorder='big')
        self._payload_buffer.first_aa5a_position[self._payload_buffer.buffer_pointer + ipayload] = first_aa5a_position
        self._payload_buffer.fpga_id[self._payload_buffer.buffer_pointer + ipayload] = fpga_id
        self._payload_buffer.asic_id[self._payload_buffer.buffer_pointer + ipayload] = asic_id
        self._payload_buffer.payload_type[self._payload_buffer.buffer_pointer + ipayload] = payload_type
        self._payload_buffer.trigger_in_cnt[self._payload_buffer.buffer_pointer + ipayload] = trigger_in_cnt
        self._payload_buffer.trigger_out_cnt[self._payload_buffer.buffer_pointer + ipayload] = trigger_out_cnt
        self._payload_buffer.event_cnt[self._payload_buffer.buffer_pointer + ipayload] = event_cnt
        self._payload_buffer.timestamp[self._payload_buffer.buffer_pointer + ipayload] = timestamp
        self._payload_buffer.data_h3[self._payload_buffer.buffer_pointer + ipayload] = data_h3
        self._payload_buffer.data_h2[self._payload_buffer.buffer_pointer + ipayload] = data_h2
        self._payload_buffer.data_h1[self._payload_buffer.buffer_pointer + ipayload] = data_h1
        self._payload_buffer.data_crc[self._payload_buffer.buffer_pointer + ipayload] = 0  # Placeholder for CRC check result


    


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate H2G files")
    parser.add_argument("file_path", type=str, help="Path to the H2G file")
    parser.add_argument("--out-folder", type=str, default='', help="Output folder for results")
    parser.add_argument("--interactive", action='store_true', help="Enable interactive mode for detailed output on error")
    parser.add_argument("--pandas", action='store_true', help="Output pandas DataFrame header info pickles")
    parser.add_argument("--pandas-payloads", action='store_true', help="Output pandas DataFrame payload info pickles")
    parser.add_argument("--max-packets", type=int, help="maximum number of packets to process")
    parser.add_argument("--skip-lines", type=int, default=25, help="number of header lines to skip in the H2G file")
    
    args = parser.parse_args()
    
    val = h2g_validator(args.file_path, 
                        args.out_folder, 
                        args.interactive, 
                        args.pandas, 
                        args.pandas_payloads, 
                        args.max_packets, 
                        args.skip_lines)

    r = val.validate_h2g_file()
    print('packets total:')
    print(r['packet_count'])
    print(f'packets by ip:')
    print(f'{208:8d}\t{209:8d}')
    print(f"{r['packet_count_ip'][208]:8d}\t{r['packet_count_ip'][209]:8d}")
    print(f"{r['aa5a_failures_ip'][208]:8d}\t{r['aa5a_failures_ip'][209]:8d}")
    print(f"{r['aa5a_failures_ip'][208]/r['packet_count_ip'][208]*100:8.2f}%\t{r['aa5a_failures_ip'][209]/r['packet_count_ip'][209]*100:8.2f}%")

    #    _global_dict = {'packet_count': 0, 'packet_count_ip': {208: 0, 209: 0}, 'aa5a_failures_ip': {208: 0, 209: 0}}

    sys.exit(0)

