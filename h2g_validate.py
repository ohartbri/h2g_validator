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

    _header_dict = {'packet_number': [], 'fpga_ip': [], 'fpga_port': [], 'udp_tx_counter': [], 'data_pointer': [], 'payloads_valid': [], 'first_aa5a_position': [],'h1_count': [], 'h2_count': [], 'h3_count': [], 'crc_count': []}
    _payload_dict = {'packet_number': [], 'payload_number': [], 'magic_header': [], 'payload_valid': [], 'aa5a_position': [], 'fpga_id': [], 'asic_id': [], 'payload_type': [],
                     'trigger_in_cnt': [],'trigger_out_cnt': [], 'event_cnt': [], 'timestamp': [], 'data_h3': [], 'data_h2': [], 'data_h1': [], 'data_crc': []}

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

    def validate_h2g_file(self) -> None:
        print("Starting H2G file validation...")
        print('      ', end='', flush=True)
        chunk_size = 100 * 1024 * 1024  # 10 MB
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
            if len(chunk) < self._packet_size:
                print(f"\nRemaining chunk size {len(chunk)} bytes is smaller than packet size {self._packet_size} bytes. Stopping processing.")
                break
            for i in range(0, len(chunk) - self._packet_size + 1, self._packet_size):
                
                packet = chunk[i:i+self._packet_size]
                header_content, payload_contents = self.parse_packet(bytearray(packet))

                header_content['packet_number'] = self._global_dict['packet_count']
                for payload in payload_contents:
                    payload['packet_number'] = self._global_dict['packet_count']
                

                self._global_dict['packet_count'] += 1
                this_fpga_ip = header_content['fpga_ip']
                if this_fpga_ip not in self._global_dict['packet_count_ip']:
                    self._global_dict['packet_count_ip'][this_fpga_ip] = 0
                    self._global_dict['aa5a_failures_ip'][this_fpga_ip] = 0
                self._global_dict['packet_count_ip'][this_fpga_ip] += 1
                if header_content['first_aa5a_position'] != 0:
                    self._global_dict['aa5a_failures_ip'][this_fpga_ip] += 1

                self._datapointer += self._packet_size

                if self._pandas:
                    for key, value in header_content.items():
                        self._header_dict[key].append(value)
                if self._pandas_payloads:   
                    for payload_content in payload_contents:
                        for key, value in payload_content.items():
                            self._payload_dict[key].append(value)


        
        print()
        print("H2G file parsing completed.")
        print(f'Total packets processed:')
        print(f"{self._global_dict['packet_count']} ")

        if self._pandas:
            self._header_dict['packet_number'] = np.array(self._header_dict['packet_number'], dtype=np.uint64)
            self._header_dict['fpga_ip'] = np.array(self._header_dict['fpga_ip'], dtype=np.uint8)
            self._header_dict['fpga_port'] = np.array(self._header_dict['fpga_port'], dtype=np.uint8)
            self._header_dict['udp_tx_counter'] = np.array(self._header_dict['udp_tx_counter'], dtype=np.uint32)
            self._header_dict['data_pointer'] = np.array(self._header_dict['data_pointer'], dtype=np.uint64)
            self._header_dict['payloads_valid'] = np.array(self._header_dict['payloads_valid'], dtype=np.int8)
            self._header_dict['first_aa5a_position'] = np.array(self._header_dict['first_aa5a_position'], dtype=np.int16)
            self._header_dict['h1_count'] = np.array(self._header_dict['h1_count'], dtype=np.int8)
            self._header_dict['h2_count'] = np.array(self._header_dict['h2_count'], dtype=np.int8)
            self._header_dict['h3_count'] = np.array(self._header_dict['h3_count'], dtype=np.int8)
            self._header_dict['crc_count'] = np.array(self._header_dict['crc_count'], dtype=np.int8)
            self._df_header = pd.DataFrame(self._header_dict)
            
            
            if self._out_folder == '':
                _df_header_path = self._file_path + "_header_info.pkl"
            else:
                _df_header_path = os.path.join(self._out_folder, os.path.basename(self._file_path)) + "_header_info.pkl"
            
            self._df_header.to_pickle(_df_header_path)
            print(f"Header information saved to { _df_header_path }")

        if self._pandas_payloads:
            self._payload_dict['packet_number'] = np.array(self._payload_dict['packet_number'], dtype=np.uint64)
            self._payload_dict['payload_number'] = np.array(self._payload_dict['payload_number'], dtype=np.uint8)
            self._payload_dict['payload_valid'] = np.array(self._payload_dict['payload_valid'], dtype=np.int8)
            self._payload_dict['magic_header'] = np.array(self._payload_dict['magic_header'], dtype=np.uint16)
            self._payload_dict['fpga_id'] = np.array(self._payload_dict['fpga_id'], dtype=np.uint8)
            self._payload_dict['asic_id'] = np.array(self._payload_dict['asic_id'], dtype=np.uint8)
            self._payload_dict['payload_type'] = np.array(self._payload_dict['payload_type'], dtype=np.uint8)
            self._payload_dict['trigger_in_cnt'] = np.array(self._payload_dict['trigger_in_cnt'], dtype=np.uint32)
            self._payload_dict['trigger_out_cnt'] = np.array(self._payload_dict['trigger_out_cnt'], dtype=np.uint32)
            self._payload_dict['event_cnt'] = np.array(self._payload_dict['event_cnt'], dtype=np.uint32)
            self._payload_dict['timestamp'] = np.array(self._payload_dict['timestamp'], dtype=np.uint64)
            self._payload_dict['data_h3'] = np.array(self._payload_dict['data_h3'], dtype=np.uint8)
            self._payload_dict['data_h2'] = np.array(self._payload_dict['data_h2'], dtype=np.uint8)
            self._payload_dict['data_h1'] = np.array(self._payload_dict['data_h1'], dtype=np.uint8)
            self._payload_dict['data_crc'] = np.array(self._payload_dict['data_crc'], dtype=np.uint8)



            self._df_payload = pd.DataFrame(self._payload_dict)
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

        payload_contents = [self.parse_payload(payload, ipayload) for ipayload, payload in enumerate(payloads)]\

        header_content = self.parse_header(header)
        header_content['first_aa5a_position'] = payload_contents[0]['aa5a_position']
        
        # n_payloads_valid is either sum of non-padding payloads valid or -1 if any payload is invalid
        n_payloads_valid = sum([payload_content['payload_valid'] for payload_content in payload_contents]) if -1 not in [payload_content['payload_valid'] for payload_content in payload_contents] else -1
        header_content['payloads_valid'] = sum([payload_content['payload_valid'] for payload_content in payload_contents])
        header_content['h1_count'] = sum([payload_content['data_h1'] for payload_content in payload_contents])
        header_content['h2_count'] = sum([payload_content['data_h2'] for payload_content in payload_contents])
        header_content['h3_count'] = sum([payload_content['data_h3'] for payload_content in payload_contents])
        header_content['crc_count'] = sum([payload_content['data_crc'] for payload_content in payload_contents])

        

        return header_content, payload_contents

    def parse_header(self, header: bytearray) -> {}:
        udp_tx_counter = int.from_bytes(header[0:4], byteorder='big')
        fpga_ip = header[4]
        fpga_port = header[5]

        return {'udp_tx_counter': udp_tx_counter,
                'fpga_ip': fpga_ip,
                'fpga_port': fpga_port,
                'data_pointer': self._datapointer}

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

        return {'payload_number': ipayload,
                'payload_valid': payload_valid,
                'magic_header': magic_header,
                'aa5a_position': first_aa5a_position,
                'fpga_id': fpga_id,
                'asic_id': asic_id,
                'payload_type': payload_type,
                'trigger_in_cnt': trigger_in_cnt,
                'trigger_out_cnt': trigger_out_cnt,
                'event_cnt': event_cnt,
                'timestamp': timestamp,
                #'reserved': binascii.hexlify(reserved).decode(),
                #'data': data
                'data_h3': data_h3,
                'data_h2': data_h2,
                'data_h1': data_h1,
                'data_crc': 0,
                }



    


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

    ips_seen = [ip for ip, count in r['packet_count_ip'].items() if count > 0]

    print('packets total:')
    print(r['packet_count'])
    print(f'packets by ip:')
    print(''.join([f'{ip:8d}\t' for ip in ips_seen]))
    print(''.join([f"{r['packet_count_ip'][ip]:8d}\t" for ip in ips_seen]))
    print(''.join([f"{r['aa5a_failures_ip'][ip]:8d}\t" for ip in ips_seen]))
    print(''.join([f"{np.float64(r['aa5a_failures_ip'][ip])/r['packet_count_ip'][ip]*100:8.2f}%\t" for ip in ips_seen]))

    #    _global_dict = {'packet_count': 0, 'packet_count_ip': {208: 0, 209: 0}, 'aa5a_failures_ip': {208: 0, 209: 0}}

    sys.exit(0)

