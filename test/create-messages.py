#!/usr/bin/env python3

# -*- coding: utf-8 -*-

import sys
import struct
import json

reader = 'VASCO DIGIPASS 870 0' # Windows, 'VASCO DIGIPASS 870 [CCID] 00 00' on linux
current_token = 'IhOcGOSbU/w1TnQNcfz56LUkfYwzmwr4chRgyE68RHNys9jJUt4IH9dAaEVjF8RHMA05daDdU4NwR2jnaaxLaNVlqsVPK+/03ouxb09zubR5SrxjfBXLlavd8Pn2F4P+99YA4mG9S4XqGlb+UOG5hvFiCN7zG2SdrDg4wPCqjn6XeiltDxSRnFa3elGVr2odve6YjPIZKcvy1mTTDF5HU2FYX40KCTptrf2fFOsfNc64j9/u/b0PKeuEbXHH6OlaQLN75CXkHM4X04xgrjrVj95OtKJlQ961fn3BemQ7yHSDWjRrqAugW8SqYNsm1/sE4NDNFqx28Hi6QRw4Q5CyKQ=='

def send_native_message(message, filename):
    with open(filename, 'wb') as f:
        message_bytes = bytes(message, 'utf-8')
        f.write(struct.pack('@I', len(message_bytes)))
        f.write(message_bytes)
        f.flush()

message = {}
message['cmd'] = 'GET_INFO'
message['isRequest'] = True
send_native_message(json.dumps(message), 'get_info.txt')

message = {}
message['cmd'] = 'GET_READERS'
message['activationToken'] = current_token
message['isRequest'] = True
send_native_message(json.dumps(message), 'get_readers.txt')

# authenticate
message = {}
message['cmd'] = 'READ_FILE'
message['reader'] = reader
message['activationToken'] = current_token
message['fileId'] = '3F00DF005039'
message['isRequest'] = True
send_native_message(json.dumps(message), 'read_file.txt')

message = {}
message['cmd'] = 'COMPUTE_AUTHENTICATION'
message['reader'] = reader
message['activationToken'] = current_token
message['hash'] = '6ABAF13A932D96E8BBFB91ABE2185487FF2E43FF76911E5396DE9FB1579ECC51'
message['isRequest'] = True
send_native_message(json.dumps(message), 'compute_authentication.txt')

# sign document
message = {}
message['cmd'] = 'PIN_PAD_AVAILABLE'
message['reader'] = reader
message['activationToken'] = current_token
message['isRequest'] = True
send_native_message(json.dumps(message), 'pin_pad_available.txt')

message = {}
message['cmd'] = 'VERIFY_PIN'
message['reader'] = reader
message['activationToken'] = current_token
message['isRequest'] = True
send_native_message(json.dumps(message), 'verify_pin.txt')

message = {}
message['cmd'] = 'COMPUTE_SIGNATURE'
message['reader'] = reader
message['activationToken'] = current_token
message['hash'] = '6ABAF13A932D96E8BBFB91ABE2185487FF2E43FF76911E5396DE9FB1579ECC51'
message['isRequest'] = True
send_native_message(json.dumps(message), 'compute_signature.txt')

# maestro
message = {}
message['cmd'] = 'SELECT_MAESTRO'
message['reader'] = reader
message['activationToken'] = current_token
message['isRequest'] = True
send_native_message(json.dumps(message), 'select_maestro.txt')

message = {}
message['cmd'] = 'GET_PROCESSING_OPTIONS'
message['reader'] = reader
message['activationToken'] = current_token
message['data'] = '8300'
message['isRequest'] = True
send_native_message(json.dumps(message), 'get_processing_options.txt')

message = {}
message['cmd'] = 'READ_RECORD'
message['reader'] = reader
message['activationToken'] = current_token
message['record'] = '01'
message['sfi'] = '02'
message['isRequest'] = True
send_native_message(json.dumps(message), 'read_record.txt')

message = {}
message['cmd'] = 'COMPUTE_SIGN_CHALLENGE'
message['reader'] = reader
message['activationToken'] = current_token
message['language'] = 'nl'
message['transaction'] = '1'
message['hash'] = '6ABAF13A932D96E8BBFB91ABE2185487FF2E43FF76911E5396DE9FB1579ECC51'
message['isRequest'] = True
send_native_message(json.dumps(message), 'compute_sign_challenge.txt')

