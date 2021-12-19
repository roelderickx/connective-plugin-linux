#!/usr/bin/python

# -*- coding: utf-8 -*-

import sys
import socket
import struct
import json
import datetime

IS_DEBUG = True

HOST = '192.168.1.21'
PORT = 5417
BUFF_SIZE = 4096

def log(message):
    #with open('connective-proxy.log', 'a') as f:
    #    f.write(message + '\n')
    if IS_DEBUG:
        sys.stderr.write(message + '\n')


def read_native_message():
    text_length_bytes = sys.stdin.buffer.read(4)

    if len(text_length_bytes) == 0:
        return None

    text_length = struct.unpack('@I', text_length_bytes)[0]
    text = sys.stdin.buffer.read(text_length)

    return text


def send_native_message(response):
    sys.stdout.buffer.write(struct.pack('@I', len(response)))
    sys.stdout.buffer.write(response)
    sys.stdout.buffer.flush()


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    tstamp = datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    log('---- %s - Connected to %s:%d' % (tstamp, HOST, PORT))

    request = read_native_message()
    log('Request: %s' % request)
    s.sendall(request)
    response = s.recv(BUFF_SIZE)
    log('Response: %s' % response)
    send_native_message(response)

