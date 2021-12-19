#!/usr/bin/python

# -*- coding: utf-8 -*-

import socket
import subprocess
import threading
import struct

HOST = '192.168.1.21'
PORT = 5417
BUFF_SIZE = 4096

class ConnectiveBrowserDaemon:
    def __init__(self):
        self.sock = None


    def __process_connection(self, connection):
        try:
            # For use with wine. Keep in mind wine does not fully support smartcards.
            '''
            piped_app = subprocess.Popen(['wine', 'extension-native.exe', \
                                          'com.connective.signer.json', \
                                          '{4f643bc8-78f5-49c6-8efd-78ee30289f0b}'], \
                                         stdin=subprocess.PIPE, \
                                         stdout=subprocess.PIPE, \
                                         stderr=None)
            '''
            # For use on native windows
            piped_app = subprocess.Popen(['extension-native.exe', \
                                          'com.connective.signer.json', \
                                          '{4f643bc8-78f5-49c6-8efd-78ee30289f0b}'], \
                                         stdin=subprocess.PIPE, \
                                         stdout=subprocess.PIPE, \
                                         stderr=None)

            # The application is stateless so we can just use Popen.communicate
            # and expect the app to close
            try:
                request = connection.recv(BUFF_SIZE)
                nm_request = struct.pack('@I', len(request)) + request
                print('Received request %s' % nm_request)
                nm_response, nm_err = piped_app.communicate(input=nm_request, timeout=10)
                response_len = struct.unpack('@I', nm_response[:4])[0]
                response = nm_response[4:response_len+4]
                connection.sendall(response)
                print('Sent response %s' % response)
            except subprocess.TimeoutExpired:
                piped_app.kill()
        finally:
            connection.close()
            print('Connection closed')


    def start(self):
        # 01 open the server socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
            self.sock.bind((HOST, PORT))
            self.sock.listen()

            # 02 accept connections; read and process messages
            while True:
                connection, client_address = self.sock.accept()

                print('Connection accepted from %s:%d' % client_address)

                thread = threading.Thread(target=self.__process_connection, args=(connection, ))
                thread.daemon = True
                thread.start()


    def shutdown(self):
        if self.sock:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()



# start a daemon listening on HOST:PORT
daemon = ConnectiveBrowserDaemon()
try:
    daemon.start()
finally:
    daemon.shutdown()

