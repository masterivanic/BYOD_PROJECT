from multiprocessing.sharedctypes import Value
import socket
import select
import time
import sys
import logging
import json
# from scapy.all import *

buffer_size = 4096
delay = 0.0001
forward_to = ('google.com', 80)  # remote server to connect to


class Forward:
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self, host, port):
        try:
            self.forward.connect((host, port))
            return self.forward
        except Exception as e:
            print(e)
            return False


class TheServer:

    input_list = []
    channel = {}

    def __init__(self, host, port):
        self.s = None
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(200)

    def main_loop(self):
        print("server launching.........")
        self.input_list.append(self.server)
        while 1:
            time.sleep(delay)
            ss = select.select
            inputready, outputready, exceptready = ss(self.input_list, [], [])
            for self.s in inputready:
                if self.s == self.server:
                    self.on_accept()
                    break

                self.data = self.s.recv(buffer_size)
                if len(self.data) == 0:
                    self.on_close()
                    break
                else:
                    self.on_recv()

    def on_accept(self):
        forward = Forward().start(forward_to[0], forward_to[1])
        clientsock, clientaddr = self.server.accept()
        if forward:
            print(clientaddr, "has connected")
            self.input_list.append(clientsock)
            self.input_list.append(forward)
            self.channel[clientsock] = forward
            self.channel[forward] = clientsock
        else:
            print("Can't establish connection with remote server.", end=' ')
            print("Closing connection with client side", clientaddr)
            clientsock.close()

    def on_close(self):
        print(self.s.getpeername(), "has disconnected")
        # remove objects from input_list
        self.input_list.remove(self.s)
        self.input_list.remove(self.channel[self.s])
        out = self.channel[self.s]
        # close the connection with client
        self.channel[out].close()  # equivalent to do self.s.close()
        # close the connection with remote server
        self.channel[self.s].close()
        # delete both objects from channel dict
        del self.channel[out]
        del self.channel[self.s]

    def force_decode(self, string, codecs=['utf8', 'cp1252']):
        for i in codecs:
            try:
                return string.decode(i)
            except UnicodeDecodeError:
                pass
        logging.warn("cannot decode url %s" % ([string]))

    def on_recv(self):
        data = self.data
        encod = str(data, 'ISO-8859-1')
        print(encod)

        # here we can parse and/or modify the data before send forward
        # print(json.dumps(data, indent=2))
        self.channel[self.s].send(data)


if __name__ == '__main__':
    # proxy = IP(dst="0.0.0.0").src
    server = TheServer("192.168.140.211", 33333)
    try:
        server.main_loop()
    except KeyboardInterrupt:
        print("Ctrl C - Stopping server")
        sys.exit(1)
