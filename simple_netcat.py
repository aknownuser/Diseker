import socket


class SimpleNetcat:

    def __init__(self, ip, port):
        self.buff = ""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((ip, port))

    def read(self, length = 1024):
        return self.socket.recv(length)

    def read_until(self, data):

        while not data in self.buff:
            self.buff += self.read()

        pos = self.buff.find(data)
        rval = self.buff[:pos + len(data)]
        self.buff = self.buff[pos +len(data):]

        return rval

    def write (self, data):
        self.socket.send(data)

    def close(self):
        self.socket.close()