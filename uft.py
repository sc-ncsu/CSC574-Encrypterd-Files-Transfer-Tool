#!/usr/bin/env python3
# Unity ID: 200483016
# North Carolina State University

import sys
import socket as sk
from struct import *

# CONSTANTS
LISTEN_HOSTS = 5
BUFFER_SIZE = 1024


####################################################################################################################
# Part 1. server()


def server(server_bind_port):
    # '0.0.0.0'ensures that both local address and network address can be accessed
    server_bind_ip = '0.0.0.0'
    server_bind_addr = (server_bind_ip, server_bind_port)

    # create server socket
    server_s = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
    # print("[+] The server is starting.")

    # bind ip & port to server socket
    server_s.bind(server_bind_addr)

    # waiting for the connection from client
    # number of maximum client: 5
    server_s.listen(LISTEN_HOSTS)

    # accept the connect request from client
    client_s, addr = server_s.accept()

 
    # receive data from client
    while True:

        # first acquire the length of data
        recv_len = client_s.recv(2)

        # if nothing is received, terminate transmission and close the sockets
        if not recv_len:
            break

        len_PDU_tuple = unpack('!H', recv_len)
        # data type after unpack() is "tuple"
        len_PDU = len_PDU_tuple[0]
        bytes_read = client_s.recv(len_PDU)

        # write the data to stdout
        sys.stdout.buffer.write(bytes_read)

    # close sockets
    server_s.close()
    client_s.close()


####################################################################################################################
# Part 2. client()

def client(server_ip, server_port):

    server_addr = (server_ip, server_port)

    # create client socket
    client_s = sk.socket(sk.AF_INET, sk.SOCK_STREAM)

    # connect to a server according to the given address
    print(f"[+] Connecting to {server_ip}:{server_port}...")
    client_s.connect(server_addr)
    print(f"[+] Server {server_ip}:{server_port} has been connected.")
    
    # act as a PDU counter
    PDU_index = 0

    while True:
        
        # read bytes from stdin
        bytes_read = sys.stdin.buffer.read(BUFFER_SIZE)

        # check if reach EOF
        if not bytes_read:
            break

        # first send the length of PDU (2 bytes)
        PDU_len = pack('!H',len(bytes_read))
        print(f'[*] Sending the {PDU_index}-th PDU (size:{len(bytes_read)} B)...')
        PDU_index += 1
        client_s.send(PDU_len)

        # then send the data fragment
        client_s.sendall(bytes_read)



    # close the socket
    print("[+] File has been transferred successfully.")
    client_s.close()


####################################################################################################################
# Part 3. main()
def main():
    
    # server mode
    if (sys.argv[1] == '-l'):
        port = int(sys.argv[2])
        server(port)

    # client mode
    else:
        # 传入server_ip, server_port
        port = int(sys.argv[2])
        client(sys.argv[1], port)


if __name__ == '__main__':
    main()