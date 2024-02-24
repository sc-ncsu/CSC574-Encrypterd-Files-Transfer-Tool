#!/usr/bin/env python3
# Unity ID: 200483016
# North Carolina State University

import sys
import os
from struct import *
import socket as sk

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random.random import getrandbits



# CONSTANTS
LISTEN_HOSTS = 5
BUFFER_SIZE = 1024
g=2
p=0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b

####################################################################################################################
# Part 1. server_dh()

def server_dh(server_bind_port):

    # create a server socket
    # '0.0.0.0' ensures that both local and network server can be accessed
    server_bind_ip = '0.0.0.0'
    server_bind_addr = (server_bind_ip, server_bind_port)
    server_s = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
    server_s.bind(server_bind_addr)

    # waiting for the connection with clients
    # capacity of connection with client：5
    # if there is a new connection request, accept it, connect to client
    server_s.listen(LISTEN_HOSTS)
    client_s, addr = server_s.accept()

    # receive A from client, and then convert it to integer
    A = client_s.recv(384)
    A = A.decode(encoding='UTF-8')
    A = int(A)

    # send B
    b_for_key = getrandbits(100)
    p_int = int(p)
    B = pow(g, b_for_key, p_int)
    B = "{:0>384d}".format(B)
    B = B.encode(encoding='UTF-8')
    client_s.send(B)


    # calculate the key after receiving A from client
    key = pow(A, b_for_key, p_int)
    h_obj = SHA256.new()
    key = '%x' % key
    key = key.encode()
    h_obj.update(key)
    key = h_obj.digest()[:32]

    # In connection
    while True:

        recv_len = client_s.recv(2)

        # if no data, terminate
        if not recv_len:
            break

        # unpack the data to get integer back
        Total_len_tuple = unpack('!H', recv_len)
        Total_len = Total_len_tuple[0]
        
        # receive nonce
        recv_nonce = client_s.recv(16)

        # receive MAC tag
        recv_tag = client_s.recv(16)

        # calculate the size of data fragment
        valid_data_size = Total_len-32
        encrypted_segment = client_s.recv(valid_data_size)


        # decrypt and write data to file
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce = recv_nonce)
            decrypted_segment = cipher.decrypt_and_verify(encrypted_segment, recv_tag)

            # unpadding
            decrypted_segment = unpad(decrypted_segment, 16, 'pkcs7')

            sys.stdout.buffer.write(decrypted_segment)
        except (ValueError):
            print("Error: integrity check failed.", file = sys.stderr )
            exit(1)

    # close sockets
    server_s.close()
    client_s.close()
####################################################################################################################
# Part 2. client_dh()

def client_dh(server_ip, server_port):


    # create a client socket
    client_s = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
    server_addr = (server_ip, server_port)
    
    # connect to the server
    print(f"[+] Connecting to {server_ip}:{server_port}...")
    client_s.connect(server_addr)
    print(f"[+] Server {server_ip}:{server_port} has been connected.")



    # getrandbits(N): generate an N-bits integer
    a_for_key = getrandbits(100)
    p_int = int(p)

    # pow(a,b,c) => (a^b) mod c
    A = pow(g, a_for_key, p_int)
    # make A with a length of 384 bits
    # (A is string type)
    A = "{:0>384d}".format(A)
    # encode A with UTF-8
    A = A.encode(encoding='UTF-8')
    # send A
    client_s.send(A)


    # convert B back to integer
    B = client_s.recv(384)
    B = B.decode(encoding='UTF-8')
    B = int(B) 

    ############################
    # calculate the key
    key = pow(B, a_for_key, p_int)
    h_obj = SHA256.new()
    key = '%x' % key
    key = key.encode()
    h_obj.update(key)
    key = h_obj.digest()[:32]
    ############################

    # act as a PDU counter
    PDU_index = 0

    while True:

       # read from stdin
        bytes_read = sys.stdin.buffer.read(BUFFER_SIZE)

        if not bytes_read:
            break

        # padding
        bytes_read = pad(bytes_read, 16, 'pkcs7')


        # encrypt and digest
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(bytes_read)

        # send length of PDU
        Total_len = len(ciphertext) + len(cipher.nonce) + len(tag)
        print(f'[*] Sending the {PDU_index}-th PDU (size:{Total_len} B)...')
        Total_len = pack('!H', Total_len)
        PDU_index += 1


        try:
            client_s.send(Total_len)
            client_s.send(cipher.nonce)
            client_s.send(tag)
            client_s.sendall(ciphertext)

        except (BrokenPipeError):
            print("Error: integrity check failed.", file = sys.stderr )
            exit(1)

    # close socket
    print("[+] File has been transferred successfully.")
    client_s.close()



####################################################################################################################
# Part 3. main()
def main():

    port = int(sys.argv[2])

    # server dh mode 
    if (sys.argv[1] == '-l'):
        server_dh(port)

    # client dh mode
    else:
        ip = sys.argv[1]
        client_dh(ip,port)
        


if __name__ == '__main__':
    main()