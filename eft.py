#!/usr/bin/env python3
# Unity ID: 200483016
# North Carolina State University

import sys
from struct import *
import socket as sk

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2


# CONSTANTS
LISTEN_HOSTS = 5
BUFFER_SIZE = 1024


####################################################################################################################
# Part 1. server_safe()

def server_safe(server_bind_port, password):


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

    # receive salt, calculate the key
    salt = client_s.recv(16)
    key = PBKDF2(password, salt=salt, dkLen=32)

    # if the following codes is run, then the connection is established 
    while True:

        # receive total_len (byte type)
        recv_len = client_s.recv(2)

        # if no more data are received, terminate the file transmission
        if not recv_len:
            break
        
        # the Total_len should be unpacked to integer
        Total_len_tuple = unpack('!H', recv_len)
        Total_len = Total_len_tuple[0]
        
        # recieve nonce
        recv_nonce = client_s.recv(16)

        # receive MAC tag
        recv_tag = client_s.recv(16)

        # compute valid data size, receive encrypted data
        valid_data_size = Total_len-32
        encrypted_segment = client_s.recv(valid_data_size)

        # decrypt data and write it back to a file
        # if key does not match, raise an "integrity check failed" exception
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce = recv_nonce)
            decrypted_segment = cipher.decrypt_and_verify(encrypted_segment, recv_tag)
            # unpadding
            decrypted_segment = unpad(decrypted_segment, 16, 'pkcs7')
            sys.stdout.buffer.write(decrypted_segment)
        except (ValueError):
            print("Error: integrity check failed.", file = sys.stderr )

    # close socket
    server_s.close()
    client_s.close()


####################################################################################################################
# Part 2. client_safe()

def client_safe(server_ip, server_port, password):


    # generate the salt
    salt = get_random_bytes(16)

    # create a client socket
    client_s = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
    server_addr = (server_ip, server_port)
    
    # connect to server
    print(f"[+] Connecting to {server_ip}:{server_port}...")
    client_s.connect(server_addr)
    print(f"[+] Server {server_ip}:{server_port} has been connected.")

    # act as a PDU counter
    PDU_index = 0

    # send the salt to server
    client_s.send(salt)


    while True:

        # read from stdin
        bytes_read = sys.stdin.buffer.read(BUFFER_SIZE)

        # check if reach EOF
        if not bytes_read:
            break

        # padding
        bytes_read = pad(bytes_read, 16, 'pkcs7')

        # generate a key with 'PBKDF2'
        key = PBKDF2(password, salt=salt, dkLen=32)
        # create a cipher (GCM mode) 
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(bytes_read)

        # send the length of PDU (2 bytes)
        Total_len = len(ciphertext) + len(cipher.nonce) + len(tag)
        print(f'[*] Sending the {PDU_index}-th PDU (size:{Total_len} B)...')
        Total_len = pack('!H', Total_len)
        PDU_index += 1
        client_s.send(Total_len)

        # send nonce
        client_s.send(cipher.nonce)

        # send MAC tag
        client_s.send(tag)

        # send encrypted data fragment
        client_s.sendall(ciphertext)

    # close socket
    print("[+] File has been transferred successfully.")
    client_s.close()



####################################################################################################################
# Part 3. main()
def main():

    password = sys.argv[2]
    port = int(sys.argv[4])

    # server mode
    if (sys.argv[3] == '-l'):
        server_safe(port,password)

    # client mode
    else:
        ip = sys.argv[3]
        client_safe(ip,port,password)


if __name__ == '__main__':
    main()