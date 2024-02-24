#!/usr/bin/env python3
# Unity ID: 200483016
# North Carolina State University

import sys
import os
from struct import *
import socket as sk

from Crypto.Cipher import AES
from Crypto.Random.random import getrandbits
from Crypto.Hash import SHA256


# CONSTANTS
LISTEN_HOSTS = 5
BUFFER_SIZE = 1024
filename = 'intercepted'
g=2
p=0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b


####################################################################################################################
# Part 1. proxy()
def proxy(proxy_bind_port, server_ip, server_port):

    # integrate server's ip and port
    server_addr = (server_ip, server_port)


    # 1、先和server 建立连接（假装自己是client）
    # 1. pretend to be client, connect to server
    socket_as_client = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
    socket_as_client.connect(server_addr)
    print(f"[+] Server {server_ip}:{server_port} has been connected.")


    # 2、再和client建立连接 （假装自己是server）
    # 2. pretend to be server, connect to client
    proxy_bind_ip = '0.0.0.0'
    proxy_bind_addr = (proxy_bind_ip, proxy_bind_port)
    socket_as_server = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
    socket_as_server.bind(proxy_bind_addr)
    socket_as_server.listen(LISTEN_HOSTS)
    real_client_socket, real_client_addr = socket_as_server.accept()

    
    # 4、与 client 交换 AB
    # 4. exchange A&B with client

    # 4.1 接收 client 发来的 A
    # 4.1 receive A from client
    A_from_client = real_client_socket.recv(384)
    A_from_client = A_from_client.decode(encoding='UTF-8')
    A_from_client = int(A_from_client)

    # 4.2 发送 B 给 client
    # 4.2 send b to client
    b_from_proxy = getrandbits(100)
    p_int = int(p)
    B_from_proxy = pow(g, b_from_proxy, p_int)
    B_from_proxy = "{:0>384d}".format(B_from_proxy)
    B_from_proxy = B_from_proxy.encode(encoding='UTF-8')
    real_client_socket.send(B_from_proxy)

    # 4.3 通过 client 的 A 计算 "key1"
    # 4.3 calculate "key1" through A from client
    key1 = pow(A_from_client, b_from_proxy, p_int)
    h1 = SHA256.new()
    key1 = '%x' % key1
    key1 = key1.encode()
    h1.update(key1)
    key1 = h1.digest()[:32]


    # 5、与 server 交换 AB
    # 5. exchange A&B with server

    # 5.1 计算新的 A，发送给 server
    # 5.1 calculate new A and send it to the server

    # 使用的 socket 是 "socket_as_client"
    a_from_proxy = getrandbits(100)
    A_from_proxy = pow(g, a_from_proxy, p_int)
    A_from_proxy = "{:0>384d}".format(A_from_proxy)
    A_from_proxy = A_from_proxy.encode(encoding='UTF-8')
    socket_as_client.send(A_from_proxy)

    # 5.2 接收 server 发来的 B，恢复为整数
    # 5.2 receive B from server and conver it back to integer
    B_from_server = socket_as_client.recv(384)
    B_from_server = B_from_server.decode(encoding='UTF-8')
    B_from_server = int(B_from_server)

    # 5.3 计算新的 key2
    # 5.3 calculate a new "key2"
    key2 = pow(B_from_server, a_from_proxy, p_int)
    h2 = SHA256.new()
    key2 = '%x' % key2
    key2 = key2.encode()
    h2.update(key2)
    key2 = h2.digest()[:32]

    # 6 数据处理和转发
    # 6. data processing and retransmission
    while True:
        ############################################################################
        # PART 1. 通过key1对client发来的数据解密
        # part 1. decrypt data according to key1

        Total_len_from_client = real_client_socket.recv(2)

        if not Total_len_from_client:
            break

        Total_len_from_client = unpack('!H', Total_len_from_client)
        Total_len_from_client = Total_len_from_client[0]

        # receive client_nonce
        nonce_from_client = real_client_socket.recv(16)
        # receive client MAC tag
        tag_from_client = real_client_socket.recv(16)
        # 接收并计算有效数据大小
        # receive and calculate the size of valid data
        datasize_from_client = Total_len_from_client - 32
        encrypted_from_client = real_client_socket.recv(datasize_from_client)

        # 对从client接收的数据解密
        # decrypt the data segment from client
        cipher1 = AES.new(key1, AES.MODE_GCM, nonce=nonce_from_client)
        decrypted_from_client = cipher1.decrypt_and_verify(encrypted_from_client, tag_from_client)

        # Unpadding (no need)
        # decrypted_from_client = unpad(decrypted_from_client, 16, 'pkcs7')




        ############################################################################
        # PART 2. 重新加密并发送数据给 server
        # PART 2. re-encrypt data and send it to server

        # 用 proxy 的 key2 重新加密
        # re-encrypt with key2 calculated by proxy
        cipher2 = AES.new(key2, AES.MODE_GCM)
        ciphertext2, tag2 = cipher2.encrypt_and_digest(decrypted_from_client)

        # 发送用 key2 加密后的 data
        # send data encrpyed with key2
        Total_len_to_server = len(ciphertext2) + len(cipher2.nonce) + len(tag2)
        Total_len_to_server = pack('!H', Total_len_to_server)

        socket_as_client.send(Total_len_to_server)
        socket_as_client.send(cipher2.nonce)
        socket_as_client.send(tag2)
        socket_as_client.sendall(ciphertext2)

    print("[+] File has been transmitted.")
    real_client_socket.close()
    socket_as_client.close()
    socket_as_server.close()



####################################################################################################################
# Part 4. main()
def main():
    proxy_bind_port = int(sys.argv[2])
    server_ip   = sys.argv[3]
    server_port = int(sys.argv[4])
    proxy(proxy_bind_port, server_ip, server_port)
        


if __name__ == '__main__':
    main()