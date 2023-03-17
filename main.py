'''
file encryping program
'''


import os
from Crypto.Cipher import AES
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def encrypt_file_RSA(public_key_path, filename):
    chunk_size = 64 * 1024  # 64KB 단위로 파일을 읽음
    output_filename = filename + '.locked'

    with open(public_key_path, 'rb') as public_key_file:
        public_key = RSA.import_key(public_key_file.read())  # 공개키 불러오기

    cipher = PKCS1_OAEP.new(public_key)  # RSA 암호화 객체 생성

    with open(filename, 'rb') as infile:
        with open(output_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                outfile.write(cipher.encrypt(chunk))  # 파일을 64KB 단위로 암호화하여 저장

    return output_filename


def get_key(password):
    key = password.encode('utf-8')
    while len(key) % 16 != 0:
        key += b' '
    hashed_key = hashlib.sha256(key).digest()
    return hashed_key


def encrypt_file_AES(key, filename):
    chunk_size = 64*1024
    output_file = f"{filename}.locked"
    filesize = str(os.path.getsize(filename)).zfill(16)
    init_vector = os.urandom(16)

    encryptor = AES.new(key, AES.MODE_CBC, init_vector)

    with open(filename, 'rb') as infile, open(output_file, 'wb') as outfile:
        outfile.write(filesize.encode())
        outfile.write(init_vector)

        while True:
            chunk = infile.read(chunk_size)
            if len(chunk) == 0:
                break
            elif len(chunk) % 16 != 0:
                chunk += b' ' * (16 - (len(chunk) % 16))

            outfile.write(encryptor.encrypt(chunk))
    
    os.remove(filename)  # 원본 파일 삭제


filename = input("File to encrypt: ")
password = input("Password: ")


key = get_key(password)
encrypt_file_AES(key, filename)
