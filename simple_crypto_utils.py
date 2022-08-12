from Cryptodome import Random
from Cryptodome.Cipher import AES
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from base64 import encodebytes, b64decode
from pathlib import Path


secret = str.encode('aKQ}uF@YocbR{GH3@E$lLZC7EdXIcmQ$?aRh*tuBEhHN5l@PizqQ6XzD14oY%gr7')


def keysgen(prj_name):
    """Генерация начальной ключевой пары для ассиметричного шифрования по алгоритму RSA"""
    keys_path = Path(Path.cwd(), 'keys')
    # Создание закрытого (секретного) ключа
    privatekey = RSA.generate(2048)
    # Запись закрытого (секретного) ключа в файл
    sec_path = Path(keys_path, prj_name + '.seprk')
    f = open(sec_path, 'wb')
    f.write(bytes(privatekey.exportKey('PEM')))
    f.close()
    # Создание открытого (публичного) ключа
    publickey = privatekey.publickey()
    # Запись открытого (публичного) ключа в файл
    pub_path = Path(keys_path, prj_name + '.sepbk')
    f = open(pub_path, 'wb')
    f.write(bytes(publickey.exportKey('PEM')))
    f.close()


def encrypt(plain_path, pub_key):
    """Шифрование файла"""
    # Генерация сессионного ключа симметричного шифрования для алгоритма AES
    sessionkey = Random.new().read(32)  # 256 бит
    # Загрузка в память архива для зашифрования в двоичном виде
    f = open(plain_path, 'rb')
    plaintext = f.read()
    f.close()
    # Шифрование архива 'plaintext.rar' по алгоритму AES
    iv = Random.new().read(16)  # 128 bit
    obj = AES.new(sessionkey, AES.MODE_CFB, iv)
    ciphertext = iv + obj.encrypt(plaintext)
    ciphertext = bytes(ciphertext)
    # Шифрование сессионного симметричного ключа открытым ассимметричным ключом получателя
    publickey = RSA.importKey(open(pub_key, 'rb').read())  # 'public_key.txt'
    cipherrsa = PKCS1_OAEP.new(publickey)
    sessionkey = cipherrsa.encrypt(sessionkey)
    # Запись зашифрованного сессионного ключа в файл
    f = open(plain_path + '.seef', 'wb')
    f.write(bytes(sessionkey) + encodebytes(secret) + bytes(ciphertext))
    f.close()


def decrypt(enc_path, sec_key):
    """Расшифровка файла"""
    # Расшифровка сессионного ключа закрытым (секретным) ключом по алгоритму RSA
    privatekey = RSA.importKey(open(sec_key, 'rb').read())
    cipherrsa = PKCS1_OAEP.new(privatekey)
    f = open(enc_path, 'rb')
    encrypted = f.read().split(encodebytes(secret))
    sessionkey = encrypted[0]
    sessionkey = cipherrsa.decrypt(sessionkey)
    # Расшифровка архива сессионным ключом, полученном на предыдущем шаге
    ciphertext = encrypted[1]
    f.close()
    iv = ciphertext[:16]
    obj = AES.new(sessionkey, AES.MODE_CFB, iv)
    plaintext = obj.decrypt(ciphertext)
    plaintext = plaintext[16:]
    # Запись расшифрованного архива в файл 'decrypted.rar'
    f = open(enc_path[:-5] + '.decrypted', 'wb')
    f.write(bytes(plaintext))
    f.close()
