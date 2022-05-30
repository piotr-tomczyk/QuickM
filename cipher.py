from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import os
import messagePopUp

class CipherMethods:
    @staticmethod
    def GenerateRSAKeys():
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        os.mkdir("RSApriv")
        file_out = open("RSApriv/private.pem", "wb")
        file_out.write(private_key)
        file_out.close()

        os.mkdir("RSApub")
        file_out = open("RSApub/public.pem", "wb")
        file_out.write(public_key)
        file_out.close()
    @staticmethod
    def CipherMessage(data, mode):
        data = pad(data, AES.block_size)

        recipient_key = RSA.import_key(open("public_rec.pem").read())
        session_key = get_random_bytes(32)

        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)
        if mode == "ecb":
            cipher_aes = AES.new(session_key[0:16], AES.MODE_ECB)
        elif mode == "cbc":
            cipher_aes = AES.new(session_key[0:16], AES.MODE_CBC, session_key[16:32])
        ciphertext = cipher_aes.encrypt(data)
        text = enc_session_key + ciphertext

        return text
    @staticmethod
    def DecipherMessage(data, mode, type):
        file_out = open("encrypted_data1.bin", "wb")
        file_out.write(data)
        file_out.close()
        file_in = open("encrypted_data1.bin", "rb")

        private_key = RSA.import_key(open("RSApriv/private.pem").read())

        enc_session_key, ciphertext = [
            file_in.read(x) for x in (private_key.size_in_bytes(), -1)
        ]

        file_in.close()
        os.remove("encrypted_data1.bin")

        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        if mode == "ecb":
            cipher_aes = AES.new(session_key[0:16], AES.MODE_ECB)
        elif mode == "cbc":
            cipher_aes = AES.new(session_key[0:16], AES.MODE_CBC, session_key[16:32])
        data = cipher_aes.decrypt(ciphertext)
        if type == "message":
            message = unpad(data, AES.block_size).decode()
            messagePopUp.start(message)
            return
        if type == "file":
            message = data[: (1024 * 8)]
            return message
        return
    