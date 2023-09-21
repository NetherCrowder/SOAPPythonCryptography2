from Crypto.Cipher import DES #Importación de pyCryptodome para utilizar el cifrado de DES

class DESEncrypt:
    def __init__(self, key):
        self.key = key

    def pad(self, text):
        pad_length = 8 - (len(text) % 8)
        padded_text = text + bytes([pad_length] * pad_length)
        return padded_text

    def encrypt(self, plaintext):
        plaintext = self.pad(plaintext)
        cipher = DES.new(self.key, DES.MODE_ECB)
        ciphertext = cipher.encrypt(plaintext)
        return ciphertext