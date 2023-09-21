from Crypto.Cipher import DES #Importación de pyCryptodome para utilizar el cifrado de DES

class DESDecrypt:
    def __init__(self, key):
        self.key = key

    def unpad(self, text):
        pad_length = text[-1]
        if all(byte == pad_length for byte in text[-pad_length:]):
            return text[:-pad_length]
        return text

    def decrypt(self, ciphertext):
        cipher = DES.new(self.key, DES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)
        plaintext = self.unpad(plaintext)
        return plaintext