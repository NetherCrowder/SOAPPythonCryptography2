# Creación de la API Web del proyecto
# Importación de la librería Fastapi

from fastapi import FastAPI #Importación de la librería FastApi
import base64 #Importación de la libreria de Base64
from LuisChaverraCryptography.Core.Security.Encrypt.DESEncrypt import DESEncrypt
from LuisChaverraCryptography.Core.Security.Decrypt.DESDecrypt import DESDecrypt

app: FastAPI = FastAPI(title='SOAP Python Cryptography', description='USBSI 2023-02')

@app.get("/DESEncrypt", summary="DES Encrypt", description="Codificado en DES", tags=["DES"])
async def DESEncode(Data: str | None = None, key: str | None = None):
    encrypted_data: str | None = None
    try:
        if len(key) != 8:
            encrypted_data = "Codificación interrumpida, la clave debe tener 8 caracteres"
        else:
            ##key = user_key.encode()
            desencrypt = DESEncrypt(key.encode('utf-8'))
            plaintText = Data.encode('utf-8')
            cipherText = desencrypt.encrypt(plaintText)
            encrypted_data = base64.b64encode(cipherText).decode('utf-8')
    except:
        encrypted_data = "Codificación fallida"
    return encrypted_data

@app.get("/DESDecrypt", summary="DES Decrypt", description="Decodificado en DES",tags=["DES"])
async def DESDecode(Data: str | None = None, key: str | None = None):
    plaint_data: str | None = None
    try:
        if len(key) != 8:
            plaint_data = "Decodificación interrumpida, la clave debe tener 8 caracteres"
        else:
            #key = user_key.encode()
            desDecrypt = DESDecrypt(key.encode('utf-8'))
            decryptedText = desDecrypt.decrypt(base64.b64decode(Data))
            plaint_data = decryptedText.decode('utf-8')
    except:
        plaint_data = "Decodificación fallida"
    return plaint_data