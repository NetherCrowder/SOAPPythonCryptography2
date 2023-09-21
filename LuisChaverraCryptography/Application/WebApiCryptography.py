# Creación de la API Web del proyecto
# Importación de la librería Fastapi

from fastapi import FastAPI #Importación de la librería FastApi
import base64 #Importación de la libreria de Base64

#Importación de los clases de DES
from LuisChaverraCryptography.Core.Security.Encrypt.DESEncrypt import DESEncrypt
from LuisChaverraCryptography.Core.Security.Decrypt.DESDecrypt import DESDecrypt

#Importación de las clases de 3DES
from LuisChaverraCryptography.Core.Security.Encrypt.ThreeDESEncrypt import ThreeDESEncrypt
from LuisChaverraCryptography.Core.Security.Decrypt.ThreeDESDecrypt import ThreeDESDecrypt

app: FastAPI = FastAPI(title='SOAP Python Cryptography', description='USBSI 2023-02')

@app.get("/DESEncrypt", summary="DES Encrypt", description="Codificado en DES", tags=["DES"])
async def DESEncode(Data: str | None = None, key: str | None = None):
    encrypted_data: str | None = None
    try:
        if len(key) != 8:
            encrypted_data = "Codificación interrumpida, la clave debe tener 8 caracteres"
        else:
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
            desDecrypt = DESDecrypt(key.encode('utf-8'))
            descipherText = desDecrypt.decrypt(base64.b64decode(Data))
            plaint_data = descipherText.decode('utf-8')
    except:
        plaint_data = "Decodificación fallida"
    return plaint_data

#########################################################################################################

@app.get("/3DESEncrypt", summary="3DES Encrypt", description="Codificado en 3DES", tags=["3DES"])
async def DESEncode(Data: str | None = None, key: str | None = None):
    encrypted_data: str | None = None
    try:
        if len(key) != 24:
            encrypted_data = "Codificación interrumpida, la clave debe tener 24 caracteres"
        else:
            threedesEncrypt = ThreeDESEncrypt(key.encode('utf-8'))
            cipherText = threedesEncrypt.encrypt(Data.encode('utf-8'))
            encrypted_data = cipherText.decode('utf-8')
    except:
        encrypted_data = "Codificación fallida"
    return encrypted_data

@app.get("/3DESDecrypt", summary="3DES Decrypt", description="Decodificado en 3DES",tags=["3DES"])
async def DESDecode(Data: str | None = None, key: str | None = None):
    plaint_data: str | None = None
    try:
        if len(key) != 24:
            plaint_data = "Decodificación interrumpida, la clave debe tener 8 caracteres"
        else:
            threedesDecrypt = ThreeDESDecrypt(key.encode('utf-8'))
            descipherText = threedesDecrypt.decrypt(Data.encode('utf-8'))
            plaint_data = descipherText.decode('utf-8')
    except:
        plaint_data = "Decodificación fallida"
    return plaint_data