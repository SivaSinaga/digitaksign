from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import base64

# Load public key
with open("public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# Load signature dari file
with open("signature.txt", "r") as f:
    sig_b64 = f.read()

signature = base64.b64decode(sig_b64)

# Pesan yang ingin diverifikasi
pesan = input("Masukkan pesan untuk verifikasi: ").encode()

try:
    public_key.verify(
        signature,
        pesan,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    print("VALID — Pesan asli, signature cocok!")
except InvalidSignature:
    print("INVALID — Pesan telah diubah atau signature palsu!")