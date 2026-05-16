from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64

# Load private key
with open("private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Pesan yang akan ditandatangani
pesan = input("Masukkan pesan: ").encode()

# Buat digital signature (SHA-256 + RSA)
signature = private_key.sign(
    pesan,
    padding.PKCS1v15(),
    hashes.SHA256()
)

# Simpan signature dalam format base64
sig_b64 = base64.b64encode(signature).decode()

print(f"[Pesan]     : {pesan.decode()}")
print(f"[Signature] : {sig_b64[:60]}...")

# Simpan ke file
with open("signature.txt", "w") as f:
    f.write(sig_b64)

print("Signature disimpan ke signature.txt")