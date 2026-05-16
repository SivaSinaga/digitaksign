from flask import Flask, request, render_template, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import base64, hashlib
import os

app = Flask(__name__)

def load_keys():
    with open("private.pem","rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    with open("public.pem","rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    return priv, pub

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/sign", methods=["POST"])
def sign():
    pesan = request.json["pesan"].encode()
    priv, _ = load_keys()
    sig = priv.sign(pesan, padding.PKCS1v15(), hashes.SHA256())
    h = hashlib.sha256(pesan).hexdigest()
    return jsonify({
        "hash": h,
        "signature": base64.b64encode(sig).decode(),
        "status": "signed"
    })

@app.route("/verify", methods=["POST"])
def verify():
    pesan = request.json["pesan"].encode()
    sig = base64.b64decode(request.json["signature"])
    _, pub = load_keys()
    try:
        pub.verify(sig, pesan, padding.PKCS1v15(), hashes.SHA256())
        return jsonify({"valid": True})
    except InvalidSignature:
        return jsonify({"valid": False})

if __name__ == "__main__":
    # Buat SSL context
import os   ← tambahkan di baris paling atas

# bagian bawah app.py:
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)