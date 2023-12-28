from Cryptodome.PublicKey import RSA, ECC
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome import Random
import socket

# Access server's public key so that we can encrypt our messages
# before establishing a shared secret
print("Reading server public key...")
server_public_key_bytes = open("server_public_key.pem").read()
server_public_key = RSA.import_key(server_public_key_bytes)
print("Server Public Key (RSA): \n" + server_public_key_bytes)

# Generate server cipher for encrypting messages
server_cipher_rsa = PKCS1_OAEP.new(server_public_key)

# Generate the client's Elliptic Curve Diffie Hellman (Ephemeral) parameters
print("Generating client ECDHE parameters...")
key = ECC.generate(curve="ed25519")
public_key = key.public_key().export_key(format="raw")
print("Client public key (ECDH): " + public_key.hex())

# Generate symetric cipher for the client's public key
# NOTE: Because of the symetrical encryption done by the server,
#       the public key should not be known by third-parties!
cipher_ec = AES.new(public_key, AES.MODE_GCM)

# Connect to server
print("Connecting to the server...")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 8888))

# Send ECDH public key to the server
print("Sending ECDHE public key to the server...")
enc_public_key = server_cipher_rsa.encrypt(public_key)
sock.send(enc_public_key)

# Receive server's ECDH public key to establish shared secret
enc_server_public_key_ec = sock.recv(2048) # The packet size is unknown, so just using 2048 here
server_public_key_ec = cipher_ec.decrypt(enc_server_public_key_ec)
print("Server public key (ECDH): " + server_public_key_ec.hex())
