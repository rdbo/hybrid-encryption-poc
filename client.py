from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome import Random
import x25519
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
key = Random.get_random_bytes(32)
public_key = x25519.scalar_base_mult(key)
print("Client public key (ECDH): " + public_key.hex())

# Generate a session key that will only be used once by the server for encrypting the its ECDH public key
session_key = Random.get_random_bytes(32)
print("Session key: " + session_key[:2].hex() + "..." + session_key[-2:].hex())

# Connect to server
print("Connecting to the server...")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 8888))

# Send ECDH public key to the server
# NOTE: This should have MAC
print("Sending ECDHE public key to the server...")
enc_public_key = server_cipher_rsa.encrypt(session_key + public_key)
sock.send(enc_public_key)

# Receive server's ECDH public key to establish shared secret
enc_data = sock.recv(2048) # The packet size is unknown, so just using 2048 here
nonce = enc_data[:16] # First 16 bytes are the nonce
print("Server nonce: " + nonce.hex())
tag = enc_data[16:32] # Message Authentication Code (MAC)
print("Server MAC: " + tag.hex())
enc_server_public_key_ec = enc_data[32:] # The rest is the encrypted public key

# Generate symetric cipher for the session key
cipher_ec = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
server_public_key_ec = cipher_ec.decrypt_and_verify(enc_server_public_key_ec, tag)
print("Server public key (ECDH): " + server_public_key_ec.hex())

# Generate shared key from the client private key and the server public key
shared_key = x25519.scalar_mult(key, server_public_key_ec)
print("Shared Key: " + shared_key[:2].hex() + "..." + shared_key[-2:].hex())

# Generate cipher to encrypt message to the server, and encrypt it
message = b"Hello server!"
print("Message to the server: " + message.decode())
shared_cipher_ec = AES.new(shared_key, AES.MODE_GCM)
enc_msg, tag = shared_cipher_ec.encrypt_and_digest(message)
nonce = shared_cipher_ec.nonce
print("Nonce: " + nonce.hex())
print("Size of nonce: " + str(len(nonce)))
print("MAC: " + tag.hex())

# Send encrypted message to the server, along with the nonce and the MAC
sock.send(nonce + tag + enc_msg)
print("Sent message to the server")

# Receive and decrypt message from server using shared key
enc_data = sock.recv(2048)
print("Received message from the server")
nonce = enc_data[:16]
tag = enc_data[16:32]
enc_msg = enc_data[32:]
print("Nonce: " + nonce.hex())
print("MAC: " + tag.hex())

# Generate cipher to decrypt the message, and decrypt it
shared_cipher_ec = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
data = shared_cipher_ec.decrypt_and_verify(enc_msg, tag)
print("Server Message: " + data.decode())
