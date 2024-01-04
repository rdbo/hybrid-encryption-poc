from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome import Random
import x25519
import socket

# Generate RSA keypair from random bytes
print("Generating RSA keypair...")
rng = Random.new().read
key_size_bits = 2048
key = RSA.generate(key_size_bits, rng)
public_key = key.publickey().export_key(format="PEM")
print("Server public key (RSA): \n" + public_key.decode())

# Store server public key so that the client can read it
# NOTE: this simulates a pre-shared public key
print("Saving server public key...")
with open("server_public_key.pem", "wb") as f:
    f.write(public_key)

# Create cipher decryption using the RSA private key
print("Creating cipher for RSA decryption...")
cipher_rsa = PKCS1_OAEP.new(key)

# Start server
print("Starting server...")
rsa_packet_size = int(key_size_bits / 8) # RSA encrypted ciphertext has the same size as the RSA public key
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow the server to restart without 'Address in use' error
sock.bind(("127.0.0.1", 8888))
sock.listen(1) # Listen to only one client, since this is only a PoC

print("Waiting for client...")
conn, addr = sock.accept()

print("Client connected: " + str(addr))

# Receive the client's encrypted ECDHE public key and session key, and decrypt them using the server's private key
print("Receiving client's encrypted ECDHE public key...")
enc_data = conn.recv(rsa_packet_size)
data = cipher_rsa.decrypt(enc_data)
session_key = data[:32]
client_public_key_ec = data[32:]
print("Client public key: " + client_public_key_ec.hex())
print("Session key: " + session_key[:2].hex() + "..." + session_key[-2:].hex())

# Create cipher encryption using the client's session key
client_cipher_ec = AES.new(session_key, AES.MODE_GCM)
print("Client public key nonce: " + client_cipher_ec.nonce.hex())
print("Size of nonce: " + str(len(client_cipher_ec.nonce)))

# Generate the server's Elliptic Curve Diffie Hellman (Ephemeral) parameters for the connected client
# NOTE: We are handling only one client, so we don't have to do anything more complex here, but in an
#       real world scenario, we would generate ECDH keys for every connected client
print("Generating ECDHE parameters for this connection...")
server_key_ec = Random.get_random_bytes(32)
server_public_key_ec = x25519.scalar_base_mult(server_key_ec)
print("Server public key (ECDH): " + server_public_key_ec.hex())

# Encrypt the server ECDH public key and send it back to the client
enc_server_public_key_ec, tag = client_cipher_ec.encrypt_and_digest(server_public_key_ec)
print("MAC: " + tag.hex())
conn.send(client_cipher_ec.nonce + tag + enc_server_public_key_ec)

# Generate shared key
shared_key = x25519.scalar_mult(server_key_ec, client_public_key_ec)
print("Shared Key: " + shared_key[:2].hex() + "..." + shared_key[-2:].hex())

# Receive and decrypt message from client using shared key
enc_data = conn.recv(2048)
print("Received message from the client")
nonce = enc_data[:16]
tag = enc_data[16:32]
enc_msg = enc_data[32:]
print("Nonce: " + nonce.hex())
print("MAC: " + tag.hex())

# Generate cipher to decrypt the message, and decrypt it
shared_cipher_ec = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
data = shared_cipher_ec.decrypt_and_verify(enc_msg, tag)
print("Client Message: " + data.decode())

# Generate cipher to encrypt message to the client, and encrypt it
message = b"Hello client!"
print("Message to the client: " + message.decode())
shared_cipher_ec = AES.new(shared_key, AES.MODE_GCM)
enc_msg, tag = shared_cipher_ec.encrypt_and_digest(message)
nonce = shared_cipher_ec.nonce
print("Nonce: " + nonce.hex())
print("Size of nonce: " + str(len(nonce)))
print("MAC: " + tag.hex())

# Send encrypted message to the server, along with the nonce and the MAC
conn.send(nonce + tag + enc_msg)
print("Sent message to the client")
