from Cryptodome.PublicKey import RSA, ECC
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome import Random
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

# Receive the client's encrypted ECDHE public key and decrypt it using the server's private key
print("Receiving client's encrypted ECDHE public key...")
enc_client_public_key = conn.recv(rsa_packet_size)
client_public_key_ec = cipher_rsa.decrypt(enc_client_public_key)
print("Client public key: " + client_public_key_ec.hex())

# Create cipher encryption using the client's public ECDH key
# NOTE: this encryption is done symetrically, using the client's public key.
#       This means that the client public key should be unique for this connection (ephemeral).
client_cipher_ec = AES.new(client_public_key_ec, AES.MODE_GCM)
print("Client public key nonce: " + client_cipher_ec.nonce.hex())
print("Size of nonce: " + str(len(client_cipher_ec.nonce)))

# Generate the server's Elliptic Curve Diffie Hellman (Ephemeral) parameters for the connected client
# NOTE: We are handling only one client, so we don't have to do anything more complex here, but in an
#       real world scenario, we would generate ECDH keys for every connected client
print("Generating ECDHE parameters for this connection...")
server_key_ec = ECC.generate(curve="ed25519")
server_public_key_ec = server_key_ec.public_key().export_key(format="raw")
print("Server public key (ECDH): " + server_public_key_ec.hex())

# Encrypt the server ECDH public key and send it back to the client
# TODO: Send tag as MAC (encrypt_and_digest)
enc_server_public_key_ec, tag = client_cipher_ec.encrypt_and_digest(server_public_key_ec)
print("MAC: " + tag.hex())
conn.send(client_cipher_ec.nonce + tag + enc_server_public_key_ec)

# Generate shared key
# TODO
