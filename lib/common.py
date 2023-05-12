import secrets
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def generate_ec_keypair():
    # Generate EC private key
    private_key = ec.generate_private_key(ec.SECP256K1())

    # Serialize private key
    serialized_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Get the public key
    public_key = private_key.public_key()

    # Serialize public key
    serialized_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return serialized_private, serialized_public


def recover_public_key(serialized_private):
    # Load private key
    private_key = _load_private_key(serialized_private)

    # Get the public key
    public_key = private_key.public_key()

    # Serialize public key
    serialized_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return serialized_public


def _load_private_key(serialized_private):
    # Load private key
    loaded_private_key = serialization.load_pem_private_key(
        serialized_private,
        password=None,
    )

    return loaded_private_key


def _load_public_key(serialized_public):
    # Load public key
    loaded_public_key = serialization.load_pem_public_key(
        serialized_public,
    )

    return loaded_public_key


def create_csr(serialized_private_key, serialized_public_key, common_name):
    # Load keys
    private_key = _load_private_key(serialized_private_key)
    public_key = _load_public_key(serialized_public_key)

    # Create a CSR builder
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name)
        ])
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(common_name)
        ]),
        critical=False
    )

    # Sign the CSR with the private key
    csr = csr_builder.sign(private_key, hashes.SHA256())

    # Serialize the CSR
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    return csr_pem


def is_certificate_signed_by_ca(certificate, ca_certificate):
    # Load the certificate to be checked
    cert_to_check = x509.load_pem_x509_certificate(certificate)

    # Load the CA certificate
    issuer_public_key = x509.load_pem_x509_certificate(ca_certificate).public_key()

    # Verify the certificate chain
    try:
        issuer_public_key.verify(
            cert_to_check.signature,
            cert_to_check.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False


def generate_data_signature(serialized_private_key, data):
    # Load private key
    private_key = _load_private_key(serialized_private_key)

    # Generate signature
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )

    return signature


def verify_data_signature(data, signature, certificate):
    # Get the ECDSA public key from the certificate
    cert_public_key = x509.load_pem_x509_certificate(certificate).public_key()

    # Verify the signature
    try:
        cert_public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False


def create_shared_secret_key(local_private_key, remote_public_key):
    # Load keys
    l_private_key = _load_private_key(local_private_key)
    r_public_key = _load_public_key(remote_public_key)

    # Perform ECDH key exchange
    shared_key = l_private_key.exchange(ec.ECDH(), r_public_key)

    # Derive key using HKDF
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=16,  # 128 bits
        salt=None,
        info=b"",
    )

    secret_key = kdf.derive(shared_key)
    return secret_key


def encrypt_data(data, secret_key):
    # Create a random IV (Initialization Vector)
    iv = secrets.token_bytes(16)

    # Generate an AES-128 cipher with CBC mode
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv))

    # Create a padder for PKCS7 padding
    padder = sym_padding.PKCS7(128).padder()

    # Pad the data
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the padded data
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return the IV and ciphertext
    return iv + ciphertext


def decrypt_data(ciphertext, secret_key):
    # Split the ciphertext into IV and encrypted data
    iv = ciphertext[:16]
    encrypted_data = ciphertext[16:]

    # Create an AES-128 cipher with CBC mode
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv))

    # Decrypt the ciphertext
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Create an unpadder for PKCS7 padding
    unpadder = sym_padding.PKCS7(128).unpadder()

    # Unpad the decrypted data
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Return the unpadded data
    return unpadded_data
