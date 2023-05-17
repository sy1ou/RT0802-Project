from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding

class CA:
    def __init__(self, certificate, key):
        self.__certificate_file = certificate
        self.__key_file = key

    def sign_csr(self, csr):
        # Load the CA certificate
        with open(self.__certificate_file, "rb") as cert_file:
            ca_cert = x509.load_pem_x509_certificate(cert_file.read())

        # Load the CA private key
        with open(self.__key_file, "rb") as key_file:
            ca_key = load_pem_private_key(key_file.read(), password=None)

        # Load the CSR
        csr = x509.load_pem_x509_csr(csr)

        # Create the signed certificate
        signed_cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            ca_cert.not_valid_before
        ).not_valid_after(
            ca_cert.not_valid_after
        ).sign(ca_key, hashes.SHA256())

        return signed_cert.public_bytes(Encoding.PEM)
