#!/usr/bin/env python3

import os
import json
from sys import argv
from time import sleep
from threading import Thread
from cryptography import x509

from lib.common import *
from lib.client import *

def setup_shared_secret(instance, peer):
    # Send local certificate (required for next steps)
    instance.send_message(f"{instance.client_name}:{peer}:REPLY;CLIENT_CERT|{instance.client_cert}")

    retry = 1
    # Check if we have the peer's certificate
    while not instance.peer_session.get(peer):
        if retry > 3:
            print(f"Fail to retrieved {peer}'s certificat.")
            return False

        # Request the peer's certificate
        print(f"Request the {peer}'s certificate. ({retry})")
        instance.send_message(f"{instance.client_name}:{peer}:REQUEST;CLIENT_CERT")
        retry += 1
        sleep(1)
    else:
        try:
            if not instance.peer_session[peer].get('private_key'):
                # Generate EC key pair
                private_key, public_key = generate_ec_keypair()

                # Store session private key
                instance.peer_session[peer]['private_key'] = private_key.decode()

                # Generate signature
                signature = generate_data_signature(instance.client_key.encode(), public_key)

                # Send local session public key
                instance.send_message(f"{instance.client_name}:{peer}:REPLY;SESSION_PUBKEY|{public_key.decode()}|{signature.hex()}")

            retry = 1
            # Check if we have the peer's session public key
            while not instance.peer_session[peer].get('public_key'):
                if retry > 3:
                    print(f"Fail to retrieved {peer}'s session public key..")
                    return False

                # Request the peer's session public key
                print(f"Request the {peer}'s session public key. ({retry})")
                instance.send_message(f"{instance.client_name}:{peer}:REQUEST;SESSION_PUBKEY")
                retry += 1
                sleep(1)
            else:
                # Generate a shered secret key with local private key and peer's public key
                shared_secret_key = create_shared_secret_key(instance.peer_session[peer]['private_key'].encode(), instance.peer_session[peer]['public_key'].encode())

                # Store the shared secret key
                instance.peer_session[peer]['secret'] = shared_secret_key.hex()
        except Exception as e:
            print(f"Session init error: {e}")
            return False

    return True

def system_exchange(instance, data):
    content_type, content = data.split(';', 1)

    match content_type:
        case 'CLIENT_NAMES':
            try:
                # Parse the response to get the list of client IDs
                client_names = content.split(",")

                print("Available client IDs:")
                for client_name in client_names:
                    print(client_name)

            except Exception as e:
                print(f"Failed to retrieve client IDs: {e}")

        case 'CLIENT_CERT':
            # Verify new client certificate
            is_signed = is_certificate_signed_by_ca(content.encode(), instance.ca_cert.encode())
            if is_signed:
                print("Client certificate verified.")
                instance.client_cert = content

def client_exchange(instance, src, data):
    content_type, content = data.split(';', 1)
    # Default vars
    response = ''

    # Filter message by content type
    match content_type:
        case 'REQUEST':
            # Define action per request type
            match content:
                case 'CLIENT_CERT':
                    # Send the client certificate as the response
                    response = f"REPLY;{content}|{instance.client_cert}"

                case 'SESSION_PUBKEY':
                    if not instance.peer_session[src].get('private_key'):
                        # Generate EC key pair
                        private_key, public_key = generate_ec_keypair()

                        # Store session private key
                        instance.peer_session[src]['private_key'] = private_key.decode()
                    else:
                        public_key = recover_public_key(instance.peer_session[src]['private_key'].encode())

                    # Generate signature
                    signature = generate_data_signature(instance.client_key.encode(), public_key)

                    # Send the session public key and its signature as the response
                    response = f"REPLY;{content}|{public_key.decode()}|{signature.hex()}"

        case 'REPLY':
            request_type, answer = content.split('|', 1)

            # Define action per request type
            match request_type:
                case 'CLIENT_CERT':
                    # Verify new peer certificate
                    is_signed = is_certificate_signed_by_ca(answer.encode(), instance.ca_cert.encode())
                    if is_signed:
                        print("Peer's certificate verified.")
                        if not instance.peer_session.get(src):
                            instance.peer_session[src] = {}
                        instance.peer_session[src]['certificate'] = answer

                case 'SESSION_PUBKEY':
                    public_key, signature = answer.split('|', 1)

                    # Verify the peer's session public key with peer's certificate
                    is_signed = verify_data_signature(public_key.encode(), bytes.fromhex(signature), instance.peer_session[src]['certificate'].encode())
                    if is_signed:
                        print("Peer's session public key verified.")
                        instance.peer_session[src]['public_key'] = public_key

        case 'DATA':
            # Default vars
            message = ''

            # Check if session secret exists
            secret = instance.peer_session[src].get('secret')
            if not secret:
                if not setup_shared_secret(instance, src):
                    print(f"Fail to setup a shared secret with {src}.")
                else:
                    secret = instance.peer_session[src].get('secret')

            try:
                # Decrypt data in AES-128 with session secret key
                message = decrypt_data(bytes.fromhex(content), bytes.fromhex(secret))

            except Exception as e:
                print(f"Decryption error: {e}")

            if message:
                print(f"{src}: {message.decode()}")
            else:
                print("Failed to read messsage.")

        case _:
            print(f"Unknown content type: {content_type}")

    # Send response to the client
    if response:
        # Format data payload
        payload = f"{instance.client_name}:{src}:{response}"
        instance.send_message(payload)

def forwarder(instance):
    while instance.running:
        try:
            # Fetch income data from queue
            data = instance.message_queue.get()

            # Extract the source ID, the destination ID and the message
            src, dest, raw_message = data.split(':', 2)

            if src == 'server':
                # Extract signature
                data, signature = raw_message.split('!', 1)

                # Exit if error occurs with the signature verification
                if not verify_data_signature(data.encode(), bytes.fromhex(signature), instance.server_cert.encode()):
                    print("The response is not signed by the server's ceritifcate.")
                    return False
                else:
                    print("Server response verified.")

                # Handle system exchange process
                try:
                    system_exchange(instance, data)
                except Exception as e:
                    print(f"System exchange error: {e}")
            else:
                # Handle client exchange process
                try:
                    client_exchange(instance, src, raw_message)
                except Exception as e:
                    print(f"Client exchange error: {e}")

            # Indicate that the processing of the data is complete
            instance.message_queue.task_done()

        except Exception as e:
            print(f"Forward error: {e}")
            return False

    return True

def user_interface(instance):
    while instance.running:
        # Default vars
        data = ''

        try:
            # Wait new user entry
            dest_client_name = ''
            while dest_client_name == '':
                print("Enter destination client name (or 'server' to make server request)")
                dest_client_name = input("> ")

            # Action when sending to server
            if dest_client_name == 'server':
                # Default vars
                request = 'Null'
                argument = ''

                # List possible actions to user
                print("Enter 1 to 'GET_CLIENT_NAMES'")
                print("Enter 2 to 'Soon'")

                choice = input("> ")

                match choice:
                    case '1':
                        request = 'GET_CLIENT_NAMES'

                # Prepare data to encrypt
                cleartext = f"{request};{argument}"

                # Encrypt the data with ECIES using the public key
                data = encrypt_data_with_certificate(cleartext.encode(), instance.server_cert.encode()).hex()

            # Action when sending to any other client
            else:
                message = input("Enter message to send: ")

                # Check if a session exists with the peer
                session = instance.peer_session.get(dest_client_name)
                if not session:
                    if not setup_shared_secret(instance, dest_client_name):
                        print(f"Fail to setup a shared secret with {dest_client_name}.")
                    else:
                        secret = instance.peer_session[dest_client_name].get('secret')
                else:
                    # Check if session secret exists
                    secret = instance.peer_session[dest_client_name].get('secret')
                    if not secret:
                        if not setup_shared_secret(instance, dest_client_name):
                            print(f"Fail to setup a shared secret with {dest_client_name}.")
                        else:
                            secret = instance.peer_session[dest_client_name].get('secret')

                if secret:
                    try:
                        # Encrypt data in AES-128 with session secret key
                        ciphertext = encrypt_data(message.encode(), bytes.fromhex(secret))

                        # Format data paylaod
                        data = f"DATA;{ciphertext.hex()}"

                    except Exception as e:
                        print(f"Encryption error: {e}")

            if data:
                # Format payload
                payload = f"{instance.client_name}:{dest_client_name}:{data}"

                instance.send_message(payload)
            else:
                print("Fail to send message.")

        except KeyboardInterrupt:
            instance.disconnect()
            break

        except Exception as e:
            print(f"Internal client error: {e}")
            return False

    return True

if __name__ == '__main__':
    # Get configuration file from argument
    try:
        config_file = argv[1]
    except:
        print("You must specify a config file.")
        exit(1)

    # Check is exists and load configuration
    if not os.path.isfile(config_file):
        print("Need a config file as argument.")
        exit(1)

    # Fetch configuration from file
    with open(config_file, 'r') as f:
        config = json.load(f)

    # Fetch ca certificate from file
    with open(config['ca_certificate_file'], "r") as ca_cert_file:
        cert_content = ca_cert_file.read()

    # Create new client instance
    instance = Client(
        client_name = config['client_name'],
        server_address = config['server_address'],
        server_port = config['server_port'],
        ca_cert = cert_content
    )

    # Connect to the server
    if instance.connect():
        # Verify server certificate
        is_signed = is_certificate_signed_by_ca(instance.server_cert.encode(), instance.ca_cert.encode())
        if is_signed:
            print("The certificate is signed by the CA.")
        else:
            print("The certificate is not signed by the CA.")

        # Start a thread to handle incoming messages from the server
        Thread(target=forwarder, args=(instance,), daemon=True).start()

        # Generate EC key pair
        private_key, public_key = generate_ec_keypair()

        # Store private key
        instance.client_key = private_key.decode()

        # Create CSR
        common_name = instance.client_name
        csr = create_csr(private_key, public_key, common_name)

        # Prepare data to encrypt
        data = f"SIGN_CERTIFICATE;{csr.decode()}"

        # Encrypt the data with ECIES using the public key
        ciphertext = encrypt_data_with_certificate(data.encode(), instance.server_cert.encode())

        # Format data payload
        data = f"{instance.client_name}:server:{ciphertext.hex()}"

        # Send CSR to CA
        instance.send_message(data)

        # Start 'user_interface' process
        user_interface(instance)
