#!/usr/bin/env python3

import os
import json
from sys import argv

from lib.common import *
from lib.server import *
from lib.ca import *

def message_relay(server, src, dest, message):
    # Find the destination client connection
    for dest_conn in server.client_connections:
        if dest_conn.client_name == dest:
            # Enqueue the message into the destination client's message queue
            dest_conn.message_queue.put(f"{src}:{dest}:{message}")
            break

def system_request(server, src_client_name, data):
    request, argument = data.split(';', 2)
    # Default vars
    response = ''

    print(f"Request: {request}")
    if argument:
        print(f"Argument: {argument}")

    # Define action per request type
    match request:
        case "GET_CLIENT_NAMES":
            # Generate clients names list
            client_list = server.get_client_names()

            # Send the client names as the response
            response = f"CLIENT_NAMES;{client_list}"

        case "SIGN_CERTIFICATE":
            # Sign client's CSR with CA
            client_csr = argument.encode()
            client_certificate = lab_ca.sign_csr(client_csr)

            # Send the client certificate as the response
            response = f"CLIENT_CERT;{client_certificate.decode()}"

    # Send response to the client
    if response:
        message_relay(server, 'server', src_client_name, response)

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

    with open(config_file, 'r') as f:
        config = json.load(f)

    # Create ca server instance
    lab_ca = CA(
        certificate = config['ca']['certificate_file'],
        key = config['ca']['key_file'],
    )

    # Generate EC key pair
    private_key, public_key = generate_ec_keypair()

    # Create CSR
    common_name = "server"
    csr = create_csr(private_key, public_key, common_name)

    # Sign CSR with CA
    signed_certificate = lab_ca.sign_csr(csr)

    # Fetch ca certificate from file
    with open(config['server']['ca_certificate_file'], "r") as ca_cert_file:
        cert_content = ca_cert_file.read()

    # Create new server instance
    lab = Server(
        host = config['server']['address'],
        port = config['server']['port'],
        server_key = private_key.decode(),
        server_cert = signed_certificate.decode(),
        ca_cert = cert_content
    )

    # Start server
    if lab.start():
        while lab.running:
            try:
                # Fetch income data from queue
                data = lab.incoming_queue.get()

                # Extract the source ID, the destination ID and the message
                src, dest, message = data.split(':', 2)

                if dest == 'server':
                    # Handle system request process
                    system_request(lab, src, message)
                else:
                    # Handle regular message relay
                    message_relay(lab, src, dest, message)

                # Indicate that the processing of the data is complete
                lab.incoming_queue.task_done()

            except KeyboardInterrupt:
                lab.stop()
                exit(0)

            except Exception as e:
                print(f"Internal server error: {e}")
                lab.stop()
                exit(1)
