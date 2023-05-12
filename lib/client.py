import socket
from queue import Queue
from select import select
from threading import Thread

class Client:
    def __init__(self, client_name, server_address, server_port, ca_cert):
        self.client_name = client_name
        self.host = server_address
        self.port = server_port
        self.ca_cert = ca_cert
        self.server_cert = None
        self.client_key = None
        self.client_cert = None
        self.client_socket = None
        self.peer_session = {}
        self.message_queue = Queue()
        self.running = False

    def connect(self):
        try:
            # Create a TCP/IP socket
            self.client_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

            # Connect to the server
            self.client_socket.connect((self.host, self.port))
            print(f"Connected to server at {self.host}:{self.port}")

            # Send 'client_name' to server
            data = f"client_name:{self.client_name}"
            self.client_socket.sendall(data.encode())

            # Retrieve 'server_cert' from server
            data = self.client_socket.recv(4096).decode()
            _, self.server_cert = data.split(':', 1)

            # Set socket in non-blocking mode
            self.client_socket.setblocking(False)

            self.running = True

            # Start a thread to handle incoming messages from the server
            Thread(target=self._handle_messages, daemon=True).start()

        except socket.error as e:
            print(f"Failed to connect: {e}")
            return False

        return True

    def disconnect(self):
        try:
            self.running = False

            # Close the client socket
            if self.client_socket:
                self.client_socket.close()

        except socket.error as e:
            print(f"Failed to disconnect: {e}")
            return False

        return True

    def send_message(self, data):
        try:
            # Send the message to the server
            self.client_socket.sendall(data.encode())
            print("Message sent.")
        except socket.error as e:
            print(f"Socket error occurred: {e}")

    def _handle_messages(self):
        while self.running:
            # Wait for the socket to become readable
            readable, _, _ = select([self.client_socket], [], [], 1.0) # Set timeout to 1 second

            if self.client_socket in readable and self.running:
                try:
                    # Receive data from the server
                    data = self.client_socket.recv(4096).decode()

                    if not data:
                        # If no data received, the server has closed the connection
                        print("\nDisconnected from server.")
                        self.disconnect()

                    else:
                        # Extract the source, the destination and the message
                        src, dest, message = data.split(':', 2)

                        # Drop potential spoofing message
                        if dest == self.client_name:
                            # Print the received message
                            print(f"\nReceived message from {src}.")

                            # Put income data in processing queue
                            self.message_queue.put(data)

                except socket.error as e:
                    print(f"Socket error occurred: {e}")
