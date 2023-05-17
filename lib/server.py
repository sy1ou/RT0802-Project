import socket
import queue
from select import select
from threading import Thread

class ClientConnection:
    def __init__(self, client_socket, client_address, client_name, message_queue):
        self.client_socket = client_socket
        self.client_address = client_address
        self.client_name = client_name
        self.message_queue = message_queue
        self.certificate = None
        self.public_key = None

class Server:
    def __init__(self, host, port, server_key, server_cert, ca_cert):
        self.host = host
        self.port = port
        self.ca_cert = ca_cert
        self.server_key = server_key
        self.server_cert = server_cert
        self.server_socket = None
        self.client_connections = []
        self.incoming_queue = queue.Queue()
        self.connection_thread = None
        self.running = False

    def start(self):
        try:
            # Create an SSL context
            #ssl_context = SSL.Context(SSL.TLSv1_2_METHOD)
            #ssl_context.use_privatekey_file(self.keyfile)
            #ssl_context.use_certificate_file(self.certfile)

            # Create a TCP/IP socket
            self.server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

            # Set socket in non-blocking mode
            self.server_socket.setblocking(False)

            # Bind the socket to the host and port
            self.server_socket.bind((self.host, self.port))

            # Listen for incoming connections
            self.server_socket.listen(5)
            print(f"Server listening on [{self.host}]:{self.port}")

            self.running = True

            # Start a thread to handle incoming connections
            self.connection_thread = Thread(target=self._handle_connections)
            self.connection_thread.start()

        except socket.error or KeyboardInterrupt as e:
            print(f"Failed to start server: {e}")
            return False

        return True

    def stop(self):
        try:
            self.running = False

            # Close all client sockets
            for client_conn in self.client_connections:
                client_conn.client_socket.close()

            # Close the server socket and threads
            if self.server_socket:
                self.connection_thread.join()
                self.server_socket.close()

            print("Server stopped.")

        except socket.error as e:
            print(f"Failed to stop server: {e}")
            return False

        return True

    def get_client_names(self):
        # Retrieve the list of client names
        client_names = [conn.client_name for conn in self.client_connections]

        # Convert the client names to a comma-separated string
        client_names_str = ",".join(client_name for client_name in client_names)

        # Send the client IDs as the response
        return client_names_str

    def _handle_connections(self):
        while self.running:
            # Wait for the socket to become readable
            readable, _, _ = select([self.server_socket], [], [], 1.0) # Set timeout to 1 second

            if self.server_socket in readable and self.running:
                try:
                    # Accept a client connection
                    client_socket, client_address = self.server_socket.accept()
                    print(f"Connection established from [{client_address[0]}]:{client_address[1]}")

                    # Create a message queue for the client
                    message_queue = queue.Queue()

                    # Retrieve 'client_name' from client
                    data = client_socket.recv(1024).decode()
                    _, client_name = data.split(':', 1)

                    # Send server certificate to client
                    data = f"srv_cert:{self.server_cert}"
                    client_socket.sendall(data.encode())

                    # Set socket in non-blocking mode
                    client_socket.setblocking(False)

                    # Create a client connection object
                    client_conn = ClientConnection(client_socket, client_address, client_name, message_queue)

                    # Add the client connection to the list
                    self.client_connections.append(client_conn)

                    # Start a thread to handle incoming messages for this client
                    Thread(target=self._handle_incoming_messages, args=(client_conn,)).start()

                    # Start a thread to handle outgoing messages for this client
                    Thread(target=self._handle_outgoing_messages, args=(client_conn,)).start()

                except socket.error as e:
                    # Handle any socket errors
                    print("Socket error:", e)
                    break

    def _handle_incoming_messages(self, client_conn):
        while self.running:
            # Wait for the socket to become readable
            readable, _, _ = select([client_conn.client_socket], [], [], 1.0) # Set timeout to 1 second

            if client_conn.client_socket in readable and self.running:
                try:
                    # Receive data from the client
                    data = client_conn.client_socket.recv(4096).decode()

                    if not data:
                        # If no data received, the client has closed the connection
                        print(f"Connection closed by {client_conn.client_address}")

                        # Remove the client connection from the list
                        self.client_connections.remove(client_conn)

                        # Close the client socket
                        client_conn.client_socket.close()
                        break

                    else:
                        # Retrive 'src_id' from data
                        src_id, _ = data.split(':', 1)

                        # Drop potential spoofing message
                        if src_id == client_conn.client_name:
                            # Print the received message
                            print(f"Received message from {client_conn.client_name}.")

                            # Put income data in processing queue
                            self.incoming_queue.put(data)

                except socket.error as e:
                    print(f"Socket error occurred for {client_conn.client_address}: {e}")

    def _handle_outgoing_messages(self, client_conn):
        while self.running:
            try:
                # Get data from the client's message queue
                data = client_conn.message_queue.get(timeout=1)

                # Send data to the client
                client_conn.client_socket.sendall(data.encode())

                # Print the sent message
                print(f"Sent message to {client_conn.client_name}.")

                # Indicate that the processing of the message is complete
                client_conn.message_queue.task_done()

            except queue.Empty:
                pass

            except socket.error as e:
                print(f"Socket error occurred for {client_conn.client_address}: {e}")
