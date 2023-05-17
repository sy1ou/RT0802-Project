# RT0802-Project
Secure communication lab via PKI and Relay

## Usage
In this section you will find the different steps to use this project.

### Python requirements
The project requires two Python libraries, namely `eciespy` version 0.3 and `cryptography` version 40.0. These libraries likely serve specific functionalities or dependencies within the project. The provided `Pipfile` simplifies the installation and management of these dependencies, ensuring a consistent and reproducible environment for the project's usage.

### Makefile
Running the Makefile will generate the CA certificate and key files (`pki/ca.crt` and `pki/ca.key`), and then generate the server configuration JSON file (`config/server_config.json`) and client configuration JSON files (`config/client1.json`, `config/client2.json`, etc.) with the appropriate server address, port, and CA configuration.

To define the number of clients, server address, and server port, you can pass the respective parameters when running the Makefile. For example:

``` bash
make NUM_CLIENTS=3 SERVER_ADDRESS=myserver.com SERVER_PORT=8080
```

This will generate configuration files for 3 clients with the specified server address and port.

You can use the `make clean` command to clean up the generated files.

Please ensure that you have OpenSSL installed on your system for the commands to work correctly.

### Launch server
Execute the server application with the server configuration file as the command-line argument.
The server will initialize, start listening for data, and handle system requests or relay messages. Press Ctrl+C to stop the server.

``` bash
./app-server.py config/server_config.json
```

### Launch clients
Execute the client application with their respective configuration file as the command-line argument.

The client will load the configuration, establish a connection with the server, and verify the server's certificate.
A separate thread will be started to handle incoming messages from the server.

The user interface process will start, allowing interaction with the client application. Press Ctrl+C to stop the client.

``` bash
./app-client.py config/client1.json
```
