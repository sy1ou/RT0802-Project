# Makefile

# Directories
PKI_DIR := pki
CONFIG_DIR := config

# File paths
CA_CERT := $(PKI_DIR)/ca.crt
CA_KEY := $(PKI_DIR)/ca.key
SERVER_CONFIG_FILE := $(CONFIG_DIR)/server_config.json

# Default number of clients
NUM_CLIENTS ?= 2

# Server configuration
SERVER_ADDRESS := localhost
SERVER_PORT := 8000

# Generate client configuration files
CLIENT_CONFIG_FILES := $(addprefix $(CONFIG_DIR)/client, $(addsuffix .json, $(shell seq 1 $(NUM_CLIENTS))))

# Default target
all: ca server_config $(CLIENT_CONFIG_FILES)

# Create the CA certificate and key
ca:
	@mkdir -p $(PKI_DIR)
	openssl ecparam -name secp256k1 -genkey -out $(PKI_DIR)/ca.key
	openssl req -x509 -new -nodes -key $(PKI_DIR)/ca.key -sha256 -days 1 -out $(CA_CERT)

# Create the JSON server configuration file
server_config:
	@mkdir -p $(CONFIG_DIR)
	@echo "{ \
		\"server\": { \
			\"address\": \"$(SERVER_ADDRESS)\", \
			\"port\": $(SERVER_PORT), \
			\"ca_certificate_file\": \"$(CA_CERT)\" \
		}, \
		\"ca\": { \
			\"certificate_file\": \"$(CA_CERT)\", \
			\"key_file\": \"$(CA_KEY)\" \
		} \
	}" > $(SERVER_CONFIG_FILE)

# Create the JSON client configuration files
$(CONFIG_DIR)/client%.json:
	@echo "{ \
		\"client_name\": \"client$*\", \
		\"server_address\": \"$(SERVER_ADDRESS)\", \
		\"server_port\": $(SERVER_PORT), \
		\"ca_certificate_file\": \"$(CA_CERT)\" \
	}" > $@

# Clean up generated files
clean:
	rm -rf $(PKI_DIR) $(CONFIG_DIR)

# Phony targets
.PHONY: all ca server_config clean
