# Client has to run on canary

# Increase log verbosity
log_level = "DEBUG"

# Setup data dir
data_dir = "/tmp/canary_client"

bind_addr = "160.80.105.4"

# Enable the client
client {
    enabled = true

    # This is the endpoint where run the Server
    servers = ["160.80.105.5:4647"]
}