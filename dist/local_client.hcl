# Client has to run on canary

# Increase log verbosity
log_level = "DEBUG"

# Setup data dir
data_dir = "/tmp/local_client"

# Enable the client
client {
	enabled = true
	servers = ["127.0.0.1:4647"]
}

ports {

http = 5656
rpc = 5657
serf = 5658

}
