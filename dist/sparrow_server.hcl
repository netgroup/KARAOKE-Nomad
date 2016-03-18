# Server has to run in a different endpoint, for example in your laptop

# Increase log verbosity
log_level = "DEBUG"

# Setup data dir
data_dir = "/tmp/canary_server"

bind_addr = "160.80.105.5"

server {
	enabled = true

	# This is necessary for master election. In this case we have auto-proclamation
	bootstrap_expect = 1
}