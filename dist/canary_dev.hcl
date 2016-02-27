# This deployment is only for dev, we have client and server in the same machine

# Increase log verbosity
log_level = "DEBUG"

data_dir = "/var/lib/canary_dev"

server {
  enabled = true
  bootstrap_expect = 1
}

client {
  enabled = true
}
