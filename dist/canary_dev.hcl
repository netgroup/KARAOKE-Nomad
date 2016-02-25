# This deployment is only for dev, we have client and server in the same machine

bind_addr = "160.80.105.4"
data_dir = "/var/lib/canary_dev"

server {
  enabled = true
  bootstrap_expect = 1
}

client {
  enabled = true
}
