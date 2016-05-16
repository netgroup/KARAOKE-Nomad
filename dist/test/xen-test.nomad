job "xen-test" {
    datacenters = ["dc1"]
    type = "batch"

    constraint {
	attribute = "${attr.kernel.name}"
	value = "linux"
    }

    group "test" {

	task "clickos-2048" {
        
	    driver = "xen"

	    config = {
            	img_source = "http://160.80.105.5/clickos_x86_64"
		cfg_source = "http://160.80.105.5/clickos2048.cfg"
            }	

            resources {
                cpu = 500 # 500 Mhz
                memory = 256 # 256MB
            }
        }
    }
}