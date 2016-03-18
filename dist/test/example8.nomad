# There can only be a single job definition per file.
# Create a job with ID and Name 'example'
job "example8" {
	# Run the job in the global region, which is the default.
	# region = "global"

    	type = "batch"


	# Specify the datacenters within the region this job can run in.
	datacenters = ["dc1"]

	constraint {
		attribute = "${attr.kernel.name}"
		value = "linux"
	}

	# Configure the job to do rolling updates
	update {
		# Stagger updates every 10 seconds
		stagger = "10s"

		# Update a single task at a time
		max_parallel = 1
	}

	# Create a 'cache' group. Each task in the group will be
	# scheduled onto the same machine.
	group "java8" {

		# Define a task to run
		task "web8" {
			# Run a Java Jar
			driver = "java"
			config {
				artifact_source = "http://160.80.105.5/helloworld.jar"
				jvm_options = ["-Xmx2048m", "-Xms256m"]
			}
			resources {
				cpu = 500 # 500 Mhz
				memory = 256 # 256MB
			}

		}
	}
}
