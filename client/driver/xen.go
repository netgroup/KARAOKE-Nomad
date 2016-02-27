package driver

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/nomad/client/allocdir"
	"github.com/hashicorp/nomad/client/config"
	"github.com/hashicorp/nomad/client/driver/executor"
	cstructs "github.com/hashicorp/nomad/client/driver/structs"
	"github.com/hashicorp/nomad/client/fingerprint"
	"github.com/hashicorp/nomad/helper/discover"
	"github.com/hashicorp/nomad/nomad/structs"
)

var (
	reMajVersion = regexp.MustCompile(`xen_major\s+:\s([1-9])`)
	reMinVersion = regexp.MustCompile(`xen_minor\s+:\s([1-9])`)
	reExtVersion = regexp.MustCompile(`xen_extra\s+:\s.([1-9])`)
)

// XenDriver is a driver for running Xen.
type XenDriver struct {
	DriverContext
	fingerprint.StaticFingerprinter
}

// Configuration for XenDriver
type XenDriverConfig struct {
	ArtifactSource string           `mapstructure:"artifact_source"`
	Checksum       string           `mapstructure:"checksum"`
	Accelerator    string           `mapstructure:"accelerator"`
	PortMap        []map[string]int `mapstructure:"port_map"` // A map of host port labels and to guest ports.
}

// old xenHandle is returned from Start/Open as a handle to the PID (identical to qemu and java).

/*
type xenHandle struct {
	cmd    executor.Executor
	waitCh chan *cstructs.WaitResult
	doneCh chan struct{}
}
*/

// xenHandle is returned from Start/Open as a handle to the PID (identical to qemu)
// TODO verify if it is ok
type xenHandle struct {
	pluginClient *plugin.Client
	userPid      int
	executor     executor.Executor
	allocDir     *allocdir.AllocDir
	killTimeout  time.Duration
	logger       *log.Logger
	waitCh       chan *cstructs.WaitResult
	doneCh       chan struct{}
}

// NewXenDriver is used to create a new exec driver (identical to qemu and java).
func NewXenDriver(ctx *DriverContext) Driver {
	return &XenDriver{DriverContext: *ctx}
}

// Return the driver to be used
func (d *XenDriver) Fingerprint(cfg *config.Config, node *structs.Node) (bool, error) {
	bin := "xl"

	outBytes, err := exec.Command(bin, "info").Output()
	if err != nil {
		return false, nil
	}
	out := strings.TrimSpace(string(outBytes))
	matches1 := reMajVersion.FindStringSubmatch(out)
	if len(matches1) != 2 {
		return false, fmt.Errorf("Unable to parse Xen major version string: %#v", matches1)
	}
	matches2 := reMinVersion.FindStringSubmatch(out)
	if len(matches2) != 2 {
		return false, fmt.Errorf("Unable to parse Xen minor version string: %#v", matches2)
	}
	matches3 := reExtVersion.FindStringSubmatch(out)
	if len(matches3) != 2 {
		return false, fmt.Errorf("Unable to parse Xen extra version string: %#v", matches3)
	}

	matches := matches1[1] + "." + matches2[1] + "." + matches3[1]

	node.Attributes["driver.xen"] = "1"
	node.Attributes["driver.xen.version"] = matches

	return true, nil
}

// Run an existing Xen image. Start() will pull down an existing, valid Xen
// image and save it to the Drivers Allocation Dir
func (d *XenDriver) Start(ctx *ExecContext, task *structs.Task) (DriverHandle, error) {

	/*
			Old code
			// Xen defaults to 256M of RAM for a given VM. Instead, we force users to
			// supply a memory size in the tasks resources
			if task.Resources == nil || task.Resources.MemoryMB == 0 {
				return nil, fmt.Errorf("Missing required Task Resource: Memory")
			}

			args := []string{
		                "xl",
		                "create",
		                "/root/clickos.cfg",
			}

			// Setup the command
			cmd := executor.Command(args[0], args[1:]...)
			d.logger.Printf("[DEBUG] Starting XenVM command: %q", strings.Join(args, " "))

			// Create and Return Handle
		    h := &execHandle{
		            cmd:    cmd,
		            doneCh: make(chan struct{}),
		            waitCh: make(chan *cstructs.WaitResult, 1),
		    }

		    go h.run()
		    return h, nil
	*/

	/*var driverConfig QemuDriverConfig
	if err := mapstructure.WeakDecode(task.Config, &driverConfig); err != nil {
		return nil, err
	}

	if len(driverConfig.PortMap) > 1 {
		return nil, fmt.Errorf("Only one port_map block is allowed in the qemu driver config")
	}

	// Get the image source
	source, ok := task.Config["artifact_source"]
	if !ok || source == "" {
		return nil, fmt.Errorf("Missing source image Qemu driver")
	}

	// Qemu defaults to 128M of RAM for a given VM. Instead, we force users to
	// supply a memory size in the tasks resources
	if task.Resources == nil || task.Resources.MemoryMB == 0 {
		return nil, fmt.Errorf("Missing required Task Resource: Memory")
	}
	*/

	// Get the tasks local directory.
	taskDir, ok := ctx.AllocDir.TaskDirs[d.DriverContext.taskName]
	if !ok {
		return nil, fmt.Errorf("Could not find task directory for task: %v", d.DriverContext.taskName)
	}

	// Proceed to download an artifact to be executed.
	/*
		vmPath, err := getter.GetArtifact(
			taskDir,
			driverConfig.ArtifactSource,
			driverConfig.Checksum,
			d.logger,
		)
		if err != nil {
			return nil, err
		}

		vmID := filepath.Base(vmPath)

		// Parse configuration arguments
		// Create the base arguments
		accelerator := "tcg"
		if driverConfig.Accelerator != "" {
			accelerator = driverConfig.Accelerator
		}
		// TODO: Check a lower bounds, e.g. the default 128 of Qemu
		mem := fmt.Sprintf("%dM", task.Resources.MemoryMB)
	*/

	args := []string{
		"pwd",
		" ",
		//"/root/clickos.cfg",
	}

	/*
		// Check the Resources required Networks to add port mappings. If no resources
		// are required, we assume the VM is a purely compute job and does not require
		// the outside world to be able to reach it. VMs ran without port mappings can
		// still reach out to the world, but without port mappings it is effectively
		// firewalled
		protocols := []string{"udp", "tcp"}
		if len(task.Resources.Networks) > 0 && len(driverConfig.PortMap) == 1 {
			// Loop through the port map and construct the hostfwd string, to map
			// reserved ports to the ports listenting in the VM
			// Ex: hostfwd=tcp::22000-:22,hostfwd=tcp::80-:8080
			var forwarding []string
			taskPorts := task.Resources.Networks[0].MapLabelToValues(nil)
			for label, guest := range driverConfig.PortMap[0] {
				host, ok := taskPorts[label]
				if !ok {
					return nil, fmt.Errorf("Unknown port label %q", label)
				}

				for _, p := range protocols {
					forwarding = append(forwarding, fmt.Sprintf("hostfwd=%s::%d-:%d", p, host, guest))
				}
			}

			if len(forwarding) != 0 {
				args = append(args,
					"-netdev",
					fmt.Sprintf("user,id=user.0,%s", strings.Join(forwarding, ",")),
					"-device", "virtio-net,netdev=user.0",
				)
			}
		}

		// If using KVM, add optimization args
		if accelerator == "kvm" {
			args = append(args,
				"-enable-kvm",
				"-cpu", "host",
				// Do we have cores information available to the Driver?
				// "-smp", fmt.Sprintf("%d", cores),
			)
		}*/

	d.logger.Printf("[DEBUG] Starting xenVM command: %q", strings.Join(args, " "))
	bin, err := discover.NomadExecutable()
	if err != nil {
		return nil, fmt.Errorf("unable to find the nomad binary: %v", err)
	}

	pluginLogFile := filepath.Join(taskDir, fmt.Sprintf("%s-executor.out", task.Name))
	pluginConfig := &plugin.ClientConfig{
		Cmd: exec.Command(bin, "executor", pluginLogFile),
	}

	exec, pluginClient, err := createExecutor(pluginConfig, d.config.LogOutput, d.config)
	if err != nil {
		return nil, err
	}
	executorCtx := &executor.ExecutorContext{
		TaskEnv:       d.taskEnv,
		AllocDir:      ctx.AllocDir,
		TaskName:      task.Name,
		TaskResources: task.Resources,
		LogConfig:     task.LogConfig,
	}
	t1 := time.Now()
	ps, err := exec.LaunchCmd(&executor.ExecCommand{Cmd: args[0], Args: args[1:]}, executorCtx)
	if err != nil {
		pluginClient.Kill()
		return nil, fmt.Errorf("error starting process via the plugin: %v", err)
	}
	t2 := time.Now()
	duration := t2.Sub(t1)
	d.logger.Printf("[INFO] Started new xenVM in:%v\n", duration)

	// Create and Return Handle
	h := &xenHandle{
		pluginClient: pluginClient,
		executor:     exec,
		userPid:      ps.Pid,
		allocDir:     ctx.AllocDir,
		killTimeout:  d.DriverContext.KillTimeout(task),
		logger:       d.logger,
		doneCh:       make(chan struct{}),
		waitCh:       make(chan *cstructs.WaitResult, 1),
	}

	go h.run()
	return h, nil
}

type xenId struct {
	KillTimeout  time.Duration
	UserPid      int
	PluginConfig *PluginReattachConfig
	AllocDir     *allocdir.AllocDir
}

func (d *XenDriver) Open(ctx *ExecContext, handleID string) (DriverHandle, error) {
	/*
		Old Process
		// Find the process
		cmd, err := executor.OpenId(handleID)
		if err != nil {
			return nil, fmt.Errorf("failed to open ID %v: %v", handleID, err)
		}

		// Return a driver handle
		h := &execHandle{
			cmd:    cmd,
			doneCh: make(chan struct{}),
			waitCh: make(chan *cstructs.WaitResult, 1),
		}
		go h.run()
		return h, nil
	*/

	id := &xenId{}
	if err := json.Unmarshal([]byte(handleID), id); err != nil {
		return nil, fmt.Errorf("Failed to parse handle '%s': %v", handleID, err)
	}

	pluginConfig := &plugin.ClientConfig{
		Reattach: id.PluginConfig.PluginConfig(),
	}

	executor, pluginClient, err := createExecutor(pluginConfig, d.config.LogOutput, d.config)
	if err != nil {
		d.logger.Println("[ERROR] driver.xen: error connecting to plugin so destroying plugin pid and user pid")
		if e := destroyPlugin(id.PluginConfig.Pid, id.UserPid); e != nil {
			d.logger.Printf("[ERROR] driver.xen: error destroying plugin and userpid: %v", e)
		}
		return nil, fmt.Errorf("error connecting to plugin: %v", err)
	}

	// Return a driver handle
	h := &xenHandle{
		pluginClient: pluginClient,
		executor:     executor,
		userPid:      id.UserPid,
		allocDir:     id.AllocDir,
		logger:       d.logger,
		killTimeout:  id.KillTimeout,
		doneCh:       make(chan struct{}),
		waitCh:       make(chan *cstructs.WaitResult, 1),
	}
	go h.run()
	return h, nil

}

func (h *xenHandle) ID() string {
	/*
		Old code
		id, _ := h.cmd.ID()
		return id
	*/
	id := xenId{
		KillTimeout:  h.killTimeout,
		PluginConfig: NewPluginReattachConfig(h.pluginClient.ReattachConfig()),
		UserPid:      h.userPid,
		AllocDir:     h.allocDir,
	}

	data, err := json.Marshal(id)
	if err != nil {
		h.logger.Printf("[ERR] driver.xen: failed to marshal ID to JSON: %s", err)
	}
	return string(data)
}

func (h *xenHandle) WaitCh() chan *cstructs.WaitResult {
	return h.waitCh
}

func (h *xenHandle) Update(task *structs.Task) error {
	/*
		Old code
		// Update is not possible
		return nil
	*/
	// Store the updated kill timeout.
	h.killTimeout = task.KillTimeout
	h.executor.UpdateLogConfig(task.LogConfig)

	// Update is not possible
	return nil
}

// Shut-down command
func (h *xenHandle) Kill() error {
	/*
		Old code
		h.cmd.Shutdown()
		select {
		case <-h.doneCh:
			return nil
		case <-time.After(5 * time.Second):
			return h.cmd.ForceStop()
		}*/
	if err := h.executor.ShutDown(); err != nil {
		if h.pluginClient.Exited() {
			return nil
		}
		return fmt.Errorf("executor Shutdown failed: %v", err)
	}

	select {
	case <-h.doneCh:
		return nil
	case <-time.After(h.killTimeout):
		if h.pluginClient.Exited() {
			return nil
		}
		if err := h.executor.Exit(); err != nil {
			return fmt.Errorf("executor Exit failed: %v", err)
		}

		return nil
	}
}

// Run command
func (h *xenHandle) run() {
	/*
		Old code
		res := h.cmd.Wait()
		close(h.doneCh)
		h.waitCh <- res
		close(h.waitCh)
	*/
	ps, err := h.executor.Wait()
	if ps.ExitCode == 0 && err != nil {
		if e := killProcess(h.userPid); e != nil {
			h.logger.Printf("[ERROR] driver.xen: error killing user process: %v", e)
		}
		if e := h.allocDir.UnmountAll(); e != nil {
			h.logger.Printf("[ERROR] driver.xen: unmounting dev,proc and alloc dirs failed: %v", e)
		}
	}
	close(h.doneCh)
	h.waitCh <- &cstructs.WaitResult{ExitCode: ps.ExitCode, Signal: 0, Err: err}
	close(h.waitCh)
	h.pluginClient.Kill()

}
