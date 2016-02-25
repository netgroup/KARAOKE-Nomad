package driver

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/nomad/client/config"
	"github.com/hashicorp/nomad/client/driver/executor"
	cstructs "github.com/hashicorp/nomad/client/driver/structs"
	"github.com/hashicorp/nomad/client/fingerprint"
	"github.com/hashicorp/nomad/nomad/structs"
)

var (
	reMajVersion = regexp.MustCompile(`xen_major:'d'`)
	reMinVersion = regexp.MustCompile(`xen_minor:'d'`)
	reExtVersion = regexp.MustCompile(`xen_extra:.'d'`)
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

// xenHandle is returned from Start/Open as a handle to the PID (identical to qemu and java).
type xenHandle struct {
	cmd    executor.Executor
	waitCh chan *cstructs.WaitResult
	doneCh chan struct{}
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
		return false, fmt.Errorf("Unable to parse Xen version string: %#v", matches1)
	}
	matches2 := reMinVersion.FindStringSubmatch(out)
	if len(matches2) != 2 {
		return false, fmt.Errorf("Unable to parse Xen version string: %#v", matches2)
	}
	matches3 := reExtVersion.FindStringSubmatch(out)
	if len(matches3) != 2 {
		return false, fmt.Errorf("Unable to parse Xen version string: %#v", matches3)
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
		// Xen defaults to 256M of RAM for a given VM. Instead, we force users to
		// supply a memory size in the tasks resources
		if task.Resources == nil || task.Resources.MemoryMB == 0 {
			return nil, fmt.Errorf("Missing required Task Resource: Memory")
		}*/


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
}

func (d *XenDriver) Open(ctx *ExecContext, handleID string) (DriverHandle, error) {
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
}

func (h *xenHandle) ID() string {
	id, _ := h.cmd.ID()
	return id
}

func (h *xenHandle) WaitCh() chan *cstructs.WaitResult {
	return h.waitCh
}

func (h *xenHandle) Update(task *structs.Task) error {
	// Update is not possible
	return nil
}

// Shut-down command
func (h *xenHandle) Kill() error {
	h.cmd.Shutdown()
	select {
	case <-h.doneCh:
		return nil
	case <-time.After(5 * time.Second):
		return h.cmd.ForceStop()
	}
}

// Run command
func (h *xenHandle) run() {
	res := h.cmd.Wait()
	close(h.doneCh)
	h.waitCh <- res
	close(h.waitCh)
}
