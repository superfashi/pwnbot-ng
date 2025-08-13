package container

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	nettypes "github.com/containers/common/libnetwork/types"
	"go.uber.org/zap"
)

type nilNetwork struct {
	// because we use pre-setup network namespace, we don't need to implement any network functionality
}

func (nilNetwork) NetworkCreate(nettypes.Network, *nettypes.NetworkCreateOptions) (nettypes.Network, error) {
	panic("stub")
}

func (nilNetwork) NetworkUpdate(string, nettypes.NetworkUpdateOptions) error {
	panic("stub")
}

func (nilNetwork) NetworkRemove(string) error {
	panic("stub")
}

func (nilNetwork) NetworkList(...nettypes.FilterFunc) ([]nettypes.Network, error) {
	panic("stub")
}

func (nilNetwork) NetworkInspect(string) (nettypes.Network, error) {
	panic("stub")
}

func (nilNetwork) Setup(string, nettypes.SetupOptions) (map[string]nettypes.StatusBlock, error) {
	panic("stub")
}

func (nilNetwork) Teardown(string, nettypes.TeardownOptions) error {
	panic("stub")
}

func (nilNetwork) RunInRootlessNetns(func() error) error {
	panic("stub")
}

func (nilNetwork) RootlessNetnsInfo() (*nettypes.RootlessNetnsInfo, error) {
	panic("stub")
}

func (nilNetwork) Drivers() []string {
	panic("stub")
}

func (nilNetwork) DefaultNetworkName() string {
	panic("stub")
}

func (nilNetwork) NetworkInfo() nettypes.NetworkInfo {
	panic("stub")
}

func createNetNamespace(nsPath string) error {
	runtime.LockOSThread()

	if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
		return err
	}

	return syscall.Mount(fmt.Sprintf("/proc/self/task/%d/ns/net", syscall.Gettid()), nsPath, "", syscall.MS_BIND, "")
}

func removeNetNamespace(logger *zap.Logger, nsPath string) error {
	if err := syscall.Unmount(nsPath, syscall.MNT_DETACH); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if !errors.Is(err, syscall.EINVAL) {
			logger.Error("failed to unmount network namespace", zap.Error(err))
			return err
		}
	}
	if err := os.RemoveAll(nsPath); err != nil {
		logger.Error("failed to remove netns file", zap.Error(err))
		return err
	}
	return nil
}

func SetupNetworkNamespace(ctx context.Context, logger *zap.Logger) (string, func(*zap.Logger), error) {
	nsPath, err := filepath.Abs("netns")
	if err != nil {
		logger.Error("failed to get absolute path", zap.Error(err))
		return "", nil, err
	}

	var defers []func(*zap.Logger)
	defer func() {
		for i := len(defers) - 1; i >= 0; i-- {
			defers[i](logger)
		}
	}()

	if err := removeNetNamespace(logger, nsPath); err != nil {
		logger.Error("failed to remove existing netns", zap.Error(err))
		return "", nil, err
	}

	if err := os.WriteFile(nsPath, nil, 0644); err != nil {
		logger.Error("failed to create netns file", zap.Error(err))
		return "", nil, err
	}
	defers = append(defers, func(logger *zap.Logger) {
		if err := removeNetNamespace(logger, nsPath); err != nil {
			logger.Error("failed to remove network namespace", zap.Error(err))
		}
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- createNetNamespace(nsPath)
	}()

	if err := <-errCh; err != nil {
		logger.Error("failed to create network namespace", zap.Error(err))
		return "", nil, err
	}

	netavarkOptions, err := json.Marshal(struct {
		nettypes.NetworkOptions
		Networks map[string]*nettypes.Network `json:"network_info"`
	}{
		NetworkOptions: nettypes.NetworkOptions{
			ContainerID: "exploits",
			Networks: map[string]nettypes.PerNetworkOptions{
				"pwnbot": {
					InterfaceName: "eth0",
					StaticIPs: []net.IP{
						net.IPv4(192, 168, 88, 86),
						[]byte{0xfd, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88},
					},
				},
			},
		},
		Networks: map[string]*nettypes.Network{
			"pwnbot": {
				ID:               "pwnbot",
				NetworkInterface: "pwnbot",
				Driver:           nettypes.BridgeNetworkDriver,
				Subnets: []nettypes.Subnet{{
					Subnet: nettypes.IPNet{IPNet: net.IPNet{
						IP:   net.IPv4(192, 168, 88, 84),
						Mask: net.CIDRMask(30, 32),
					}},
					Gateway: net.IPv4(192, 168, 88, 85),
				}, {
					Subnet: nettypes.IPNet{IPNet: net.IPNet{
						IP:   []byte{0xfd, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88},
						Mask: net.CIDRMask(127, 128),
					}},
					Gateway: []byte{0xfd, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x89},
				}},
				IPv6Enabled: true,
			},
		},
	})
	if err != nil {
		logger.Error("failed to marshal netavark options", zap.Error(err))
		return "", nil, err
	}

	defers = append(defers, func(logger *zap.Logger) {
		cmd := exec.Command("netavark", "--config", networkRoot, "--firewall-driver", "iptables", "teardown", nsPath)
		cmd.Stdin = bytes.NewReader(netavarkOptions)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			logger.Error("failed to run netavark teardown command", zap.Error(err))
		}
	})

	cmd := exec.CommandContext(ctx, "netavark", "--config", networkRoot, "--firewall-driver", "iptables", "setup", nsPath)
	cmd.Stdin = bytes.NewReader(netavarkOptions)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		logger.Error("failed to run netavark command", zap.Error(err))
		return "", nil, err
	}

	var swappedDefers []func(*zap.Logger)
	swappedDefers, defers = defers, swappedDefers
	return nsPath, func(logger *zap.Logger) {
		for i := len(swappedDefers) - 1; i >= 0; i-- {
			swappedDefers[i](logger)
		}
	}, nil
}
