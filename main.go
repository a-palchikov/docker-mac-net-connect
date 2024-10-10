//go:build darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/chipmk/docker-mac-net-connect/networkmanager"
	"github.com/chipmk/docker-mac-net-connect/version"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

const (
	ENV_WG_TUN_FD             = "WG_TUN_FD"
	ENV_WG_UAPI_FD            = "WG_UAPI_FD"
	ENV_WG_PROCESS_FOREGROUND = "WG_PROCESS_FOREGROUND"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	level := slog.LevelDebug
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		if err := level.UnmarshalText([]byte(logLevel)); err != nil {
			return fmt.Errorf("invalid log level, expected one of %q or a <level><+-numeral>", loggingLevels)
		}
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))

	log.Info("docker-mac-net-connect", slog.String("version", version.Version))

	tun, err := tun.CreateTUN("utun", device.DefaultMTU)
	if err != nil {
		return fmt.Errorf("creating TUN device: %w", err)
	}

	interfaceName, err := tun.Name()
	if err != nil {
		return fmt.Errorf("getting TUN device name: %w", err)
	}

	logger := log.With(slog.String("iface", interfaceName))

	fileUAPI, err := ipc.UAPIOpen(interfaceName)
	if err != nil {
		return fmt.Errorf("opening UAPI: %w", err)
	}

	logw := slogWrapper{Logger: logger}
	device := device.NewDevice(tun, conn.NewDefaultBind(), &device.Logger{Verbosef: logw.Verbosef, Errorf: logw.Errorf})

	logger.Debug("Device started")

	errChan := make(chan error, 1)
	uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
	if err != nil {
		return fmt.Errorf("listening on UAPI socket: %w", err)
	}

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errChan <- err
				return
			}
			go device.IpcHandle(conn)
		}
	}()

	logger.Debug("UAPI listener started")

	// Wireguard configuration
	const (
		hostPeerIP = "10.33.33.1"
		vmPeerIP   = "10.33.33.2"
	)

	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("creating new wgctrl client: %w", err)
	}
	defer c.Close()

	hostPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generate host private key: %w", err)
	}

	vmPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generate VM private key: %w", err)
	}

	_, wildcardIpNet, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		return fmt.Errorf("parsing wildcard CIDR: %w", err)
	}

	_, vmIpNet, err := net.ParseCIDR(vmPeerIP + "/32")
	if err != nil {
		return fmt.Errorf("parsing VM peer CIDR: %w", err)
	}

	peer := wgtypes.PeerConfig{
		PublicKey: vmPrivateKey.PublicKey(),
		AllowedIPs: []net.IPNet{
			*wildcardIpNet,
			*vmIpNet,
		},
	}

	port := 3333
	err = c.ConfigureDevice(interfaceName, wgtypes.Config{
		ListenPort: &port,
		PrivateKey: &hostPrivateKey,
		Peers:      []wgtypes.PeerConfig{peer},
	})
	if err != nil {
		return fmt.Errorf("configuring Wireguard device: %w", err)
	}

	networkManager := networkmanager.New()

	_, stderr, err := networkManager.SetInterfaceAddress(hostPeerIP, vmPeerIP, interfaceName)
	if err != nil {
		return fmt.Errorf("setting interface address with ifconfig (%s): %w", stderr, err)
	}

	logger.Debug("Interface created", slog.String("iface", interfaceName))

	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return fmt.Errorf("creating Docker client: %w", err)
	}

	logger.Debug("Wireguard server listening")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		for {
			logger.Debug("Setting up Wireguard on Docker Desktop VM")

			err = setupVm(ctx, cli, port, hostPeerIP, vmPeerIP, hostPrivateKey, vmPrivateKey, logger)
			if err != nil {
				logger.Warn("Failed to setup VM", slog.Any("err", err))
				time.Sleep(5 * time.Second)
				continue
			}

			networks, err := cli.NetworkList(ctx, types.NetworkListOptions{})
			if err != nil {
				logger.Warn("Failed to list Docker networks", slog.Any("err", err))
				time.Sleep(5 * time.Second)
				continue
			}

			for _, network := range networks {
				networkManager.ProcessDockerNetworkCreate(network, interfaceName)
			}

			logger.Debug("Watching Docker events")

			msgs, errsChan := cli.Events(ctx, types.EventsOptions{
				Filters: filters.NewArgs(
					filters.Arg("type", "network"),
					filters.Arg("event", "create"),
					filters.Arg("event", "destroy"),
				),
			})

			for {
				select {
				case err := <-errsChan:
					select {
					case errChan <- err:
					case <-ctx.Done():
					}
					return
				case msg := <-msgs:
					// Add routes when new Docker networks are created
					if msg.Type == "network" && msg.Action == "create" {
						network, err := cli.NetworkInspect(ctx, msg.Actor.ID, types.NetworkInspectOptions{})
						if err != nil {
							logger.Warn("Failed to inspect new Docker network", slog.Any("err", err))
							continue
						}

						networkManager.ProcessDockerNetworkCreate(network, interfaceName)
						continue
					}

					// Delete routes when Docker networks are destroyed
					if msg.Type == "network" && msg.Action == "destroy" {
						network, exists := networkManager.DockerNetworks[msg.Actor.ID]
						if !exists {
							logger.Warn("Unknown Docker network. No routes will be removed.", slog.String("network", msg.Actor.ID))
							continue
						}

						networkManager.ProcessDockerNetworkDestroy(network)
						continue
					}
				case <-ctx.Done():
					log.Debug("Context cancelled, closing routes loop")
					return
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
	case <-errChan:
	case <-device.Wait():
	}

	// Clean up
	uapi.Close()
	device.Close()

	logger.Debug("Shutting down")
	return nil
}

func setupVm(
	ctx context.Context,
	dockerCli *client.Client,
	serverPort int,
	hostPeerIp string,
	vmPeerIp string,
	hostPrivateKey wgtypes.Key,
	vmPrivateKey wgtypes.Key,
	log *slog.Logger,
) error {
	imageName := fmt.Sprintf("%s:%s", version.SetupImage, getSetupImageVersion())

	_, _, err := dockerCli.ImageInspectWithRaw(ctx, imageName)
	if err != nil {
		log.Debug("Image doesn't exist locally. Pulling...", slog.String("image", imageName))

		pullStream, err := dockerCli.ImagePull(ctx, imageName, types.ImagePullOptions{})
		if err != nil {
			return fmt.Errorf("pulling setup image: %w", err)
		}

		_, _ = io.Copy(os.Stdout, pullStream)
	}

	resp, err := dockerCli.ContainerCreate(ctx, &container.Config{
		Image: imageName,
		Env: []string{
			"SERVER_PORT=" + strconv.Itoa(serverPort),
			"HOST_PEER_IP=" + hostPeerIp,
			"VM_PEER_IP=" + vmPeerIp,
			"HOST_PUBLIC_KEY=" + hostPrivateKey.PublicKey().String(),
			"VM_PRIVATE_KEY=" + vmPrivateKey.String(),
		},
	}, &container.HostConfig{
		AutoRemove:  true,
		NetworkMode: "host",
		CapAdd:      []string{"NET_ADMIN"},
	}, nil, nil, "wireguard-setup")
	if err != nil {
		return fmt.Errorf("creating container: %w", err)
	}

	// Run container to completion
	err = dockerCli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{})
	if err != nil {
		return fmt.Errorf("starting container: %w", err)
	}

	func() error {
		reader, err := dockerCli.ContainerLogs(ctx, resp.ID, types.ContainerLogsOptions{
			ShowStdout: true,
			ShowStderr: true,
			Follow:     true,
		})
		if err != nil {
			return fmt.Errorf("getting logs for container %s: %w", resp.ID, err)
		}

		defer reader.Close()

		_, err = stdcopy.StdCopy(os.Stdout, os.Stderr, reader)
		if err != nil {
			return err
		}

		return nil
	}()

	log.Info("Setup container complete")

	return nil
}

func getSetupImageVersion() string {
	if imageTag := os.Getenv("DOCKER_MAC_NET_SETUP_IMAGE_TAG"); imageTag != "" {
		return imageTag
	}
	return version.Version
}

type Level slog.Level

func (r Level) String() string {
	return strings.ToLower(slog.Level(r).String())
}

const (
	DebugLevel = Level(slog.LevelDebug)
	InfoLevel  = Level(slog.LevelInfo)
	WarnLevel  = Level(slog.LevelWarn)
	ErrorLevel = Level(slog.LevelError)
)

var loggingLevels = []string{
	strings.ToLower(DebugLevel.String()),
	strings.ToLower(InfoLevel.String()),
	strings.ToLower(WarnLevel.String()),
	strings.ToLower(ErrorLevel.String()),
}

func (r slogWrapper) Verbosef(format string, args ...any) {
	m := fmt.Sprintf(format, args...)
	r.Debug(m)
}

func (r slogWrapper) Errorf(format string, args ...any) {
	m := fmt.Sprintf(format, args...)
	r.Debug(m)
}

type slogWrapper struct {
	*slog.Logger
}

var errSetupFailed = errors.New("setup failed")
