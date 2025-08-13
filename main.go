package main

import (
	"context"
	"net/netip"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	"github.com/containers/buildah"
	"go.uber.org/zap"

	"pwnbot-ng/container"
	"pwnbot-ng/preprocess"
	"pwnbot-ng/proxy"
	"pwnbot-ng/repo"
	"pwnbot-ng/thrower"
	"pwnbot-ng/ticker"
)

type netIpPrefix netip.Prefix

func (n *netIpPrefix) Set(s string) error {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return err
	}
	*n = netIpPrefix(prefix)
	return nil
}

func (n *netIpPrefix) String() string {
	return (*netip.Prefix)(n).String()
}

func main() {
	if buildah.InitReexec() {
		return
	}

	syscall.Umask(0)

	kingpin.CommandLine.Name = "pwnbot"
	kingpin.CommandLine.Help = "Pwn the world"
	kingpin.CommandLine.HelpFlag.Short('h')
	var (
		gitRepo      = kingpin.Flag("repo", "Exploits git repo URL to clone from").Envar("PWNBOT_GIT_REPO").Required().String()
		logPath      = kingpin.Flag("log", "Path to write logs to").Envar("PWNBOT_LOG_PATH").Default("logs").String()
		roundDura    = kingpin.Flag("round", "Duration of a round in seconds").Envar("PWNBOT_ROUND_DURATION").Default("5m").Duration()
		tickerAddr   = kingpin.Flag("tick", "Address for the ticker to listen on").Envar("PWNBOT_TICKER_ADDR").Default("127.0.0.1:12450").String()
		proxyNetwork = func() *netip.Prefix {
			p := new(netip.Prefix)
			kingpin.Flag("proxy", "Network prefix for the proxy").Envar("PWNBOT_PROXY_NETWORK").PlaceHolder("10.10.0.0/20").SetValue((*netIpPrefix)(p))
			return p
		}()
	)
	kingpin.Parse()

	config := zap.NewDevelopmentConfig()
	config.DisableStacktrace = true
	logger, err := config.Build()
	if err != nil {
		panic(err)
	}

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("starting pwnbot")

	repoLogger := logger.Named("repo")
	r, err := repo.NewRepository(rootCtx, repoLogger, *gitRepo)
	if err != nil {
		logger.Panic("failed to initialize repository", zap.Error(err))
	}

	proxy.CleanupRules(logger.Named("proxy.cleanup"))

	networkLogger := logger.Named("network")
	netNsPath, closer, err := container.SetupNetworkNamespace(rootCtx, networkLogger)
	if err != nil {
		logger.Panic("failed to setup network namespace", zap.Error(err))
	}
	defer closer(networkLogger)

	proxyLogger := logger.Named("proxy")
	prox, err := proxy.CreateProxy(rootCtx, proxyLogger, *proxyNetwork, netNsPath)
	if err != nil {
		logger.Panic("failed to create proxy", zap.Error(err))
	}
	defer prox.Stop(proxyLogger)

	tick, err := ticker.NewTicker(rootCtx, logger.Named("ticker"), *tickerAddr, *roundDura)
	if err != nil {
		logger.Panic("failed to start ticker", zap.Error(err))
	}
	defer tick.Stop()

	containerLogger := logger.Named("container")
	engine, err := container.StartEngine(rootCtx, containerLogger, *logPath+"/container", netNsPath, r.SubscribeConfig(), r.SubscribeExploits(), r.SubscribeDefaultImage())
	if err != nil {
		logger.Panic("failed to start container engine", zap.Error(err))
	}
	defer engine.Stop(containerLogger)

	preprocessLogger := logger.Named("preprocess")
	preprocessor := preprocess.RunPreprocess(
		rootCtx,
		preprocessLogger,
		*logPath+"/preprocess",
		r.SubscribeServices(),
		r.SubscribeTeams(),
		r.SubscribePreprocess(),
		tick.SubscribeTicker(),
	)
	defer preprocessor.Close()

	throwerLogger := logger.Named("thrower")
	throw, err := thrower.NewThrower(
		rootCtx,
		throwerLogger,
		*logPath+"/thrower",
		prox,
		r.SubscribeConfig(),
		preprocessor.Subscribe(),
		r.SubscribeExploits(),
		engine.SubscribeExecutor(),
		r.SubscribeFlagSubmitter(),
		tick,
	)

	if err != nil {
		logger.Panic("failed to start thrower", zap.Error(err))
	}
	defer throw.Close()

	if err := r.Run(rootCtx, repoLogger); err != nil {
		logger.Panic("repository run exit", zap.Error(err))
	}
}
