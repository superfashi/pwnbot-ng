package main

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	"github.com/containers/buildah"
	"go.uber.org/zap"

	"pwnbot-ng/container"
	"pwnbot-ng/preprocess"
	"pwnbot-ng/proxy"
	"pwnbot-ng/repo"
	"pwnbot-ng/thrower"
)

func main() {
	if buildah.InitReexec() {
		return
	}

	syscall.Umask(0)

	kingpin.CommandLine.Name = "pwnbot-local"
	kingpin.CommandLine.Help = "Pwn the world (but locally)"
	kingpin.CommandLine.HelpFlag.Short('h')
	var (
		exploitsSel = kingpin.Flag("exploits", "Exploits to run (in the form of <service>/<exploit>)").Strings()
		teamsSel    = kingpin.Flag("teams", "Teams to run exploits against").Strings()
		workDir     = kingpin.Flag("workdir", "Working directory for pwnbot").PlaceHolder("~/.pwnbot").String()
	)
	kingpin.Parse()

	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("starting pwnbot local")

	repoDir, err := os.Getwd()
	if err != nil {
		logger.Panic("failed to get current working directory", zap.Error(err))
	}

	if *workDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			logger.Panic("failed to get home directory", zap.Error(err))
		}
		wd := filepath.Join(homeDir, ".pwnbot")
		if err := os.MkdirAll(wd, 0755); err != nil {
			logger.Panic("failed to create working directory", zap.String("workdir", wd), zap.Error(err))
		}
		workDir = &wd
	}
	if err := os.Chdir(*workDir); err != nil {
		logger.Panic("failed to change working directory", zap.String("workdir", *workDir), zap.Error(err))
	}

	combined, err := repo.NewLocalRepository(ctx, logger.Named("repo"), repoDir)
	if err != nil {
		logger.Panic("failed to load local repository", zap.Error(err))
	}

	if *exploitsSel != nil {
		for i := range combined.Exploits {
			combined.Exploits[i].Refs = slices.DeleteFunc(combined.Exploits[i].Refs, func(r repo.ExploitRef) bool {
				return !slices.Contains(*exploitsSel, r.Service+"/"+r.Name)
			})
		}
		combined.Exploits = slices.DeleteFunc(combined.Exploits, func(e repo.ExploitWithRefs) bool {
			return len(e.Refs) == 0
		})
	}
	if *teamsSel != nil {
		combined.Teams = slices.DeleteFunc(combined.Teams, func(t *repo.Team) bool {
			return !slices.Contains(*teamsSel, t.Name)
		})
	}

	exploits := make([]*repo.Exploit, 0, len(combined.Exploits))
	for _, exp := range combined.Exploits {
		exploits = append(exploits, exp.Exploit)
	}

	proxy.CleanupRules(logger.Named("proxy.cleanup"))

	netLogger := logger.Named("network")
	netNsPath, closer, err := container.SetupNetworkNamespace(ctx, netLogger)
	if err != nil {
		logger.Panic("failed to setup network namespace", zap.Error(err))
	}
	defer closer(netLogger)

	logger.Info("building local executors")
	executors, err := container.BuildLocalExecutor(ctx, logger.Named("container"), netNsPath, combined.Config, exploits, combined.DefaultImage)
	if err != nil {
		logger.Panic("failed to build local executors", zap.Error(err))
	}

	logger.Info("preprocessing services")
	preprocessed := preprocess.RunPreprocessLocal(ctx, logger.Named("preprocess"), combined.Services, combined.Teams, combined.Preprocesses)
	if preprocessed == nil {
		logger.Panic("failed to preprocess services")
	}

	logger.Info("throwing exploits")
	thrower.ThrowOnce(ctx, logger.Named("thrower"), combined.FlagSubmitter, combined.Config, combined.Exploits, preprocessed, executors)
}
