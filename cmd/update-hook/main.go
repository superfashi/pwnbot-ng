package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-git/go-git/v5/plumbing"
	"go.uber.org/zap"

	"pwnbot-ng/repo"
)

func main() {
	newCommit := plumbing.NewHash(os.Args[3])
	if newCommit.IsZero() {
		// deleting, whatever
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := repo.CheckLocalRepository(ctx, zap.NewNop(), newCommit); err != nil {
		_, _ = io.WriteString(os.Stderr, err.Error()+"\n")
		os.Exit(1)
	}
}
