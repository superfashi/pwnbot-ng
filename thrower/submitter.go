package thrower

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

func (s *scheduler) runFlagProcessor(ctx context.Context, logger *zap.Logger, runId string, key taskKey, lineCh <-chan string) func() bool {
	f := sync.OnceValue(func() (success bool) {
		// every 100ms, allow up to 10 bursts
		limiter := rate.NewLimiter(rate.Every(100*time.Millisecond), 10)

		for line := range lineCh {
			for _, reg := range s.defaults.Load().flagRegexes {
				submatch := reg.FindStringSubmatchIndex(line)
				if submatch == nil {
					continue
				}
				if err := limiter.Wait(ctx); err != nil {
					if !errors.Is(err, context.Canceled) {
						logger.Error("internal limiter error", zap.Error(err))
					}
					return
				}
				if s.submitFlag(ctx, logger, line[submatch[2]:submatch[3]]) {
					success = true
				}
			}
		}
		return
	})
	go f()

	return f
}

func (s *scheduler) submitFlag(ctx context.Context, logger *zap.Logger, flag string) bool {
	submitter := *s.submitter.Load()
	if submitter == "" {
		logger.Info("got flag", zap.String("flag", flag))
		return true
	}

	cmd := exec.CommandContext(ctx, submitter, flag)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		logger.Error("failed to submit flag", zap.String("flag", flag), zap.Error(err), zap.Stringer("stdout", &stdout), zap.Stringer("stderr", &stderr))
		return false
	}

	logger.Debug("flag submitted", zap.String("flag", flag), zap.Stringer("stdout", &stdout), zap.Stringer("stderr", &stderr))
	return true
}
