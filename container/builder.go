package container

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/containers/buildah"
	"github.com/containers/buildah/imagebuildah"
	"github.com/containers/storage"
	"github.com/opencontainers/runtime-spec/specs-go"
	"go.uber.org/zap"

	"pwnbot-ng/utils"
)

type asyncBuilder struct {
	close context.CancelFunc
}

const defaultImageTag = "pwnbot/default-image"

func (e *Engine) newAsyncBuilderFromDir(ctx context.Context, logger *zap.Logger, key ExecutorKey, baseDir string, noPull bool) *asyncBuilder {
	ctx, cancel := context.WithCancel(ctx)

	builder := &asyncBuilder{close: cancel}
	e.wg.Add(1)
	go func() {
		defer cancel()
		defer e.wg.Done()

		logger := logger.With(zap.Stringer("key", key))

		if err := e.buildSemaphore.Acquire(ctx, 1); err != nil {
			logger.Warn("building image cancelled", zap.Error(err))
			return
		}
		defer e.buildSemaphore.Release(1)

		for ctx.Err() == nil {
			id, err := func() (string, error) {
				timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(e.buildTimeout.Load()))
				defer cancel()

				runId := utils.GenerateRunID()
				logger := logger.With(zap.String("run_id", runId))

				logDir := strings.Join(
					[]string{
						e.logPath,
						key.String(),
						runId,
						"",
					}, "/")
				if err := os.MkdirAll(logDir, 0755); err != nil {
					logger.Error("failed to create log directory", zap.String("dir", logDir), zap.Error(err))
					return "", err
				}

				logger.Info("building image from directory", zap.String("dir", baseDir))

				outFile, err := os.Create(logDir + "stdout")
				if err != nil {
					logger.Error("failed to create stdout log file", zap.String("file", logDir+"stdout"), zap.Error(err))
					return "", err
				}
				defer func() {
					if err := outFile.Close(); err != nil {
						logger.Error("failed to close stdout log file", zap.String("file", logDir+"stdout"), zap.Error(err))
					}
				}()

				errFile, err := os.Create(logDir + "stderr")
				if err != nil {
					logger.Error("failed to create stderr log file", zap.String("file", logDir+"stderr"), zap.Error(err))
					return "", err
				}
				defer func() {
					if err := errFile.Close(); err != nil {
						logger.Error("failed to close stderr log file", zap.String("file", logDir+"stderr"), zap.Error(err))
					}
				}()

				buildOption := imagebuildah.BuildOptions{
					Isolation:        buildah.IsolationOCI,
					NetworkInterface: nilNetwork{},
					OutputFormat:     buildah.OCIv1ImageManifest,
					NamespaceOptions: buildah.NamespaceOptions{{
						Name: "network",
						Path: e.networkNs,
					}},
					SystemContext:           systemContext,
					Layers:                  true,
					RemoveIntermediateCtrs:  true,
					ForceRmIntermediateCtrs: true,
					ContextDirectory:        baseDir,
					MaxPullPushRetries:      0,
					In:                      utils.DevNull,
					Out:                     outFile,
					Err:                     errFile,
				}
				if key == DefaultExecutorKey {
					buildOption.Output = defaultImageTag
				}
				if noPull {
					buildOption.PullPolicy = buildah.PullNever
				} else {
					buildOption.PullPolicy = buildah.PullIfMissing
				}
				id, _, err := imagebuildah.BuildDockerfiles(timeoutCtx, e.store, buildOption, baseDir+"/Dockerfile")
				return id, err
			}()
			if err == nil {
				logger.Info("image built", zap.String("id", id))
				e.notifySubscribers(key, newExecutor(&e.wg, e.store, e.networkNs, id))
				return
			}
			logger.Error("error building docker files", zap.Error(err))
			select {
			case <-ctx.Done():
			case <-time.After(time.Duration(e.retryInterval.Load())):
				continue
			}
			break
		}
		logger.Warn("building image cancelled", zap.Error(ctx.Err()))
	}()

	return builder
}

type BindMount struct {
	Source      string
	Destination string
	Options     []string
}

type RunOptions struct {
	Args            []string
	Stdin           io.Reader
	Stdout          io.Writer
	Stderr          io.Writer
	BindMounts      []BindMount
	Envs            []string
	StartedCallback func(pid int)
}

type Executor = func(context.Context, *zap.Logger, RunOptions) error

func newExecutor(wg *sync.WaitGroup, store storage.Store, nsPath, id string) Executor {
	return func(ctx context.Context, logger *zap.Logger, opt RunOptions) error {
		wg.Add(1)
		defer wg.Done()

		builder, err := buildah.NewBuilder(ctx, store, buildah.BuilderOptions{
			FromImage:        id,
			Isolation:        buildah.IsolationOCI,
			NetworkInterface: nilNetwork{},
			PullPolicy:       buildah.PullNever,
			NamespaceOptions: buildah.NamespaceOptions{{
				Name: "network",
				Path: nsPath,
			}},
			SystemContext: systemContext,
		})
		if err != nil {
			logger.Error("error creating image container", zap.Error(err))
			return err
		}

		defer func() {
			if err := builder.Delete(); err != nil {
				logger.Error("error deleting image container", zap.Error(err))
			}
		}()

		mounts := make([]specs.Mount, 0, len(opt.BindMounts))
		for _, bind := range opt.BindMounts {
			mounts = append(mounts, specs.Mount{
				Destination: bind.Destination,
				Type:        "bind",
				Source:      bind.Source,
				Options:     bind.Options,
			})
		}

		return builder.Run(opt.Args, buildah.RunOptions{
			Isolation: buildah.IsolationOCI,
			NamespaceOptions: buildah.NamespaceOptions{{
				Name: "network",
				Path: nsPath,
			}},
			SystemContext:   systemContext,
			Mounts:          mounts,
			Env:             opt.Envs,
			Terminal:        buildah.WithoutTerminal,
			Stdin:           opt.Stdin,
			Stdout:          opt.Stdout,
			Stderr:          opt.Stderr,
			StartedCallback: opt.StartedCallback,
		})
	}
}
