package container

import (
	"context"
	"os"
	"sync"
	"sync/atomic"

	"github.com/cockroachdb/crlib/fifo"
	"github.com/containers/image/v5/types"
	"github.com/containers/storage"
	"github.com/go-git/go-git/v5/plumbing"
	"go.uber.org/zap"

	"pwnbot-ng/repo"
)

const policyContent = `{"default":[{"type":"insecureAcceptAnything"}]}`

const (
	runRoot     = "container/run"
	graphRoot   = "container/storage"
	networkRoot = "container/network"
	policyPath  = "policy.json"
)

var systemContext = &types.SystemContext{
	SignaturePolicyPath: policyPath,
	PodmanOnlyShortNamesIgnoreRegistriesConfAndForceDockerHub: true,
}

type Engine struct {
	logPath   string
	networkNs string

	store storage.Store

	buildTimeout   atomic.Int64 // time.Duration
	retryInterval  atomic.Int64 // time.Duration
	buildSemaphore *fifo.Semaphore

	defaultImageBuilt chan struct{}

	subscribersLock sync.Mutex
	subscribers     []chan<- ExecutorNotify

	wg     sync.WaitGroup
	cancel context.CancelFunc
}

func commonInit(logger *zap.Logger, logPath, netNsPath string) (*Engine, error) {
	if err := os.MkdirAll(logPath, 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(runRoot, 0755); err != nil {
		logger.Error("failed to create run root directory", zap.Error(err))
		return nil, err
	}
	if err := os.MkdirAll(graphRoot, 0755); err != nil {
		logger.Error("failed to create graph root directory", zap.Error(err))
		return nil, err
	}
	if err := os.WriteFile(policyPath, []byte(policyContent), 0644); err != nil {
		logger.Error("failed to write policy file", zap.Error(err))
		return nil, err
	}

	store, err := storage.GetStore(storage.StoreOptions{
		RunRoot:   runRoot,
		GraphRoot: graphRoot,
	})
	if err != nil {
		logger.Error("failed to get store", zap.Error(err))
		return nil, err
	}

	e := &Engine{
		logPath:           logPath,
		networkNs:         netNsPath,
		store:             store,
		buildSemaphore:    fifo.NewSemaphore(1),
		defaultImageBuilt: make(chan struct{}),
	}
	return e, nil
}

func StartEngine(
	ctx context.Context,
	logger *zap.Logger,
	logPath, netNsPath string,
	configChan <-chan *repo.ConfigValues,
	exploitsChan <-chan []repo.ExploitWithRefs,
	defaultImageChan <-chan *repo.DefaultImage,
) (*Engine, error) {
	e, err := commonInit(logger, logPath, netNsPath)
	if err != nil {
		return nil, err
	}
	newCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel

	e.wg.Add(1)
	go e.background(newCtx, logger, configChan, exploitsChan, defaultImageChan)

	return e, nil
}

func BuildLocalExecutor(
	ctx context.Context,
	logger *zap.Logger,
	netNsPath string,
	config *repo.ConfigValues,
	exploits []*repo.Exploit,
	defaultImage *repo.DefaultImage,
) (map[ExecutorKey]Executor, error) {
	e, err := commonInit(logger, "logs/container", netNsPath)
	if err != nil {
		return nil, err
	}

	executorCh := e.SubscribeExecutor()

	e.buildTimeout.Store(int64(config.DockerBuildTimeout))
	e.retryInterval.Store(int64(config.DockerBuildRetryInterval))
	e.buildSemaphore.UpdateCapacity(int64(config.DockerBuildConcurrency))

	builders := make(map[ExecutorKey]*asyncBuilder, len(exploits)+1)

	builders[DefaultExecutorKey] = e.newAsyncBuilderFromDir(ctx, logger, DefaultExecutorKey, defaultImage.ExtractPath, false)

	var later []*repo.Exploit
	for _, exploit := range exploits {
		if key := GetExecutorKey(exploit); key != DefaultExecutorKey {
			if checkIfDockerfileDependentOnDefault(logger, exploit) {
				logger.Debug("dependent on default image", zap.Stringer("key", key))
				later = append(later, exploit)
			} else {
				builders[key] = e.newAsyncBuilderFromDir(ctx, logger, key, exploit.ExtractPath, false)
			}
		}
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-e.defaultImageBuilt:
	}

	for _, exploit := range later {
		key := GetExecutorKey(exploit)
		builders[key] = e.newAsyncBuilderFromDir(ctx, logger, key, exploit.ExtractPath, true)
	}

	tasks := len(builders)
	executors := make(map[ExecutorKey]Executor, tasks)
	for range tasks {
		select {
		case notify := <-executorCh:
			executors[notify.Key] = notify.Executor
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return executors, nil
}

func (e *Engine) Stop(logger *zap.Logger) {
	logger.Info("stopping container engine")
	e.cancel()
	e.wg.Wait()
	if _, err := e.store.Shutdown(true); err != nil {
		logger.Error("error shutting down container store", zap.Error(err))
	}
}

func (e *Engine) SubscribeExecutor() <-chan ExecutorNotify {
	ch := make(chan ExecutorNotify, 10)

	e.subscribersLock.Lock()
	defer e.subscribersLock.Unlock()

	e.subscribers = append(e.subscribers, ch)
	return ch
}

type ExecutorKey = plumbing.Hash

var DefaultExecutorKey = plumbing.ZeroHash

func GetExecutorKey(exploit *repo.Exploit) ExecutorKey {
	if exploit.HasDockerFile {
		return exploit.TreeHash
	}
	return DefaultExecutorKey
}

type ExecutorNotify struct {
	Key ExecutorKey
	Executor
}

func (e *Engine) notifySubscribers(key ExecutorKey, exe Executor) {
	subs := func() []chan<- ExecutorNotify {
		e.subscribersLock.Lock()
		defer e.subscribersLock.Unlock()
		return e.subscribers
	}()
	for _, sub := range subs {
		sub <- ExecutorNotify{
			Key:      key,
			Executor: exe,
		}
	}
	if key == DefaultExecutorKey {
		e.defaultImageBuilt <- struct{}{}
	}
}

func (e *Engine) background(
	ctx context.Context, logger *zap.Logger,
	configChan <-chan *repo.ConfigValues, exploitsChan <-chan []repo.ExploitWithRefs, defaultImageChan <-chan *repo.DefaultImage,
) {
	defer e.wg.Done()

	var (
		defaultImageHash plumbing.Hash
		defaultBuilt     bool
		defaultDependent = make(map[ExecutorKey]string)
		builders         = make(map[ExecutorKey]*asyncBuilder)
	)
	for {
		select {
		case <-ctx.Done():
			return
		case config := <-configChan: // implementation guarantees that this is given first
			e.buildTimeout.Store(int64(config.DockerBuildTimeout))
			e.retryInterval.Store(int64(config.DockerBuildRetryInterval))
			e.buildSemaphore.UpdateCapacity(int64(config.DockerBuildConcurrency))
		case dftImg := <-defaultImageChan:
			if dftImg.TreeHash != defaultImageHash {
				defaultImageHash = dftImg.TreeHash
				if old, ok := builders[DefaultExecutorKey]; ok {
					old.close()
				}
				builders[DefaultExecutorKey] = e.newAsyncBuilderFromDir(ctx, logger, DefaultExecutorKey, dftImg.ExtractPath, false)
			}
		case <-e.defaultImageBuilt:
			defaultBuilt = true
			for key, path := range defaultDependent {
				if builder, ok := builders[key]; ok {
					// cancel current build
					builder.close()
				}
				builders[key] = e.newAsyncBuilderFromDir(ctx, logger, key, path, true)
			}
		case exploits := <-exploitsChan:
			expMaps := make(map[ExecutorKey]*repo.Exploit, len(exploits))
			for _, exploit := range exploits {
				if key := GetExecutorKey(exploit.Exploit); key != DefaultExecutorKey {
					expMaps[key] = exploit.Exploit
				}
			}

			for existing, builder := range builders {
				if existing == DefaultExecutorKey {
					continue
				}
				if _, ok := expMaps[existing]; !ok {
					builder.close()
					delete(builders, existing)
				}
			}

			for key := range defaultDependent {
				if _, ok := expMaps[key]; !ok {
					delete(defaultDependent, key)
				}
			}

			for key, exp := range expMaps {
				if _, ok := builders[key]; ok {
					continue
				}
				dependent := checkIfDockerfileDependentOnDefault(logger, exp)
				if dependent {
					logger.Debug("dependent on default image", zap.Stringer("key", key))
					defaultDependent[key] = exp.ExtractPath
					if !defaultBuilt {
						// retriggered by channel above
						continue
					}
				}
				builders[key] = e.newAsyncBuilderFromDir(ctx, logger, key, exp.ExtractPath, dependent)
			}
		}
	}
}
