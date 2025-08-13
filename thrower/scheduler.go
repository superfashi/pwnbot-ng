package thrower

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/puzpuzpuz/xsync/v4"
	"go.uber.org/zap"

	"pwnbot-ng/container"
	"pwnbot-ng/proxy"
	"pwnbot-ng/repo"
	"pwnbot-ng/ticker"
	"pwnbot-ng/utils"
)

type schedulerTaskPersist struct {
	retryCount  uint
	lastRunMono int64
	lastRunTime time.Time
}

type schedulerTask struct {
	service  repo.Service
	team     repo.Team
	exploit  *repo.Exploit
	executor container.Executor
	*schedulerTaskPersist
}

type taskKey struct {
	service string
	team    string
	exploit string
}

type taskKeyWithResult struct {
	taskKey
	success      bool
	rejected     bool
	finishedTime time.Time
}

type taskKey2 struct {
	service string
	team    string
}

func (k taskKey) to2() taskKey2 {
	return taskKey2{
		service: k.service,
		team:    k.team,
	}
}

type throwerConfig struct {
	flagRegexes []*regexp.Regexp
	timeout     time.Duration
	cooldown    time.Duration
	retries     uint
}

func throwerConfigFromRepoConfig(config *repo.ConfigValues) *throwerConfig {
	return &throwerConfig{
		flagRegexes: config.FlagRegex,
		timeout:     config.DefaultTimeout,
		cooldown:    config.DefaultCooldown,
		retries:     config.DefaultRetries,
	}
}

type runningInfo struct {
	debug     string
	allocator *proxy.PreAllocator
	rejected  *atomic.Int32
	sockets   xsync.Map[uint32, context.CancelFunc] // inode -> cancel()
	obfuscate *bool                                 // obfuscate traffic
}

type scheduler struct {
	thrower *Thrower
	ticker  *ticker.Ticker

	tasks     atomic.Pointer[map[taskKey]*schedulerTask]
	defaults  atomic.Pointer[throwerConfig]
	submitter atomic.Pointer[repo.Submitter]

	runningTasks map[taskKey2]map[string]struct{} // {(service, team), exploit}
	runningInfos xsync.Map[int, *runningInfo]     // pid -> {inode -> cancelFunc}

	mono int64

	finished chan *taskKeyWithResult
}

func newScheduler(thrower *Thrower, ticker *ticker.Ticker) *scheduler {
	s := &scheduler{
		thrower:      thrower,
		ticker:       ticker,
		runningTasks: make(map[taskKey2]map[string]struct{}),
		runningInfos: *xsync.NewMap[int, *runningInfo](),
		finished:     make(chan *taskKeyWithResult, 10000), // this has to be big enough
	}
	var empty map[taskKey]*schedulerTask
	s.tasks.Store(&empty)
	return s
}

func (s *scheduler) getGetHandler(logger *zap.Logger) proxy.GetHandlerFunc {
	return func(cancel context.CancelFunc, inode uint32) proxy.Handler {
		target := fmt.Sprintf("socket:[%d]", inode)
		for pid, info := range s.runningInfos.Range {
			if searchInNamespace(logger, pid, target) {
				// found
				info.sockets.Store(inode, cancel)
				return &handler{
					info:  info,
					inode: inode,
				}
			}
		}
		return nil
	}
}

func (s *scheduler) getRetries(task *schedulerTask) uint {
	if task.exploit.Retries != nil {
		return *task.exploit.Retries
	}
	return s.defaults.Load().retries
}

func (s *scheduler) clearTask(key *taskKeyWithResult) {
	if key == nil {
		return
	}
	delete(s.runningTasks[key.to2()], key.exploit)
	if !key.rejected {
		if task, ok := (*s.tasks.Load())[key.taskKey]; ok {
			if key.success || task.retryCount >= s.getRetries(task) {
				task.retryCount = 0
			} else {
				task.retryCount++
			}
			task.lastRunMono = s.mono           // reset the monotonic age
			task.lastRunTime = key.finishedTime // update the last run time
		}
	} else {
		// if rejected, taken as if the run did not happen
	}
}

func (s *scheduler) run(ctx context.Context, logger *zap.Logger) {
	defer s.thrower.wg.Done()

	logger.Info("scheduler started")

out:
	for {
		var cooldown <-chan time.Time
		for {
			for {
				// drain the finished channel
				select {
				case key := <-s.finished:
					s.clearTask(key)
					continue
				case <-ctx.Done():
					break out
				default:
				}
				break
			}

			var key *taskKey
			key, cooldown = s.selectTask(ctx, logger)
			if key == nil {
				// no tasks available, wait
				break
			}
			s.mono++
			s.startTask(ctx, logger, *key)
		}

		// waiting because tasks are all running
		select {
		// we don't need ticker here, as ticker -> preprocess -> update -> kick
		case <-ctx.Done():
			break out
		case <-cooldown:
		case key := <-s.finished:
			s.clearTask(key)
		}
	}

	logger.Debug("scheduler stopped")
}

func (s *scheduler) runOnce(ctx context.Context, logger *zap.Logger) {
	tasks := *s.tasks.Load()

	for key := range tasks {
		s.startTask(ctx, logger, key)
	}
	for range len(tasks) {
		select {
		case <-s.finished:
		case <-ctx.Done():
			return
		}
	}
}

func (s *scheduler) startTask(ctx context.Context, logger *zap.Logger, key taskKey) {
	runId := utils.GenerateRunID()
	logger = logger.With(
		zap.String("service", key.service),
		zap.String("team", key.team),
		zap.String("exploit", key.exploit),
		zap.String("run_id", runId),
	)

	persistentBase, err := filepath.Abs(strings.Join([]string{
		"vault",
		key.service,
		key.exploit,
	}, "/"))

	if err != nil {
		logger.Error("failed to get absolute path for persistent base", zap.Error(err))
		return
	}

	if err := os.MkdirAll(persistentBase, 0777); err != nil {
		logger.Error("failed to create persistent base directory", zap.Error(err), zap.String("path", persistentBase))
		return
	}

	logBase := strings.Join([]string{
		s.thrower.logPath,
		key.service,
		strings.ReplaceAll(key.team, "/", "_"),
		key.exploit,
		runId,
		"",
	}, "/")

	if err := os.MkdirAll(logBase, 0755); err != nil {
		logger.Error("failed to create logs base directory", zap.Error(err), zap.String("path", logBase))
		return
	}

	task := (*s.tasks.Load())[key]
	if task == nil {
		// oops, task got removed after selection
		return
	}

	if task.retryCount > 0 {
		logger.With(zap.Uint("retry", task.retryCount))
	}

	envsMap := map[string]any{
		"NOTERM": true,
		"REMOTE": true,
		"HOST":   task.team.Host,
		"PORT":   task.service.Port,
	}
	for k, v := range task.service.Extra {
		envsMap[strings.ToUpper(k)] = v
	}
	for k, v := range task.team.Extra {
		envsMap[strings.ToUpper(k)] = v
	}
	envs := make([]string, 0, len(envsMap)+1)
	for k, v := range envsMap {
		envs = append(envs, fmt.Sprintf("PWNLIB_%s=%v", k, v))
	}
	envs = append(envs, "PYTHONUNBUFFERED=1")

	allocator := s.thrower.proxy.PreAllocate(ctx, logger, int64(task.exploit.ConcurrentConnections))
	if allocator == nil {
		// probably only because the context is cancelled
		return
	}
	// make sure no errors between here and defer allocator.ReleaseAll()

	key2 := key.to2()
	if _, ok := s.runningTasks[key2]; !ok {
		s.runningTasks[key2] = make(map[string]struct{})
	}
	s.runningTasks[key2][key.exploit] = struct{}{}

	s.thrower.wg.Add(1)
	go func() {
		defer s.thrower.wg.Done()
		defer allocator.ReleaseAll()

		const lineBufferSize = 20 // back pressure exploit
		lineCh := make(chan string, lineBufferSize)
		var closed bool
		defer func() {
			if !closed {
				close(lineCh)
			}
		}()
		flagCtx, flagCancel := context.WithCancel(ctx)
		defer flagCancel()
		getSuccess := s.runFlagProcessor(flagCtx, logger, runId, key, lineCh)

		var rejected atomic.Int32
		defer func() {
			select {
			case s.finished <- &taskKeyWithResult{
				taskKey:      key,
				success:      getSuccess(),
				rejected:     rejected.Load() == 1,
				finishedTime: time.Now(),
			}:
			case <-ctx.Done():
			}
		}()

		logger.Debug("task started")
		defer logger.Debug("task finished")

		timedOut := make(chan bool, 1)
		if err := func() error {
			var wg sync.WaitGroup
			defer wg.Wait()

			stdout, err := createFlagLogger(flagCtx, logBase+"/stdout", lineCh)
			if err != nil {
				logger.Error("failed to create stdout logger", zap.Error(err))
				return err
			}
			defer stdout.close(logger)

			stderr, err := createFlagLogger(flagCtx, logBase+"/stderr", lineCh)
			if err != nil {
				logger.Error("failed to create stderr logger", zap.Error(err))
				return err
			}
			defer stderr.close(logger)

			pidCh := make(chan int)
			defer close(pidCh)

			wg.Add(1)
			go func() {
				defer wg.Done()
				defer close(timedOut)

				pid, ok := <-pidCh
				if !ok {
					// channel is closed, so something happened before the process started
					return
				}
				defer s.runningInfos.Delete(pid)

				var timeout time.Duration
				if task.exploit.Timeout != nil {
					timeout = *task.exploit.Timeout
				} else {
					timeout = s.defaults.Load().timeout
				}

				select {
				case <-pidCh:
					// should be when the task is finished (channel is closed)
					return
				case <-ctx.Done():
				case <-time.After(timeout):
					logger.Warn("task timed out", zap.Duration("timeout", timeout))
					flagCancel()
					timedOut <- true
				}

				info, loaded := s.runningInfos.Load(pid)
				if !loaded {
					logger.DPanic("should never happen")
					return
				}

				// first, try to just cancel the sockets
				var cancelled bool
				for _, cancel := range info.sockets.Range {
					cancel()
					cancelled = true
				}

				if cancelled {
					// if cancelled, wait for a bit to see if the process exits
					select {
					case <-pidCh:
						// process exited, nothing to do
						return
					case <-time.After(5 * time.Second): // wait 5 seconds
						logger.Warn("task force kill")
					}
				}

				if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
					logger.Warn("failed to kill task", zap.Int("pid", pid), zap.Error(err))
				}
			}()

			return task.executor(ctx, logger, container.RunOptions{
				Args:   []string{"/exploit/exploit"},
				Stdin:  utils.DevNull,
				Stdout: stdout,
				Stderr: stderr,
				BindMounts: []container.BindMount{{
					Source:      task.exploit.ExtractPath,
					Destination: "/exploit",
					Options:     []string{"ro"},
				}, {
					Source:      persistentBase,
					Destination: "/persistent",
				}},
				Envs: envs,
				StartedCallback: func(pid int) {
					logger.Info("exploit started", zap.Int("pid", pid))
					info := &runningInfo{
						debug:     fmt.Sprintf("%s/%s[%s](%s)", key.service, key.exploit, key.team, runId),
						allocator: allocator,
						rejected:  &rejected,
						sockets:   *xsync.NewMap[uint32, context.CancelFunc](),
						obfuscate: task.exploit.ObfuscateTraffic,
					}
					s.runningInfos.Store(pid, info)
					pidCh <- pid
				},
			})
		}(); err != nil {
			logger.Error("exploit execution error", zap.Error(err))
		}

		close(lineCh)
		closed = true
	}()
}

func (s *scheduler) kick() {
	select {
	case s.finished <- nil:
	default:
	}
}

func (s *scheduler) selectTask(ctx context.Context, logger *zap.Logger) (*taskKey, <-chan time.Time) {
	availableTasks := make(map[taskKey]int64)

	// filter out tasks that are already running for the same service/team
	for key, task := range *s.tasks.Load() {
		if len(s.runningTasks[key.to2()]) > 0 {
			continue
		}
		availableTasks[key] = s.mono - task.lastRunMono
	}

	// however, if there are no tasks available, use all tasks that are not running
	if len(availableTasks) == 0 {
		for key, task := range *s.tasks.Load() {
			// filter out running tasks
			if _, ok := s.runningTasks[key.to2()][key.exploit]; ok {
				continue
			}
			availableTasks[key] = s.mono - task.lastRunMono
		}
	}

	// filter out tasks that are in cooldown
	cooldownWait := time.Duration(math.MaxInt64)
	for key := range availableTasks {
		task := (*s.tasks.Load())[key]
		if task == nil {
			// oops, task got removed after selection
			delete(availableTasks, key)
			continue
		}
		if task.retryCount > 0 {
			// retrying tasks, skip cooldown check
			continue
		}
		if s.ticker.LastTick().Compare(task.lastRunTime) < 0 {
			cooldown := s.defaults.Load().cooldown
			if task.exploit.Cooldown != nil {
				cooldown = *task.exploit.Cooldown
			}

			if since := time.Since(task.lastRunTime); since < cooldown {
				cooldownWait = min(cooldownWait, cooldown-since)
				delete(availableTasks, key)
			}
		}
	}

	if len(availableTasks) == 0 {
		if cooldownWait == time.Duration(math.MaxInt64) {
			return nil, nil
		}
		logger.Debug("cooling down", zap.Stringer("wait", cooldownWait))
		return nil, time.After(cooldownWait)
	}

	var maxScore float64 = -2 // -1 is minimum score
	var options []taskKey
	totalNumTasks := float64(len(*s.tasks.Load()))
	for task, age := range availableTasks {
		score := float64(age)/totalNumTasks + scoreExploit(ctx, logger, task.service, task.team, task.exploit)
		if score > maxScore {
			options = append(options[:0], task)
			maxScore = score
		} else if score == maxScore {
			options = append(options, task)
		}
	}

	return &options[rand.Intn(len(options))], nil
}
