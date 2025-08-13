package thrower

import (
	"context"
	"os"
	"slices"
	"sync"

	"go.uber.org/zap"

	"pwnbot-ng/container"
	"pwnbot-ng/preprocess"
	"pwnbot-ng/proxy"
	"pwnbot-ng/repo"
	"pwnbot-ng/ticker"
)

type Thrower struct {
	logPath string

	wg sync.WaitGroup

	scheduler *scheduler
	proxy     *proxy.Proxy

	executors        map[container.ExecutorKey]container.Executor
	servicesAndTeams []*preprocess.ServiceAndTeams
	exploits         map[string]map[string]*repo.Exploit // service name -> exploit name -> exploit

	cancel context.CancelFunc
}

func NewThrower(
	ctx context.Context,
	logger *zap.Logger,
	logPath string,
	proxy *proxy.Proxy,
	configChan <-chan *repo.ConfigValues,
	servicesAndTeamsChan <-chan []*preprocess.ServiceAndTeams,
	exploitsChan <-chan []repo.ExploitWithRefs,
	executorChan <-chan container.ExecutorNotify,
	submitterChan <-chan repo.Submitter,
	ticker *ticker.Ticker,
) (*Thrower, error) {
	if err := os.MkdirAll(logPath, 0755); err != nil {
		logger.Error("failed to create log directory", zap.Error(err))
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)

	t := &Thrower{
		logPath:   logPath,
		executors: make(map[container.ExecutorKey]container.Executor),
		proxy:     proxy,
		cancel:    cancel,
	}
	t.scheduler = newScheduler(t, ticker)
	t.scheduler.submitter.Store(new(string))
	proxy.SetHandler(t.scheduler.getGetHandler(logger))

	t.wg.Add(1)
	go t.scheduler.run(ctx, logger.Named("scheduler"))

	t.wg.Add(1)
	go t.backgroundUpdate(ctx, logger, configChan, servicesAndTeamsChan, exploitsChan, executorChan, submitterChan)

	return t, nil
}

func ThrowOnce(
	ctx context.Context,
	logger *zap.Logger,
	submitter repo.Submitter,
	config *repo.ConfigValues,
	exploits []repo.ExploitWithRefs,
	servicesAndTeams []*preprocess.ServiceAndTeams,
	executors map[container.ExecutorKey]container.Executor,
) {
	newExploits := make(map[string]map[string]*repo.Exploit)
	for _, exploit := range exploits {
		for _, ref := range exploit.Refs {
			if _, ok := newExploits[ref.Service]; !ok {
				newExploits[ref.Service] = make(map[string]*repo.Exploit)
			}
			newExploits[ref.Service][ref.Name] = exploit.Exploit
		}
	}

	const logPath = "logs/thrower"
	if err := os.MkdirAll(logPath, 0755); err != nil {
		logger.Error("failed to create log directory", zap.Error(err))
		return
	}

	t := &Thrower{
		logPath:          logPath,
		executors:        executors,
		exploits:         newExploits,
		servicesAndTeams: servicesAndTeams,
	}
	t.scheduler = newScheduler(t, nil)
	t.scheduler.defaults.Store(throwerConfigFromRepoConfig(config))
	t.scheduler.submitter.Store(&submitter)
	t.updateTasks(logger)

	t.scheduler.runOnce(ctx, logger.Named("scheduler"))
	t.wg.Wait()
}

func (t *Thrower) Close() {
	t.cancel()
	t.wg.Wait()
}

func (t *Thrower) updateTasks(logger *zap.Logger) {
	oldTasks := *t.scheduler.tasks.Load()
	newTasks := make(map[taskKey]*schedulerTask, len(*t.scheduler.tasks.Load()))

	for _, serviceAndTeams := range t.servicesAndTeams {
		logger := logger.With(zap.String("service", serviceAndTeams.Service.Name))

		// get exploits available for the service
		for exploitName, exploit := range t.exploits[serviceAndTeams.Service.Name] {
			executorKey := container.GetExecutorKey(exploit)
			executor, ok := t.executors[executorKey]
			if !ok {
				logger.Debug("exploit missing executor", zap.String("exploit", exploitName))
				continue
			}

			for _, team := range serviceAndTeams.Teams {
				if (exploit.OnlyTeams != nil && !slices.Contains(exploit.OnlyTeams, team.Name)) ||
					slices.Contains(exploit.SkipTeams, team.Name) {
					logger.Debug("exploit skipped for team", zap.String("exploit", exploitName), zap.String("team", team.Name))
					continue
				}

				key := taskKey{
					service: serviceAndTeams.Service.Name,
					team:    team.Name,
					exploit: exploitName,
				}
				newTask := &schedulerTask{
					service:  serviceAndTeams.Service,
					team:     team,
					exploit:  exploit,
					executor: executor,
				}
				if oldTask, ok := oldTasks[key]; ok {
					newTask.schedulerTaskPersist = oldTask.schedulerTaskPersist
				} else {
					newTask.schedulerTaskPersist = new(schedulerTaskPersist)
				}
				newTasks[key] = newTask
			}
		}
	}

	t.scheduler.tasks.Store(&newTasks)
	t.scheduler.kick()
}

func (t *Thrower) backgroundUpdate(
	ctx context.Context,
	logger *zap.Logger,
	configChan <-chan *repo.ConfigValues,
	servicesAndTeamsChan <-chan []*preprocess.ServiceAndTeams,
	exploitsChan <-chan []repo.ExploitWithRefs,
	executorChan <-chan container.ExecutorNotify,
	submitterChan <-chan repo.Submitter,
) {
	defer t.wg.Done()

	logger.Info("running thrower background update")
	for {
		select {
		case <-ctx.Done():
			return
		case config := <-configChan: // implementation guarantees that this will be called first
			t.scheduler.defaults.Store(throwerConfigFromRepoConfig(config))
			t.proxy.UpdateParam(
				config.ConnectionConcurrency,
				config.UserConnectionConcurrency,
				config.DefaultObfuscateTraffic,
			)
		case servicesAndTeams := <-servicesAndTeamsChan:
			t.servicesAndTeams = servicesAndTeams
			t.updateTasks(logger)
		case exploits := <-exploitsChan:
			newExploits := make(map[string]map[string]*repo.Exploit)
			for _, exploit := range exploits {
				for _, ref := range exploit.Refs {
					if _, ok := newExploits[ref.Service]; !ok {
						newExploits[ref.Service] = make(map[string]*repo.Exploit)
					}
					newExploits[ref.Service][ref.Name] = exploit.Exploit
				}
			}
			t.exploits = newExploits
			t.updateTasks(logger)
		case executor := <-executorChan:
			t.executors[executor.Key] = executor.Executor // XXX: memory leak (should be fine because memory footprint is small)
			t.updateTasks(logger)
		case submitter := <-submitterChan:
			t.scheduler.submitter.Store(&submitter)
		}
	}
}
