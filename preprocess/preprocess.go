package preprocess

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"pwnbot-ng/repo"
	"pwnbot-ng/ticker"
	"pwnbot-ng/utils"
)

type packed struct {
	services   []*repo.Service
	teams      []*repo.Team
	preprocess map[string]string // service name -> preprocess path
}

type Preprocessor struct {
	logPath string

	lock        sync.Mutex
	subscribers []chan<- []*ServiceAndTeams

	pack atomic.Pointer[packed]

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type ServiceAndTeams struct {
	Service repo.Service
	Teams   []repo.Team
}

func RunPreprocess(
	ctx context.Context,
	logger *zap.Logger,
	logPath string,
	servicesChan <-chan []*repo.Service,
	teamsChan <-chan []*repo.Team,
	preprocessChan <-chan []repo.Preprocess,
	tickerChan <-chan ticker.Info,
) *Preprocessor {
	ctx, cancel := context.WithCancel(ctx)
	p := &Preprocessor{logPath: logPath, cancel: cancel}
	p.pack.Store(new(packed))
	p.wg.Add(1)
	go p.background(ctx, logger, servicesChan, teamsChan, preprocessChan, tickerChan)
	return p
}

func RunPreprocessLocal(
	ctx context.Context,
	logger *zap.Logger,
	services []*repo.Service,
	teams []*repo.Team,
	preprocess []repo.Preprocess,
) []*ServiceAndTeams {
	const logPath = "logs/preprocess"

	pack := &packed{
		services:   services,
		teams:      teams,
		preprocess: make(map[string]string, len(preprocess)),
	}
	for _, p := range preprocess {
		for _, service := range p.Services {
			pack.preprocess[service] = p.BinaryPath
		}
	}

	p := &Preprocessor{logPath: logPath}
	p.pack.Store(pack)
	return p.refreshSingle(ctx, logger, nil)
}

func (p *Preprocessor) Close() {
	p.cancel()
	p.wg.Wait()
}

func (p *Preprocessor) Subscribe() <-chan []*ServiceAndTeams {
	p.lock.Lock()
	defer p.lock.Unlock()

	sub := make(chan []*ServiceAndTeams, 10)
	p.subscribers = append(p.subscribers, sub)
	return sub
}

func (p *Preprocessor) background(
	ctx context.Context,
	logger *zap.Logger,
	servicesChan <-chan []*repo.Service,
	teamsChan <-chan []*repo.Team,
	preprocessChan <-chan []repo.Preprocess,
	tickerChan <-chan ticker.Info,
) {
	defer p.wg.Done()

	refreshCh := make(chan struct{})
	p.wg.Add(1)
	go p.refresh(ctx, logger, refreshCh)

	for {
		select {
		case <-ctx.Done():
			logger.Info("preprocess background stopped")
			return
		case services := <-servicesChan:
			load := p.pack.Load()
			p.pack.Store(&packed{
				services:   services,
				teams:      load.teams,
				preprocess: load.preprocess,
			})
		case teams := <-teamsChan:
			load := p.pack.Load()
			p.pack.Store(&packed{
				services:   load.services,
				teams:      teams,
				preprocess: load.preprocess,
			})
		case preprocess := <-preprocessChan:
			preprocessMap := make(map[string]string, len(preprocess))
			for _, p := range preprocess {
				for _, service := range p.Services {
					preprocessMap[service] = p.BinaryPath
				}
			}
			load := p.pack.Load()
			p.pack.Store(&packed{
				services:   load.services,
				teams:      load.teams,
				preprocess: preprocessMap,
			})
		case <-tickerChan:
		}
		select {
		case refreshCh <- struct{}{}:
		default:
		}
	}
}

func (p *Preprocessor) refresh(
	ctx context.Context,
	logger *zap.Logger,
	refreshCh <-chan struct{},
) {
	defer p.wg.Done()

	for {
		for {
			select {
			case <-ctx.Done():
				return
			case <-refreshCh:
				continue
			case <-time.After(time.Second): // debounce
			}
			break
		}

		logger.Debug("refreshing preprocess data")
		snts := p.refreshSingle(ctx, logger, refreshCh)
		if snts == nil {
			continue
		}

		for _, sub := range func() []chan<- []*ServiceAndTeams {
			p.lock.Lock()
			defer p.lock.Unlock()
			return p.subscribers
		}() {
			select {
			case sub <- snts:
			case <-ctx.Done():
				return
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-refreshCh:
		}
	}
}

func assembleServiceAndTeam(
	service *repo.Service,
	oteams []*repo.Team,
) *ServiceAndTeams {
	snt := new(ServiceAndTeams)
	snt.Service = *service
	teams := make([]repo.Team, len(oteams))
	for i, team := range oteams {
		teams[i] = *team
	}
	snt.Teams = teams
	return snt
}

func (p *Preprocessor) refreshSingle(
	ctx context.Context,
	logger *zap.Logger,
	refreshCh <-chan struct{},
) []*ServiceAndTeams {
	pack := *p.pack.Load()

	snts := make([]*ServiceAndTeams, 0, len(pack.services))
	resultCh := make(chan *ServiceAndTeams)

	stopCtx, stop := context.WithCancel(ctx)
	defer stop()

	var runCounter int
	for _, service := range pack.services {
		logger := logger.With(zap.String("service", service.Name))

		if prepPath := pack.preprocess[service.Name]; prepPath == "" {
			// no preprocess, assemble directly
			snts = append(snts, assembleServiceAndTeam(service, pack.teams))
		} else {
			// assemble serialized service and teams
			serviceMap := maps.Clone(service.Extra)
			serviceMap["name"] = service.Name
			serviceMap["port"] = service.Port

			teamsMap := make(map[string]any, len(pack.teams))
			for _, team := range pack.teams {
				teamsMap[team.Name] = map[string]any{
					"host": team.Host,
				}
			}

			serialized := map[string]any{
				"service": serviceMap,
				"teams":   teamsMap,
			}

			runId := utils.GenerateRunID()
			logPath := strings.Join([]string{
				p.logPath,
				service.Name,
				runId,
			}, "/")

			if err := os.MkdirAll(logPath, 0755); err != nil {
				logger.Error("failed to create log directory", zap.Error(err), zap.String("path", logPath))
				continue
			}

			runCounter++
			go func() {
				defer logger.Debug("preprocess command finished")

				if res := executePreprocess(stopCtx, logger, prepPath, logPath, serialized); res != nil {
					resultCh <- res
				} else if stopCtx.Err() == nil {
					resultCh <- assembleServiceAndTeam(service, pack.teams)
				} else {
					resultCh <- nil
				}
			}()
		}
	}

	for i := 0; i < runCounter; i++ {
		select {
		case <-refreshCh: // if we got update while waiting for results
			logger.Debug("received refresh signal while waiting for preprocess results, stopping all running commands")
			stop() // stop all running preprocess commands
			for j := i; j < runCounter; j++ {
				<-resultCh // drain the channel
			}
			return nil // signal that we need to refresh again
		case result := <-resultCh:
			if result == nil {
				continue // only case this happens is when ctx is cancelled
			}
			snts = append(snts, result)
		}
	}
	return snts
}

func executePreprocess(
	ctx context.Context,
	logger *zap.Logger,
	preprocessPath,
	logPath string,
	input map[string]any,
) *ServiceAndTeams {
	closes := make(map[*os.File]struct{})
	defer func() {
		for f := range closes {
			if err := f.Close(); err != nil {
				logger.Error("failed to close file", zap.Error(err), zap.String("file", f.Name()))
			}
		}
	}()

	parentStdin, childStdin, err := utils.CreateAnonymousSocket(logger)
	if err != nil {
		logger.Error("failed to create anonymous socket", zap.Error(err))
		return nil
	}
	closes[parentStdin] = struct{}{}
	closes[childStdin] = struct{}{}

	stdoutFile, err := os.Create(logPath + "/stdout")
	if err != nil {
		logger.Error("failed to create log file", zap.Error(err), zap.String("path", logPath+"/stdout"))
		return nil
	}
	closes[stdoutFile] = struct{}{}

	stderrFile, err := os.Create(logPath + "/stderr")
	if err != nil {
		logger.Error("failed to create log file", zap.Error(err), zap.String("path", logPath+"/stderr"))
		return nil
	}
	closes[stderrFile] = struct{}{}

	cmd := exec.CommandContext(ctx, preprocessPath)
	cmd.Stdin = childStdin
	cmd.Stdout = stdoutFile
	cmd.Stderr = stderrFile
	if err := cmd.Start(); err != nil {
		logger.Error("failed to start preprocess command", zap.Error(err))
		return nil
	}
	defer func() {
		if cmd != nil {
			if err := cmd.Process.Kill(); err != nil {
				logger.Error("failed to kill preprocess command", zap.Error(err))
			}
		}
	}()

	if err := childStdin.Close(); err != nil {
		logger.Error("failed to close child stdin", zap.Error(err), zap.String("path", childStdin.Name()))
		return nil
	}
	delete(closes, childStdin)
	if err := stderrFile.Close(); err != nil {
		logger.Error("failed to close stderr file", zap.Error(err), zap.String("path", stderrFile.Name()))
		return nil
	}
	delete(closes, stderrFile)
	if err := stdoutFile.Close(); err != nil {
		logger.Error("failed to close stdout file", zap.Error(err), zap.String("path", stdoutFile.Name()))
		return nil
	}
	delete(closes, stdoutFile)

	if err := json.NewEncoder(parentStdin).Encode(input); err != nil {
		logger.Error("failed to encode input to preprocess command", zap.Error(err))
		return nil
	}
	if err := utils.ShutdownWrite(parentStdin); err != nil {
		logger.Error("failed to shutdown write to preprocess command", zap.Error(err))
		return nil
	}

	ret, err := ParseServiceAndTeams(logger, parentStdin)
	if err != nil {
		logger.Error("failed to parse service and teams from preprocess command output", zap.Error(err))
		return nil
	}
	return ret
}

func ParseServiceAndTeams(logger *zap.Logger, reader io.Reader) (*ServiceAndTeams, error) {
	var result struct {
		Service map[string]any            `json:"service"`
		Teams   map[string]map[string]any `json:"teams"`
	}
	if err := json.NewDecoder(reader).Decode(&result); err != nil {
		logger.Error("failed to decode from reader", zap.Error(err))
		return nil, err
	}

	ret := new(ServiceAndTeams)
	if serviceName, ok := result.Service["name"].(string); !ok {
		return nil, errors.New("invalid service name")
	} else {
		ret.Service.Name = serviceName
		delete(result.Service, "name")
	}
	if servicePort, ok := result.Service["port"].(float64); !ok {
		return nil, errors.New("invalid service port")
	} else {
		ret.Service.Port = uint16(servicePort)
		delete(result.Service, "port")
	}
	ret.Service.Extra = result.Service

	teams := make([]repo.Team, 0, len(result.Teams))
	for teamName, teamData := range result.Teams {
		host, ok := teamData["host"].(string)
		if !ok {
			logger.Warn("invalid team host", zap.String("team", teamName))
			continue
		}
		delete(teamData, "host")
		teams = append(teams, repo.Team{
			Name:  teamName,
			Host:  host,
			Extra: teamData,
		})
	}
	ret.Teams = teams

	return ret, nil
}
