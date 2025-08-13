package repo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"go.uber.org/zap"
)

const (
	configFileName   = "config.yaml"
	servicesFileName = "services.yaml"
	teamsFileName    = "teams.yaml"

	exploitsPath = "exploits"

	fetchTimeout   = 30 * time.Second
	reloadInterval = 5 * time.Second
)

type ExploitRef struct {
	Service string
	Name    string
}

type ExploitWithRefs struct {
	Refs []ExploitRef
	*Exploit
}

type Preprocess struct {
	Services   []string
	BinaryPath string
}

type DefaultImage struct {
	ExtractPath string
	TreeHash    plumbing.Hash
}

type Submitter = string

type Repository struct {
	repo *git.Repository

	lastConfigHash        plumbing.Hash
	lastServicesHash      plumbing.Hash
	lastTeamsHash         plumbing.Hash
	lastDefaultImageHash  plumbing.Hash
	lastFlagSubmitterHash plumbing.Hash
	lastExploits          map[ /* tree */ plumbing.Hash]ExploitWithRefs
	lastPreprocesses      map[ /* blob */ plumbing.Hash]Preprocess

	configSubscribers        []chan<- *ConfigValues
	servicesSubscribers      []chan<- []*Service
	teamsSubscribers         []chan<- []*Team
	exploitsSubscribers      []chan<- []ExploitWithRefs
	preprocessSubscribers    []chan<- []Preprocess
	defaultImageSubscribers  []chan<- *DefaultImage
	flagSubmitterSubscribers []chan<- Submitter

	started bool
}

func NewRepository(ctx context.Context, logger *zap.Logger, url string) (*Repository, error) {
	_ = os.RemoveAll(exploitsPath)
	if err := os.MkdirAll(exploitsPath, 0755); err != nil {
		logger.Error("failed to create exploits directory", zap.Error(err))
		return nil, err
	}

	gitRepo, err := func() (*git.Repository, error) {
		timeout, cancelFunc := context.WithTimeout(ctx, fetchTimeout)
		defer cancelFunc()

		const exploitRepoPath = "exploit-repo"
		_ = os.RemoveAll(exploitRepoPath)
		return git.PlainCloneContext(timeout, exploitRepoPath, true, &git.CloneOptions{
			URL:          url,
			Tags:         git.NoTags,
			Depth:        1,
			SingleBranch: true,
			Mirror:       true,
		})
	}()
	if err != nil {
		logger.Error("failed to clone repository", zap.String("url", url), zap.Error(err))
		return nil, err
	}

	return &Repository{
		repo: gitRepo,
	}, nil
}

type combined struct {
	Config        *ConfigValues
	Services      []*Service
	Teams         []*Team
	Exploits      []ExploitWithRefs
	Preprocesses  []Preprocess
	DefaultImage  *DefaultImage
	FlagSubmitter Submitter
}

func NewLocalRepository(ctx context.Context, logger *zap.Logger, path string) (combined, error) {
	_ = os.RemoveAll(exploitsPath)
	if err := os.MkdirAll(exploitsPath, 0755); err != nil {
		logger.Error("failed to create exploits directory", zap.Error(err))
		return combined{}, err
	}

	logger = logger.With(zap.String("repo", path))

	gitRepo, err := git.PlainOpen(path)
	if err != nil {
		logger.Error("failed to open local repository", zap.Error(err))
		return combined{}, err
	}

	if worktree, err := gitRepo.Worktree(); err != nil {
		if !errors.Is(err, git.ErrIsBareRepository) {
			logger.Error("failed to get worktree", zap.Error(err))
			return combined{}, err
		}
		// pass
	} else {
		status, err := worktree.Status()
		if err != nil {
			logger.Error("failed to get worktree status", zap.Error(err))
			return combined{}, err
		}
		if !status.IsClean() {
			_, _ = fmt.Fprint(os.Stderr, status)
			return combined{}, errors.New("worktree is not clean, please commit or stash your changes")
		}
	}

	head, err := gitRepo.Head()
	if err != nil {
		logger.Error("failed to get repository head", zap.Error(err))
		return combined{}, err
	}

	configCh := make(chan *ConfigValues, 10)
	servicesCh := make(chan []*Service, 10)
	teamsCh := make(chan []*Team, 10)
	exploitsCh := make(chan []ExploitWithRefs, 10)
	preprocessCh := make(chan []Preprocess, 10)
	defaultImageCh := make(chan *DefaultImage, 10)
	flagSubmitterCh := make(chan Submitter, 10)

	repo := &Repository{
		repo: gitRepo,

		configSubscribers:        []chan<- *ConfigValues{configCh},
		servicesSubscribers:      []chan<- []*Service{servicesCh},
		teamsSubscribers:         []chan<- []*Team{teamsCh},
		exploitsSubscribers:      []chan<- []ExploitWithRefs{exploitsCh},
		preprocessSubscribers:    []chan<- []Preprocess{preprocessCh},
		defaultImageSubscribers:  []chan<- *DefaultImage{defaultImageCh},
		flagSubmitterSubscribers: []chan<- Submitter{flagSubmitterCh},

		started: true,
	}

	if err := repo.reload(ctx, logger, head); err != nil {
		logger.Error("repository load failed", zap.Error(err))
		return combined{}, err
	}

	close(configCh)
	close(servicesCh)
	close(teamsCh)
	close(exploitsCh)
	close(preprocessCh)
	close(defaultImageCh)
	close(flagSubmitterCh)

	var result combined
	var ok bool
	result.Config, ok = <-configCh
	if !ok {
		return result, errors.New("failed to load config from repository")
	}
	result.Services, ok = <-servicesCh
	if !ok {
		return result, errors.New("failed to load services from repository")
	}
	result.Teams, ok = <-teamsCh
	if !ok {
		return result, errors.New("failed to load teams from repository")
	}
	result.Exploits, ok = <-exploitsCh
	if !ok {
		return result, errors.New("failed to load exploits from repository")
	}
	result.Preprocesses, ok = <-preprocessCh
	if !ok {
		return result, errors.New("failed to load preprocesses from repository")
	}
	result.DefaultImage, ok = <-defaultImageCh
	if !ok {
		return result, errors.New("failed to load default image from repository")
	}
	result.FlagSubmitter, ok = <-flagSubmitterCh
	if !ok {
		return result, errors.New("failed to load flag submitter from repository")
	}

	return result, nil
}

func CheckLocalRepository(ctx context.Context, logger *zap.Logger, commit plumbing.Hash) error {
	repo, err := git.PlainOpen(".")
	if err != nil {
		return err
	}

	cm, err := repo.CommitObject(commit)
	if err != nil {
		return err
	}

	tree, err := cm.Tree()
	if err != nil {
		return err
	}

	configFile, err := tree.File(configFileName)
	if err != nil {
		if !errors.Is(err, object.ErrFileNotFound) {
			return err
		}
		return fmt.Errorf("%q file not found", configFileName)
	}
	if err := checkConfig(ctx, logger, configFile); err != nil {
		return fmt.Errorf("%q: %w", configFileName, err)
	}

	teamsFile, err := tree.File(teamsFileName)
	if err != nil {
		if !errors.Is(err, object.ErrFileNotFound) {
			return err
		}
		return fmt.Errorf("%q file not found", teamsFileName)
	}
	if err := checkTeams(ctx, logger, teamsFile); err != nil {
		return fmt.Errorf("%q: %w", teamsFileName, err)
	}

	servicesFile, err := tree.File(servicesFileName)
	if err != nil {
		if !errors.Is(err, object.ErrFileNotFound) {
			return err
		}
		return fmt.Errorf("%q file not found", servicesFileName)
	}
	services, err := checkServices(ctx, logger, servicesFile)
	if err != nil {
		return fmt.Errorf("%q: %w", servicesFileName, err)
	}

	// Check exploits
	for _, service := range tree.Entries {
		if service.Mode != filemode.Dir {
			continue
		}
		if isSpecialDir(service.Name) {
			continue
		}

		if !slices.Contains(services, service.Name) {
			return fmt.Errorf("service %q not found in %q file", service.Name, servicesFileName)
		}

		serviceTree, err := repo.TreeObject(service.Hash)
		if err != nil {
			return err
		}

		for _, entry := range serviceTree.Entries {
			if entry.Mode != filemode.Dir {
				continue
			}

			exploitTree, err := repo.TreeObject(entry.Hash)
			if err != nil {
				return err
			}

			if err := checkExploit(ctx, logger, exploitTree); err != nil {
				return fmt.Errorf("%s/%s: %w", service.Name, entry.Name, err)
			}
		}
	}

	// Check default image
	defaultImageTree, err := tree.Tree(".default-image")
	if err != nil {
		if !errors.Is(err, object.ErrDirectoryNotFound) {
			return err
		}
		return fmt.Errorf(".default-image directory not found")
	}
	if _, err := defaultImageTree.File("Dockerfile"); err != nil {
		if !errors.Is(err, object.ErrFileNotFound) {
			return err
		}
		return fmt.Errorf(".default-image/Dockerfile file not found")
	}

	// Check flag submitter
	submitterFile, err := tree.File("submit_flag")
	if err != nil {
		if !errors.Is(err, object.ErrFileNotFound) {
			return err
		}
	} else {
		if submitterFile.Mode != filemode.Executable {
			return fmt.Errorf("submit_flag file is not executable")
		}
	}

	return nil
}

func (r *Repository) SubscribeConfig() <-chan *ConfigValues {
	if r.started {
		panic("repository already started")
	}
	ch := make(chan *ConfigValues, 10)
	r.configSubscribers = append(r.configSubscribers, ch)
	return ch
}

func (r *Repository) SubscribeServices() <-chan []*Service {
	if r.started {
		panic("repository already started")
	}
	ch := make(chan []*Service, 10)
	r.servicesSubscribers = append(r.servicesSubscribers, ch)
	return ch
}

func (r *Repository) SubscribeTeams() <-chan []*Team {
	if r.started {
		panic("repository already started")
	}
	ch := make(chan []*Team, 10)
	r.teamsSubscribers = append(r.teamsSubscribers, ch)
	return ch
}

func (r *Repository) SubscribeExploits() <-chan []ExploitWithRefs {
	if r.started {
		panic("repository already started")
	}
	ch := make(chan []ExploitWithRefs, 10)
	r.exploitsSubscribers = append(r.exploitsSubscribers, ch)
	return ch
}

func (r *Repository) SubscribePreprocess() <-chan []Preprocess {
	if r.started {
		panic("repository already started")
	}
	ch := make(chan []Preprocess, 10)
	r.preprocessSubscribers = append(r.preprocessSubscribers, ch)
	return ch
}

func (r *Repository) SubscribeDefaultImage() <-chan *DefaultImage {
	if r.started {
		panic("repository already started")
	}
	ch := make(chan *DefaultImage, 10)
	r.defaultImageSubscribers = append(r.defaultImageSubscribers, ch)
	return ch
}

func (r *Repository) SubscribeFlagSubmitter() <-chan Submitter {
	if r.started {
		panic("repository already started")
	}
	ch := make(chan Submitter, 10)
	r.flagSubmitterSubscribers = append(r.flagSubmitterSubscribers, ch)
	return ch
}

func (r *Repository) reloadConfig(ctx context.Context, logger *zap.Logger, tree *object.Tree) (*ConfigValues, error) {
	file, err := tree.File(configFileName)
	if err != nil {
		if !errors.Is(err, object.ErrFileNotFound) {
			return nil, err
		}
		if r.lastConfigHash.IsZero() {
			return nil, nil
		}
		logger.Warn("config file not found, using default config")
		r.lastConfigHash = plumbing.ZeroHash
		return DefaultConfig(), nil
	}
	if file.Hash == r.lastConfigHash {
		return nil, nil
	}
	config, err := loadConfig(ctx, logger.With(zap.Stringer("blob", file.Hash)), file)
	if err != nil {
		return nil, err
	}
	r.lastConfigHash = file.Hash
	return config, nil
}

func (r *Repository) reloadServices(ctx context.Context, logger *zap.Logger, tree *object.Tree) ([]*Service, error) {
	file, err := tree.File(servicesFileName)
	if err != nil {
		if !errors.Is(err, object.ErrFileNotFound) {
			return nil, err
		}
		if r.lastServicesHash.IsZero() {
			return nil, nil
		}
		logger.Warn("services file not found, using empty services")
		r.lastServicesHash = plumbing.ZeroHash
		return []*Service{}, nil
	}
	if file.Hash == r.lastServicesHash {
		return nil, nil
	}
	services, err := loadServices(ctx, logger.With(zap.Stringer("blob", file.Hash)), file)
	if err != nil {
		return nil, err
	}
	r.lastServicesHash = file.Hash
	return services, nil
}

func (r *Repository) reloadTeams(ctx context.Context, logger *zap.Logger, tree *object.Tree) ([]*Team, error) {
	file, err := tree.File(teamsFileName)
	if err != nil {
		if !errors.Is(err, object.ErrFileNotFound) {
			return nil, err
		}
		if r.lastTeamsHash.IsZero() {
			return nil, nil
		}
		logger.Warn("teams file not found, using empty teams")
		r.lastTeamsHash = plumbing.ZeroHash
		return []*Team{}, nil
	}
	if file.Hash == r.lastTeamsHash {
		return nil, nil
	}
	teams, err := loadTeams(ctx, logger.With(zap.Stringer("blob", file.Hash)), file)
	if err != nil {
		return nil, err
	}
	r.lastTeamsHash = file.Hash
	return teams, nil
}

func (r *Repository) reloadExploits(ctx context.Context, logger *zap.Logger, tree *object.Tree) {
	exploits := make(map[plumbing.Hash]ExploitWithRefs)
	preprocesses := make(map[plumbing.Hash]Preprocess)
	for _, service := range tree.Entries {
		if service.Mode != filemode.Dir {
			continue
		}
		if isSpecialDir(service.Name) {
			continue
		}

		logger := logger.With(zap.String("service", service.Name), zap.Stringer("tree", service.Hash))

		serviceTree, err := r.repo.TreeObject(service.Hash)
		if err != nil {
			logger.Error("failed to get service tree", zap.Error(err))
			continue
		}

		// parsing preprocess file
		if preprocess, err := serviceTree.File("preprocess"); err == nil {
			if preprocess.Mode != filemode.Executable {
				logger.Info("preprocess file is not executable")
			} else if prep, ok := preprocesses[preprocess.Hash]; ok {
				preprocesses[preprocess.Hash] = Preprocess{
					Services:   append(prep.Services, service.Name),
					BinaryPath: prep.BinaryPath,
				}
			} else if prep, ok := r.lastPreprocesses[preprocess.Hash]; ok {
				preprocesses[preprocess.Hash] = Preprocess{
					Services:   []string{service.Name},
					BinaryPath: prep.BinaryPath,
				}
			} else {
				path, err := func() (string, error) {
					temp, err := os.CreateTemp(exploitsPath, "")
					if err != nil {
						logger.Error("failed to create temp file for preprocess", zap.Error(err))
						return "", err
					}
					defer func() {
						if err := temp.Close(); err != nil {
							logger.Error("failed to close temp file", zap.Error(err))
						}
					}()
					if err := temp.Chmod(0755); err != nil {
						logger.Error("failed to set preprocess file permissions", zap.Error(err))
						return "", err
					}

					reader, err := preprocess.Reader()
					if err != nil {
						logger.Error("failed to get preprocess reader", zap.Error(err))
						return "", err
					}
					defer func() {
						if err := reader.Close(); err != nil {
							logger.Error("failed to close preprocess reader", zap.Error(err))
						}
					}()

					if _, err := temp.ReadFrom(reader); err != nil {
						logger.Error("failed to copy preprocess file", zap.Error(err))
						return "", err
					}
					return temp.Name(), nil
				}()
				if err != nil {
					logger.Error("failed to create preprocess file", zap.Error(err))
				} else {
					preprocesses[preprocess.Hash] = Preprocess{
						Services:   []string{service.Name},
						BinaryPath: path,
					}
					logger.Info("preprocess loaded", zap.String("binary", path))
				}
			}
		} else if !errors.Is(err, object.ErrFileNotFound) {
			logger.Error("failed to query preprocess file", zap.Error(err))
		}

		// parsing exploit directories
	out:
		for _, entry := range serviceTree.Entries {
			if entry.Mode != filemode.Dir {
				continue
			}
			logger := logger.With(zap.String("exploit", entry.Name))
			logger.Debug("loading exploit")

			ref := ExploitRef{
				Service: service.Name,
				Name:    entry.Name,
			}

			if store, ok := exploits[entry.Hash]; ok {
				for _, existingRef := range store.Refs {
					if existingRef.Service == ref.Service {
						logger.Warn(
							"duplicate exploit reference for service, skipping",
							zap.String("service", ref.Service),
							zap.String("new_exp", ref.Name),
							zap.String("exist_exp", existingRef.Name),
						)
						continue out
					}
				}
				exploits[entry.Hash] = ExploitWithRefs{
					Refs:    append(store.Refs, ref),
					Exploit: store.Exploit,
				}
				logger.Debug("exploit already loaded, skipping")
				continue
			}

			if exploit, ok := r.lastExploits[entry.Hash]; ok {
				exploits[entry.Hash] = ExploitWithRefs{
					Refs:    []ExploitRef{ref},
					Exploit: exploit.Exploit,
				}
				logger.Debug("exploit already loaded, skipping")
				continue
			}

			exploitTree, err := r.repo.TreeObject(entry.Hash)
			if err != nil {
				logger.Error("failed to get tree object", zap.Error(err))
				continue
			}

			exploit, err := loadExploit(ctx, logger, r.repo, exploitTree)
			if err != nil {
				logger.Error("failed to load exploit", zap.Error(err))
				continue
			}

			exploits[exploitTree.Hash] = ExploitWithRefs{
				Refs:    []ExploitRef{ref},
				Exploit: exploit,
			}
			logger.Info("exploit loaded successfully", zap.String("dir", exploit.ExtractPath))
		}
	}
	preprocessValues := make([]Preprocess, 0, len(preprocesses))
	for _, preprocess := range preprocesses {
		preprocessValues = append(preprocessValues, preprocess)
	}
	for _, subscriber := range r.preprocessSubscribers {
		subscriber <- preprocessValues
	}
	r.lastPreprocesses = preprocesses

	exploitsValues := make([]ExploitWithRefs, 0, len(exploits))
	for _, exploit := range exploits {
		exploitsValues = append(exploitsValues, exploit)
	}
	for _, subscriber := range r.exploitsSubscribers {
		subscriber <- exploitsValues
	}
	r.lastExploits = exploits
}

func (r *Repository) reloadDefaultImage(logger *zap.Logger, tree *object.Tree) (*DefaultImage, error) {
	tree, err := tree.Tree(defaultImagePath)
	if err != nil {
		return nil, err
	}
	if tree.Hash == r.lastDefaultImageHash {
		return nil, nil
	}

	tempDir, err := extractTreeToDir(logger, r.repo, tree)
	if err != nil {
		logger.Error("failed to extract tree for default image", zap.Error(err))
		return nil, err
	}
	r.lastDefaultImageHash = tree.Hash
	return &DefaultImage{
		ExtractPath: tempDir,
		TreeHash:    tree.Hash,
	}, nil
}

func (r *Repository) reloadFlagSubmitter(logger *zap.Logger, tree *object.Tree) (*Submitter, error) {
	file, err := tree.File("submit_flag")
	if err != nil {
		if !errors.Is(err, object.ErrFileNotFound) {
			return nil, err
		}
		if r.lastFlagSubmitterHash.IsZero() {
			return nil, nil
		}
		logger.Warn("flag submitter file not found, using empty flag submitter")
		r.lastFlagSubmitterHash = plumbing.ZeroHash
		return new(Submitter), nil
	}
	if file.Hash == r.lastFlagSubmitterHash {
		return nil, nil
	}

	temp, err := os.CreateTemp(exploitsPath, "")
	if err != nil {
		logger.Error("failed to create temp file for flag submitter", zap.Error(err))
		return nil, err
	}
	defer func() {
		if err := temp.Close(); err != nil {
			logger.Error("failed to close temp file", zap.Error(err))
		}
	}()
	if err := temp.Chmod(0755); err != nil {
		logger.Error("failed to set flag submitter file permissions", zap.Error(err))
		return nil, err
	}

	reader, err := file.Reader()
	if err != nil {
		logger.Error("failed to get flag submitter reader", zap.Error(err))
		return nil, err
	}
	defer func() {
		if err := reader.Close(); err != nil {
			logger.Error("failed to close flag submitter reader", zap.Error(err))
		}
	}()

	if _, err := temp.ReadFrom(reader); err != nil {
		logger.Error("failed to copy preprocess file", zap.Error(err))
		return nil, err
	}
	name := temp.Name()

	r.lastFlagSubmitterHash = file.Hash
	return &name, nil
}

func (r *Repository) reload(ctx context.Context, logger *zap.Logger, head *plumbing.Reference) error {
	commit, err := r.repo.CommitObject(head.Hash())
	if err != nil {
		logger.Error("failed to get commit object", zap.Error(err), zap.Stringer("commit", head.Hash()))
		return err
	}

	tree, err := commit.Tree()
	if err != nil {
		logger.Error("failed to get commit tree", zap.Error(err), zap.Stringer("commit", commit.Hash))
		return err
	}

	treeLogger := logger.With(zap.Stringer("root", tree.Hash))

	config, err := r.reloadConfig(ctx, treeLogger.Named("config"), tree)
	if err != nil {
		treeLogger.Error("failed to reload config", zap.Error(err))
	} else {
		if config == nil {
			treeLogger.Debug("config not changed, using cached value")
		} else {
			for _, subscriber := range r.configSubscribers {
				subscriber <- config
			}
		}
	}

	teams, err := r.reloadTeams(ctx, treeLogger.Named("teams"), tree)
	if err != nil {
		treeLogger.Error("failed to reload teams", zap.Error(err))
	} else {
		if teams == nil {
			treeLogger.Debug("teams not changed, using cached value")
		} else {
			for _, subscriber := range r.teamsSubscribers {
				subscriber <- teams
			}
		}
	}

	services, err := r.reloadServices(ctx, treeLogger.Named("services"), tree)
	if err != nil {
		treeLogger.Error("failed to reload services", zap.Error(err))
	} else {
		if services == nil {
			treeLogger.Debug("services not changed, using cached value")
		} else {
			for _, subscriber := range r.servicesSubscribers {
				subscriber <- services
			}
		}
	}

	r.reloadExploits(ctx, treeLogger.Named("exploits"), tree)

	defaultImage, err := r.reloadDefaultImage(treeLogger.Named("default-image"), tree)
	if err != nil {
		treeLogger.Error("failed to reload default image", zap.Error(err))
	} else {
		if defaultImage == nil {
			treeLogger.Debug("default image not changed, using cached value")
		} else {
			for _, subscriber := range r.defaultImageSubscribers {
				subscriber <- defaultImage
			}
		}
	}

	flagSubmitter, err := r.reloadFlagSubmitter(treeLogger.Named("flag-submitter"), tree)
	if err != nil {
		treeLogger.Error("failed to reload flag submitter", zap.Error(err))
	} else {
		if flagSubmitter == nil {
			treeLogger.Debug("flag submitter not changed, using cached value")
		} else {
			for _, subscriber := range r.flagSubmitterSubscribers {
				subscriber <- *flagSubmitter
			}
		}
	}

	return nil
}

func (r *Repository) Run(ctx context.Context, logger *zap.Logger) error {
	head, err := r.repo.Head()
	if err != nil {
		logger.Error("failed to get repository head", zap.Error(err))
		return err
	}

	r.started = true

	if err := r.reload(ctx, logger, head); err != nil {
		logger.Error("initial repository load failed", zap.Error(err))
		return err
	}

	logger.Info("repository reload started", zap.Duration("interval", reloadInterval))

	for {
		select {
		case <-ctx.Done():
			logger.Info("repository reload stopped")
			return nil
		case <-time.After(reloadInterval):
			if err := func() error {
				timeout, cancelFunc := context.WithTimeout(ctx, fetchTimeout)
				defer cancelFunc()

				return r.repo.FetchContext(timeout, &git.FetchOptions{
					Tags:  git.NoTags,
					Depth: 1,
					Force: true,
				})
			}(); err != nil {
				if !errors.Is(err, git.NoErrAlreadyUpToDate) {
					if !errors.Is(err, context.Canceled) {
						logger.Error("failed to fetch repository", zap.Error(err))
					}
					continue
				}
			}

			newHead, err := r.repo.Head()
			if err != nil {
				logger.Error("failed to get repository head after fetch", zap.Error(err))
				continue
			}
			if newHead.Hash() == head.Hash() {
				//logger.Debug("repository already up to date, skipping reload")
				continue
			}
			logger.Debug("updating head to new commit", zap.Stringer("old", head.Hash()), zap.Stringer("new", newHead.Hash()))
			head = newHead

			if err := r.reload(ctx, logger, head); err != nil {
				logger.Error("failed to reload repository", zap.Error(err))
			} else {
				logger.Info("repository reloaded successfully")
			}
		}
	}
}
