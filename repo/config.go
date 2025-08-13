package repo

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/go-git/go-git/v5/plumbing/object"
	"go.uber.org/zap"
)

type ConfigValues struct {
	FlagRegex []*regexp.Regexp

	DefaultTimeout          time.Duration
	DefaultCooldown         time.Duration
	DefaultRetries          uint
	DefaultObfuscateTraffic bool

	DockerBuildTimeout       time.Duration
	DockerBuildConcurrency   uint
	DockerBuildRetryInterval time.Duration

	ConnectionConcurrency     uint
	UserConnectionConcurrency uint
}

var defaultFlagRegex = regexp.MustCompile(`(?i)^flag:\s+(.+)$`)

func DefaultConfig() *ConfigValues {
	return &ConfigValues{
		FlagRegex: []*regexp.Regexp{defaultFlagRegex},

		DefaultTimeout:          15 * time.Second,
		DefaultCooldown:         time.Minute,
		DefaultRetries:          0,
		DefaultObfuscateTraffic: false,

		DockerBuildTimeout:       5 * time.Minute,
		DockerBuildConcurrency:   8,
		DockerBuildRetryInterval: 5 * time.Second,

		ConnectionConcurrency:     50,
		UserConnectionConcurrency: 15,
	}
}

type configInner struct {
	FlagRegex []string `yaml:"flag_regex"`

	DefaultTimeout          *time.Duration `yaml:"default_timeout"`
	DefaultCooldown         *time.Duration `yaml:"default_cooldown"`
	DefaultRetries          *uint          `yaml:"default_retries"`
	DefaultObfuscateTraffic bool           `yaml:"default_obfuscate_traffic"`

	DockerBuildTimeout       *time.Duration `yaml:"docker_build_timeout"`
	DockerBuildConcurrency   *uint          `yaml:"docker_build_concurrency"`
	DockerBuildRetryInterval *time.Duration `yaml:"docker_build_retry_interval"`

	ConnectionConcurrency     *uint `yaml:"connection_concurrency"`
	UserConnectionConcurrency *uint `yaml:"user_connection_concurrency"`
}

func checkConfig(ctx context.Context, logger *zap.Logger, file *object.File) error {
	configYaml := new(configInner)
	if err := parseYaml(ctx, logger, file, configYaml); err != nil {
		return err
	}
	for _, regexStr := range configYaml.FlagRegex {
		regex, err := regexp.Compile(regexStr)
		if err != nil {
			return fmt.Errorf("failed to parse regex %q: %w", regexStr, err)
		}
		if regex.NumSubexp() != 1 {
			return fmt.Errorf("regex must have exactly one subexpression: %q", regexStr)
		}
	}
	if configYaml.DockerBuildConcurrency != nil && *configYaml.DockerBuildConcurrency <= 0 {
		return errors.New(`"docker_build_concurrency" must be greater than 0`)
	}
	if configYaml.UserConnectionConcurrency != nil && *configYaml.UserConnectionConcurrency <= 0 {
		return errors.New(`"user_connection_concurrency" must be greater than 0`)
	}
	if configYaml.ConnectionConcurrency != nil && *configYaml.ConnectionConcurrency <= 0 {
		return errors.New(`"connection_concurrency" must be greater than 0`)
	}
	return nil
}

func loadConfig(ctx context.Context, logger *zap.Logger, file *object.File) (*ConfigValues, error) {
	newConfigYaml := new(configInner)
	if err := parseYaml(ctx, logger, file, newConfigYaml); err != nil {
		return nil, err
	}

	newConfig := DefaultConfig()

	if len(newConfigYaml.FlagRegex) > 0 {
		newConfig.FlagRegex = make([]*regexp.Regexp, 0, len(newConfigYaml.FlagRegex))
		for _, regexStr := range newConfigYaml.FlagRegex {
			regex, err := regexp.Compile(regexStr)
			if err != nil {
				logger.Warn("invalid regex", zap.String("regex", regexStr))
				continue
			}
			if regex.NumSubexp() != 1 {
				logger.Warn("regex must have exactly one subexpression", zap.String("regex", regexStr))
				continue
			}
			newConfig.FlagRegex = append(newConfig.FlagRegex, regex)
		}
	}

	if newConfigYaml.DefaultTimeout != nil {
		newConfig.DefaultTimeout = *newConfigYaml.DefaultTimeout
	}

	if newConfigYaml.DefaultCooldown != nil {
		newConfig.DefaultCooldown = *newConfigYaml.DefaultCooldown
	}

	if newConfigYaml.DefaultRetries != nil {
		newConfig.DefaultRetries = *newConfigYaml.DefaultRetries
	}

	newConfig.DefaultObfuscateTraffic = newConfigYaml.DefaultObfuscateTraffic

	if newConfigYaml.DockerBuildTimeout != nil {
		newConfig.DockerBuildTimeout = *newConfigYaml.DockerBuildTimeout
	}
	if newConfigYaml.DockerBuildConcurrency != nil {
		if *newConfigYaml.DockerBuildConcurrency == 0 {
			logger.Warn("'docker_build_concurrency' must be greater than 0")
		} else {
			newConfig.DockerBuildConcurrency = *newConfigYaml.DockerBuildConcurrency
		}
	}
	if newConfigYaml.DockerBuildRetryInterval != nil {
		newConfig.DockerBuildRetryInterval = *newConfigYaml.DockerBuildRetryInterval
	}

	if newConfigYaml.UserConnectionConcurrency != nil {
		if *newConfigYaml.UserConnectionConcurrency == 0 {
			logger.Warn("'user_connection_concurrency' must be greater than 0")
		} else {
			newConfig.UserConnectionConcurrency = *newConfigYaml.UserConnectionConcurrency
		}
	}
	if newConfigYaml.ConnectionConcurrency != nil {
		if *newConfigYaml.ConnectionConcurrency == 0 {
			logger.Warn("'connection_concurrency' must be greater than 0")
		} else {
			newConfig.ConnectionConcurrency = *newConfigYaml.ConnectionConcurrency
		}
	}

	return newConfig, nil
}
