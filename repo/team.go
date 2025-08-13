package repo

import (
	"context"
	"fmt"

	"github.com/go-git/go-git/v5/plumbing/object"
	"go.uber.org/zap"
)

type Team struct {
	Name  string
	Host  string
	Extra map[string]any
}

func checkTeams(ctx context.Context, logger *zap.Logger, file *object.File) error {
	var teams map[string]map[string]any
	if err := parseYaml(ctx, logger, file, &teams); err != nil {
		logger.Error("failed to parse teams", zap.Error(err))
		return err
	}

	for name, obj := range teams {
		if _, ok := obj["host"]; !ok {
			return fmt.Errorf("team %q has no host", name)
		}
	}

	return nil
}

func loadTeams(ctx context.Context, logger *zap.Logger, file *object.File) ([]*Team, error) {
	var teams map[string]map[string]any
	if err := parseYaml(ctx, logger, file, &teams); err != nil {
		logger.Error("failed to parse teams", zap.Error(err))
		return nil, err
	}

	teamList := make([]*Team, 0, len(teams))
	for name, obj := range teams {
		host, ok := obj["host"].(string)
		if !ok {
			logger.Error("team has no host", zap.String("team", name))
			continue
		}
		delete(obj, "host")

		teamList = append(teamList, &Team{Name: name, Host: host})
	}

	return teamList, nil
}
