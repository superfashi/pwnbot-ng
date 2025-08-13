package repo

import (
	"context"
	"errors"
	"math"

	"github.com/go-git/go-git/v5/plumbing/object"
	"go.uber.org/zap"
)

type Service struct {
	Name  string
	Port  uint16
	Extra map[string]any
}

func checkServices(ctx context.Context, logger *zap.Logger, file *object.File) ([]string, error) {
	var m map[string]map[string]any
	if err := parseYaml(ctx, logger, file, &m); err != nil {
		return nil, err
	}

	services := make([]string, 0, len(m))
	for name, serviceConfig := range m {
		services = append(services, name)

		if disabledRaw, ok := serviceConfig["disabled"]; ok {
			disabled, ok := disabledRaw.(bool)
			if !ok {
				return nil, errors.New(`wrong type of field "disabled", expected bool`)
			}
			if disabled {
				continue
			}
		}

		if portRaw, ok := serviceConfig["port"]; ok {
			port, ok := portRaw.(uint64)
			if !ok {
				return nil, errors.New(`wrong type of field "port", expected int`)
			}
			if port <= 0 || port > math.MaxUint16 {
				return nil, errors.New("port number is out of range")
			}
		} else {
			return nil, errors.New("service port not specified")
		}
	}
	return services, nil
}

func loadServices(ctx context.Context, logger *zap.Logger, file *object.File) ([]*Service, error) {
	var m map[string]map[string]any
	if err := parseYaml(ctx, logger, file, &m); err != nil {
		return nil, err
	}

	services := make([]*Service, 0, len(m))
	for name, serviceConfig := range m {
		serviceLogger := logger.With(zap.String("name", name))

		service := new(Service)
		if disabledRaw, ok := serviceConfig["disabled"]; ok {
			disabled, ok := disabledRaw.(bool)
			if !ok {
				serviceLogger.Warn("wrong type of field 'disabled', expected bool")
				continue
			}
			if disabled {
				serviceLogger.Debug("skipping disabled service")
				continue
			}
			delete(serviceConfig, "disabled")
		}

		if portRaw, ok := serviceConfig["port"]; ok {
			port, ok := portRaw.(uint64)
			if !ok {
				serviceLogger.Warn("wrong type of field 'port', expected uint64")
				continue
			}
			if port <= 0 || port > math.MaxUint16 {
				serviceLogger.Warn("port number is out of range")
				continue
			}
			service.Port = uint16(port)
			delete(serviceConfig, "port")
		} else {
			serviceLogger.Warn("service port not specified")
			continue
		}

		service.Extra = serviceConfig
		service.Name = name
		services = append(services, service)
	}

	return services, nil
}
