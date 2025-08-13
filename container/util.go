package container

import (
	"github.com/containers/image/v5/docker/reference"
	"github.com/openshift/imagebuilder"
	"github.com/openshift/imagebuilder/dockerfile/command"
	"go.uber.org/zap"

	"pwnbot-ng/repo"
)

func checkIfDockerfileDependentOnDefault(logger *zap.Logger, exploit *repo.Exploit) bool {
	if !exploit.HasDockerFile {
		return false
	}
	node, err := imagebuilder.ParseFile(exploit.ExtractPath + "/Dockerfile")
	if err != nil {
		logger.Error("failed to parse Dockerfile", zap.Error(err), zap.Stringer("hash", exploit.TreeHash))
		return false
	}
	froms := imagebuilder.SplitChildren(node, command.From)
	for _, from := range froms {
		if from.Next == nil {
			continue
		}
		parse, err := reference.Parse(from.Next.Value)
		if err != nil {
			logger.Error("failed to parse FROM value", zap.Error(err), zap.Stringer("hash", exploit.TreeHash), zap.String("value", from.Next.Value))
			continue
		}
		named, ok := parse.(reference.Named)
		if !ok {
			continue
		}
		if named.Name() == defaultImageTag {
			return true
		}
	}
	return false
}
