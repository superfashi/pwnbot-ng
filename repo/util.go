package repo

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/goccy/go-yaml"
	"go.uber.org/zap"
)

func parseYaml(ctx context.Context, logger *zap.Logger, file *object.File, out any) error {
	fileLogger := logger.With(zap.String("file", file.Name))

	reader, err := file.Reader()
	if err != nil {
		fileLogger.Error("failed to open file", zap.Error(err))
		return err
	}
	defer func() {
		if err := reader.Close(); err != nil {
			fileLogger.Error("failed to close file reader", zap.Error(err))
		}
	}()

	if err := yaml.NewDecoder(reader).DecodeContext(ctx, out); err != nil && err != io.EOF {
		fileLogger.Warn("failed to parse yaml", zap.Error(err))
		return err
	}
	return nil
}

const (
	defaultImagePath     = ".default-image"
	trafficObfuscatePath = ".traffic-obfuscate"
)

func isSpecialDir(name string) bool {
	return name == defaultImagePath || name == trafficObfuscatePath
}

func extractTreeToDir(logger *zap.Logger, repo *git.Repository, tree *object.Tree) (string, error) {
	tempDir, err := os.MkdirTemp(exploitsPath, "")
	if err != nil {
		logger.Error("failed to create temp directory for exploit", zap.Error(err))
		return "", err
	}
	var noRemove bool
	defer func() {
		if !noRemove {
			if err := os.RemoveAll(tempDir); err != nil {
				logger.Error("failed to remove temp directory for exploit", zap.Error(err))
			}
		}
	}()

	tempDir, err = filepath.Abs(tempDir)
	if err != nil {
		logger.Error("failed to get absolute path for exploit", zap.Error(err))
		return "", err
	}
	if err := os.Chmod(tempDir, 0o755); err != nil { // ensure the temp directory is accessible
		logger.Error("failed to set permissions for temp directory", zap.Error(err))
		return "", err
	}
	if err := extractTree(logger, repo, tree, tempDir, ""); err != nil {
		logger.Error("failed to extract exploit", zap.Error(err))
		return "", err
	}

	noRemove = true
	return tempDir, nil
}

func extractTree(logger *zap.Logger, repo *git.Repository, tree *object.Tree, base, dir string) error {
	for _, entry := range tree.Entries {
		path := dir + "/" + entry.Name
		entryLogger := logger.With(zap.Stringer("blob", entry.Hash), zap.String("path", path))

		switch entry.Mode {
		case filemode.Dir:
			treeObject, err := repo.TreeObject(entry.Hash)
			if err != nil {
				entryLogger.Error("failed to get tree object", zap.Error(err))
				continue
			}
			if err := os.Mkdir(base+path, 0777); err != nil {
				logger.Error("failed to create directory", zap.Error(err), zap.String("path", base+path))
				return err
			}
			if err := extractTree(logger, repo, treeObject, base, path); err != nil {
				entryLogger.Error("failed to extract tree", zap.Error(err))
				return err
			}
		case filemode.Regular, filemode.Executable:
			blobObject, err := repo.BlobObject(entry.Hash)
			if err != nil {
				entryLogger.Error("failed to get blob object", zap.Error(err))
				continue
			}
			if err := func() error {
				fileReader, err := blobObject.Reader()
				if err != nil {
					entryLogger.Error("failed to open blob reader", zap.Error(err))
					return err
				}
				defer func() {
					if err := fileReader.Close(); err != nil {
						entryLogger.Error("failed to close blob reader", zap.Error(err))
					}
				}()

				filePath := base + path

				mode := os.FileMode(0666)
				if entry.Mode == filemode.Executable {
					mode = 0777
				}

				fileWriter, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
				if err != nil {
					logger.Error("failed to create file", zap.String("path", filePath), zap.Error(err))
					return err
				}
				defer func() {
					if err := fileWriter.Close(); err != nil {
						logger.Error("failed to close file writer", zap.String("path", filePath), zap.Error(err))
					}
				}()

				if _, err := fileWriter.ReadFrom(fileReader); err != nil {
					logger.Error("failed to copy blob", zap.String("path", filePath), zap.Error(err))
					return err
				}
				return nil
			}(); err != nil {
				return err
			}
		case filemode.Symlink:
			blobObject, err := repo.BlobObject(entry.Hash)
			if err != nil {
				entryLogger.Error("failed to get blob object", zap.Error(err))
				continue
			}
			link, err := func() ([]byte, error) {
				fileReader, err := blobObject.Reader()
				if err != nil {
					entryLogger.Error("failed to open blob reader", zap.Error(err))
					return nil, err
				}
				defer func() {
					if err := fileReader.Close(); err != nil {
						entryLogger.Error("failed to close blob reader", zap.Error(err))
					}
				}()
				return io.ReadAll(fileReader)
			}()
			if err != nil {
				return err
			}

			if err := os.Symlink(string(link), base+path); err != nil {
				logger.Error("failed to create symlink", zap.String("path", base+path), zap.Error(err))
				return err
			}
		default:
			logger.Error("unsupported file mode", zap.String("path", path), zap.Stringer("mode", entry.Mode))
			return os.ErrInvalid
		}
	}
	return nil
}
