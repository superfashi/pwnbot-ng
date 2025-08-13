package thrower

import (
	"bytes"
	"context"
	"io"
	"os"

	"go.uber.org/zap"
)

type flagLogger struct {
	logFile io.WriteCloser
	buffer  bytes.Buffer
	lineCh  chan<- string
	closed  <-chan struct{}
}

func createFlagLogger(ctx context.Context, path string, lineCh chan<- string) (*flagLogger, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &flagLogger{logFile: f, lineCh: lineCh, closed: ctx.Done()}, nil
}

func (f *flagLogger) Write(p []byte) (n int, err error) {
	n, err = f.logFile.Write(p)
	if err != nil {
		return n, err
	}
	if n != len(p) {
		return n, io.ErrShortWrite
	}

out:
	for {
		idx := bytes.IndexByte(p, '\n')
		if idx < 0 {
			f.buffer.Write(p)
			break
		}
		f.buffer.Write(p[:idx])
		p = p[idx+1:]
		select {
		case <-f.closed:
			break out
		case f.lineCh <- f.buffer.String():
		}
		f.buffer.Reset()
	}

	return n, nil
}

func (f *flagLogger) close(logger *zap.Logger) {
	if err := f.logFile.Close(); err != nil {
		logger.Error("error closing log file", zap.Error(err))
	}
	select {
	case <-f.closed:
		return
	default:
	}
	if f.buffer.Len() > 0 {
		f.lineCh <- f.buffer.String()
		f.buffer.Reset()
	}
}
