package utils

import (
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
)

var DevNull *os.File

func init() {
	var err error
	DevNull, err = os.Open(os.DevNull)
	if err != nil {
		panic("failed to open /dev/null: " + err.Error())
	}
}

func CreateAnonymousSocket(logger *zap.Logger) (*os.File, *os.File, error) {
	fd, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		logger.Error("failed to create anonymous socket", zap.Error(err))
		return nil, nil, err
	}
	if fd[0] < 0 || fd[1] < 0 {
		logger.Error("invalid file descriptors for anonymous socket", zap.Ints("fd", fd[:]))
		return nil, nil, syscall.EINVAL
	}

	oneEnd := os.NewFile(uintptr(fd[0]), "socket-end-0")
	if oneEnd == nil {
		if err := syscall.Close(fd[0]); err != nil {
			logger.Error("failed to close socket end 0", zap.Error(err))
		}
		if err := syscall.Close(fd[1]); err != nil {
			logger.Error("failed to close socket end 1", zap.Error(err))
		}
		return nil, nil, syscall.EINVAL
	}

	otherEnd := os.NewFile(uintptr(fd[1]), "socket-end-1")
	if otherEnd == nil {
		if err := oneEnd.Close(); err != nil {
			logger.Error("failed to close socket end 0", zap.Error(err))
		}
		if err := syscall.Close(fd[1]); err != nil {
			logger.Error("failed to close socket end 1", zap.Error(err))
		}
		return nil, nil, syscall.EINVAL
	}

	return oneEnd, otherEnd, nil
}

var runIdMono atomic.Uint64
var epoch = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

func init() {
	runIdMono.Store(uint64(time.Since(epoch).Milliseconds()))
}

func GenerateRunID() string {
	id := runIdMono.Add(1)
	const crockfordBase32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

	return string([]byte{
		crockfordBase32[(id>>30)&0x1F],
		crockfordBase32[(id>>25)&0x1F],
		crockfordBase32[(id>>20)&0x1F],
		crockfordBase32[(id>>15)&0x1F],
		crockfordBase32[(id>>10)&0x1F],
		crockfordBase32[(id>>5)&0x1F],
		crockfordBase32[id&0x1F],
	})
}

func ShutdownWrite(file *os.File) error {
	conn, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var outerErr error
	if err := conn.Control(func(fd uintptr) {
		outerErr = syscall.Shutdown(int(fd), syscall.SHUT_WR)
	}); err != nil {
		return err
	}
	return outerErr
}
