package thrower

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/containers/storage/pkg/reexec"
	"go.uber.org/zap"
)

/*#cgo CFLAGS: -O3 -march=native -Wall -Wextra -Werror
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <dirent.h>
#include <sched.h>

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[0];
};

static inline int is_numeric(const char *str) {
	while (*str) {
		if (*str < '0' || *str > '9') {
			return 0;
		}
		str++;
	}
	return 1;
}

static inline void scan_fd(const int dir_fd, const char *const target, const size_t target_len) {
	uint8_t buf[0x1000] __attribute__((aligned(0x1000)));
	char buf2[PATH_MAX] __attribute__((aligned(0x1000)));

	while (1) {
		const ssize_t bytes_read = getdents64(dir_fd, buf, sizeof(buf));
		if (bytes_read < 0) {
			perror("getdents64");
			return;
		}

		if (bytes_read == 0) {
			break; // No more entries
		}

		for (ssize_t off = 0; off < bytes_read;) {
			struct linux_dirent64 *entry = (struct linux_dirent64 *)(buf + off);
			off += entry->d_reclen;

			if (strcmp(entry->d_name, ".") == 0 ||
			    strcmp(entry->d_name, "..") == 0 ||
			    strcmp(entry->d_name, "0") == 0 ||
			    strcmp(entry->d_name, "1") == 0 ||
			    strcmp(entry->d_name, "2") == 0) {
				continue;
			}
			if (entry->d_type != DT_LNK) {
				continue;
			}
			ssize_t link_size = readlinkat(dir_fd, entry->d_name, buf2, sizeof(buf2));
			if (link_size < 0) {
				perror("readlinkat");
				continue;
			}
			if ((size_t)link_size != target_len) {
				continue;
			}
			if (memcmp(buf2, target, target_len) != 0) {
				continue;
			}
			exit(0);
		}
	}
}

__attribute__((constructor))
static void search_in_namespace(const int argc, const char *const argv[]) {
	if (argc < 1 || strcmp(argv[0], "searchInNamespace") != 0) {
		return;
	}
	if (argc < 2) {
		exit(2);
	}
	int err = setns(3, CLONE_NEWNS);
	if (err != 0) {
		perror("setns");
		exit(2);
	}
	const int proc_fd = open("/proc", O_RDONLY);
	if (proc_fd < 0) {
		perror("open");
		exit(2);
	}
	const size_t target_len = strlen(argv[1]);

	uint8_t buf[0x1000] __attribute__((aligned(0x1000)));
	while (1) {
		const ssize_t bytes_read = getdents64(proc_fd, buf, sizeof(buf));
		if (bytes_read < 0) {
			perror("getdents64");
			exit(2);
		}

		if (bytes_read == 0) {
			break; // No more entries
		}

		for (ssize_t off = 0; off < bytes_read;) {
			struct linux_dirent64 *entry = (struct linux_dirent64 *)(buf + off);
			off += entry->d_reclen;

			if (entry->d_type != DT_DIR) {
				continue;
			}

			if (!is_numeric(entry->d_name)) {
				continue;
			}

			char buf2[256];
			size_t off = 0;
			// this should be safe as fd is an integer
			for (const char *p = entry->d_name; *p; p++) {
				buf2[off++] = *p;
			}
			buf2[off++] = '/';
			buf2[off++] = 'f';
			buf2[off++] = 'd';
			buf2[off] = '\0';

			const int dir_fd = openat(proc_fd, buf2, O_RDONLY);
			if (dir_fd < 0) {
				perror("openat");
				continue;
			}
			scan_fd(dir_fd, argv[1], target_len);
			if (close(dir_fd) != 0) {
				perror("close");
				continue;
			}
		}
	}
	exit(1);
}
*/
import "C"

func searchInNamespace(logger *zap.Logger, pid int, target string) bool {
	mntns, err := os.Open(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	if err != nil {
		logger.Error("failed to open mount namespace", zap.Int("pid", pid), zap.Error(err))
		return false
	}
	defer func() {
		if err := mntns.Close(); err != nil {
			logger.Error("failed to close mount namespace", zap.Int("pid", pid), zap.Error(err))
		}
	}()

	cmd := reexec.Command("searchInNamespace", target)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{mntns}

	err = cmd.Run()
	if err == nil {
		return true
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return false
	}
	logger.Error("searchInNamespace command failed", zap.Int("pid", pid), zap.Error(err))
	return false
}
