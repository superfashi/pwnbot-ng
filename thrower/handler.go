package thrower

import (
	"pwnbot-ng/proxy"
)

type handler struct {
	info  *runningInfo
	inode uint32
}

func (h handler) Release() {
	h.info.sockets.Delete(h.inode)
}

func (h handler) SetRejected(retry bool) {
	if retry {
		h.info.rejected.Store(1)
	} else {
		h.info.rejected.Store(-1)
	}
}

func (h handler) String() string {
	return h.info.debug
}

func (h handler) GetPreAllocator() *proxy.PreAllocator {
	return h.info.allocator
}

func (h handler) ObfuscateTraffic() *bool {
	return h.info.obfuscate
}
