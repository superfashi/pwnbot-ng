package ticker

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

type Info = time.Time

type Ticker struct {
	lock sync.Mutex
	subs []chan<- Info

	lastTick atomic.Pointer[time.Time]

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewTicker(ctx context.Context, logger *zap.Logger, listenAddr string, roundDuration time.Duration) (*Ticker, error) {
	conn, err := new(net.ListenConfig).ListenPacket(ctx, "udp", listenAddr)
	if err != nil {
		logger.Error("failed to listen on UDP address", zap.String("address", listenAddr), zap.Error(err))
		return nil, err
	}
	logger.Info("ticker started", zap.Stringer("address", conn.LocalAddr()), zap.Stringer("round", roundDuration))

	ctx, cancel := context.WithCancel(ctx)

	t := &Ticker{
		cancel: cancel,
	}
	last := time.Now().Truncate(roundDuration)
	t.lastTick.Store(&last)

	external := make(chan time.Time)

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		defer func() {
			if err := conn.Close(); err != nil {
				logger.Error("failed to close packet conn", zap.Error(err))
			}
		}()

		var buffer [16]byte
		for {
			n, _, err := conn.ReadFrom(buffer[:])
			if err != nil {
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					logger.Error("failed to read from packet conn", zap.Error(err))
				}
				return
			}
			if n == 4+8 && bytes.Equal(buffer[:4], []byte("tick")) {
				tickAt := time.UnixMicro(int64(binary.BigEndian.Uint64(buffer[4:])))
				logger.Debug("received tick", zap.Time("tick", tickAt))
				select {
				case external <- tickAt:
				default:
					// the only way for this case is if the run thread is not consuming
					// which means that the thread was processing something else
				}
			} else {
				logger.Warn("received unexpected data", zap.ByteString("data", buffer[:n]))
			}
		}
	}()

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		<-ctx.Done()
		if err := conn.SetReadDeadline(time.Now()); err != nil {
			logger.Error("failed to set read deadline", zap.Error(err))
		}
	}()

	t.wg.Add(1)
	go t.run(ctx, roundDuration, external)

	return t, nil
}

func (t *Ticker) SubscribeTicker() <-chan Info {
	ch := make(chan Info)

	t.lock.Lock()
	defer t.lock.Unlock()

	t.subs = append(t.subs, ch)
	return ch
}

func (t *Ticker) notifyAll(tick time.Time) {
	if tick.Before(t.LastTick()) {
		return // Ignore ticks that are older than the last tick
	}
	t.lastTick.Store(&tick)

	t.lock.Lock()
	defer t.lock.Unlock()
	for _, sub := range t.subs {
		select {
		case sub <- tick:
		default:
		}
	}
}

func (t *Ticker) Stop() {
	t.cancel()
	t.wg.Wait()
}

func (t *Ticker) LastTick() time.Time {
	return *t.lastTick.Load()
}

func (t *Ticker) run(ctx context.Context, duration time.Duration, external <-chan time.Time) {
	defer t.wg.Done()

	n := time.Now()
	passed := n.Sub(n.Truncate(duration))

	if passed > 0 {
		select {
		case <-ctx.Done():
			return
		case now := <-external:
			t.notifyAll(now)
		case now := <-time.After(duration - passed):
			t.notifyAll(now)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-external:
			t.notifyAll(now)
		case now := <-time.After(duration):
			t.notifyAll(now)
		}
	}
}
