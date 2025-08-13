package proxy

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestBreakerMultipleTrip(t *testing.T) {
	var b circuitBreaker
	b.trip()
	b.trip()
	b.trip()
	if b.retry != 1 {
		t.Errorf("Expected retry count to be 1 after multiple trips, got %d", b.retry)
	}
}

func TestResetReturnImmediately(t *testing.T) {
	var b circuitBreaker
	b.trip()

	ch := make(chan struct{})
	go func() {
		ch <- struct{}{}
		b.backoff(context.Background(), zap.NewNop())
		ch <- struct{}{}
	}()

	<-ch
	start := time.Now()
	b.reset(zap.NewNop())
	<-ch
	if since := time.Since(start); since > time.Second {
		t.Errorf("Expected reset to return immediately, took %v", since)
	}
}
