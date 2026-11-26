package server

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

const (
	clientBytesPerSecond = 4 << 20
	globalBytesPerSecond = 16 << 20
	bandwidthChunk       = 32 << 10
	fairWindow           = 250 * time.Millisecond
)

// fairBudget shares the server's total download bandwidth between client
// networks. Each network that took part in the last window, or is taking
// part in this one, may use an equal share of it, so a few networks pulling
// large pastes cannot hold every page, asset, room read and comment until
// they time out. One bucket shared first come, first served did exactly
// that. An IPv6 /48 counts as one network here: one /48 is free from tunnel
// brokers, and its 65,536 /64s must not get a share each.
type fairBudget struct {
	rate float64 // bytes per second, for all networks together
	keys *limiter

	mu    sync.Mutex
	start time.Time            // the current window
	used  map[[16]byte]float64 // bytes each network took this window; 0 for one that waited
	prev  int                  // networks that took part in the previous window
	total float64
}

func newFairBudget(perSecond float64) *fairBudget {
	return &fairBudget{rate: perSecond, keys: newLimiter(0, 0, 0), used: make(map[[16]byte]float64)}
}

// take takes n bytes for ip's network, or says how long until the next
// window. A network that has taken nothing yet this window may always take
// one chunk, so even with many networks each one moves.
func (f *fairBudget) take(ip netip.Addr, now time.Time, n float64) (bool, time.Duration) {
	k, isV6 := f.keys.hashSite(ip)
	if !isV6 {
		k = f.keys.hash(ip)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if now.Sub(f.start) >= fairWindow {
		f.prev = len(f.used)
		clear(f.used)
		f.total = 0
		f.start = now
	}
	capacity := f.rate * fairWindow.Seconds()
	mine, known := f.used[k]
	active := len(f.used)
	if !known {
		active++
	}
	share := capacity / float64(max(active, f.prev, 1))
	if f.total+n > capacity || (mine > 0 && mine+n > share) {
		// Waiting counts as taking part: the next window keeps a share for it.
		if !known {
			f.used[k] = 0
		}
		return false, f.start.Add(fairWindow).Sub(now)
	}
	f.used[k] = mine + n
	f.total += n
	return true, 0
}

// Throttle while streaming rather than buffering a response or admitting
// a huge burst of whole-file downloads. Cancellation stops waiting at once.
type bandwidthWriter struct {
	ctx context.Context
	dst io.Writer
	s   *Server
	ip  netip.Addr
}

func (w bandwidthWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := min(len(p), bandwidthChunk)
		for _, take := range []func(time.Time) (bool, time.Duration){
			func(now time.Time) (bool, time.Duration) { return w.s.downloadBytes.allowN(w.ip, now, float64(n)) },
			func(now time.Time) (bool, time.Duration) { return w.s.globalBytes.take(w.ip, now, float64(n)) },
		} {
			for {
				if err := w.ctx.Err(); err != nil {
					return total, err
				}
				ok, delay := take(time.Now())
				if ok {
					break
				}
				timer := time.NewTimer(delay)
				select {
				case <-w.ctx.Done():
					timer.Stop()
					return total, w.ctx.Err()
				case <-timer.C:
				}
			}
		}
		written, err := w.dst.Write(p[:n])
		total += written
		if err != nil {
			return total, err
		}
		if written != n {
			return total, io.ErrShortWrite
		}
		p = p[n:]
	}
	return total, nil
}

// minRateWriter fails a response that the client reads more slowly than
// rate on average, after a grace period for password and save dialogs. Only
// time spent waiting for the client counts: bandwidthWriter wraps it, so
// time the server spends on its own bandwidth limits never does. A client
// that stops reading cannot hold a download slot for the whole deadline.
type minRateWriter struct {
	w     io.Writer
	rc    *http.ResponseController
	grace time.Duration
	rate  float64   // bytes per second
	hard  time.Time // the response's overall deadline
	n     int64
	spent time.Duration // time blocked writing to the client
	now   func() time.Time
}

func (m *minRateWriter) Write(p []byte) (int, error) {
	allowed := m.grace + time.Duration(float64(m.n+int64(len(p)))/m.rate*float64(time.Second)) - m.spent
	start := m.now()
	deadline := start.Add(allowed)
	if deadline.After(m.hard) {
		deadline = m.hard
	}
	m.rc.SetWriteDeadline(deadline)
	n, err := m.w.Write(p)
	m.spent += m.now().Sub(start)
	m.n += int64(n)
	return n, err
}
