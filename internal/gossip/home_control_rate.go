package gossip

import "time"

const (
	homeControlWorkPerSecond = 200.0
	homeControlWorkBurst     = 2000.0
)

type homeControlRate struct {
	tokens   float64
	lastSeen time.Time
}

type homeControlPacer struct {
	started time.Time
	work    float64
}

func newHomeControlPacer() *homeControlPacer {
	return &homeControlPacer{started: time.Now()}
}

func (p *homeControlPacer) wait(work int) {
	if work < 1 {
		work = 1
	}
	p.work += float64(work)
	available := homeControlWorkBurst + time.Since(p.started).Seconds()*homeControlWorkPerSecond
	if p.work <= available {
		return
	}
	time.Sleep(time.Duration((p.work - available) / homeControlWorkPerSecond * float64(time.Second)))
}

// allowHomeControl applies a dedicated work budget to private-home control
// traffic. It is separate from ordinary envelope/forward capacity because a
// control item can require signature verification or persistent writes.
func (m *Manager) allowHomeControl(peer string, work int) bool {
	if work < 1 {
		work = 1
	}
	cost := float64(work)
	if cost > homeControlWorkBurst {
		return false
	}
	now := time.Now()
	m.homeRateMu.Lock()
	defer m.homeRateMu.Unlock()
	rate := m.homeRates[peer]
	if rate == nil {
		m.homeRates[peer] = &homeControlRate{tokens: homeControlWorkBurst - cost, lastSeen: now}
		return true
	}
	rate.tokens += now.Sub(rate.lastSeen).Seconds() * homeControlWorkPerSecond
	if rate.tokens > homeControlWorkBurst {
		rate.tokens = homeControlWorkBurst
	}
	rate.lastSeen = now
	if rate.tokens < cost {
		return false
	}
	rate.tokens -= cost
	return true
}
