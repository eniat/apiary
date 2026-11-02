// Package telemetry publishes the loop's own numbers for prometheus.
package telemetry

import (
	"net"
	"net/http"
	"time"

	"github.com/eniat/apiary/orchestrator/internal/loop"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	reg       *prometheus.Registry
	honeypots *prometheus.GaugeVec
	sessions  prometheus.Gauge
	unserved  prometheus.Gauge
	actions   *prometheus.CounterVec
	promote   prometheus.Histogram
	reaped    prometheus.Counter
}

// own registry so the go runtime's own metrics stay out
func New() *Metrics {
	m := &Metrics{
		reg: prometheus.NewRegistry(),
		honeypots: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "apiary_honeypots",
			Help: "honeypots by state",
		}, []string{"state"}),
		sessions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "apiary_sessions",
			Help: "open attacker sessions",
		}),
		unserved: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "apiary_unserved_flows",
			Help: "flagged flows with nowhere to go",
		}),
		actions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "apiary_scaling_actions_total",
			Help: "policy decisions reached",
		}, []string{"action"}),
		promote: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "apiary_promotion_seconds",
			Help: "promote to live, a map write against a cold start",
			// a microsecond to ten seconds spans both paths
			Buckets: prometheus.ExponentialBuckets(0.000001, 10, 8),
		}),
		reaped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "apiary_reaped_total",
			Help: "honeypots destroyed",
		}),
	}
	m.reg.MustRegister(m.honeypots, m.sessions, m.unserved, m.actions, m.promote, m.reaped)
	return m
}

// one tick in
func (m *Metrics) Observe(res loop.Result) {
	s := res.Snapshot
	m.honeypots.WithLabelValues("live").Set(float64(s.Live))
	m.honeypots.WithLabelValues("warm").Set(float64(s.Warm))
	m.sessions.Set(float64(s.Sessions))
	m.unserved.Set(float64(s.Unserved))
	m.actions.WithLabelValues(res.Action.String()).Inc()
	// an empty pool is a scale up that promoted nothing so it times nothing
	if res.Promoted != "" {
		m.promote.Observe(res.Took.Seconds())
	}
	m.reaped.Add(float64(res.Reaped))
}

// listens before returning so the first scrape cant race the first tick
func (m *Metrics) Serve(addr string) (*http.Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{}))
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return srv, nil
}
