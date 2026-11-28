package metrics

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
)

// Server exposes `/metrics` and `/healthz` strictly on the configured overlay device IP.
type Server struct {
	cfg       config.MetricsConfig
	collector *Collector
	logger    *slog.Logger
	ipFn      func(dev string) (string, error)
}

// NewServer constructs a metrics HTTP Server.
func NewServer(cfg config.MetricsConfig, collector *Collector, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		cfg:       cfg,
		collector: collector,
		logger:    logger,
		ipFn:      ResolveInterfaceIP,
	}
}

// ResolveInterfaceIP looks up a unicast IPv4 (or non-link-local IPv6) address assigned to dev.
func ResolveInterfaceIP(dev string) (string, error) {
	iface, err := net.InterfaceByName(dev)
	if err != nil {
		return "", fmt.Errorf("lookup device %q: %w", dev, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("list addrs on %q: %w", dev, err)
	}
	var v6Fallback string
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP == nil || ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() {
			continue
		}
		if v4 := ipNet.IP.To4(); v4 != nil {
			return v4.String(), nil
		}
		if v6Fallback == "" {
			v6Fallback = ipNet.IP.String()
		}
	}
	if v6Fallback != "" {
		return v6Fallback, nil
	}
	return "", fmt.Errorf("device %q has no unicast IP assigned yet", dev)
}

// Handler returns the HTTP handler serving /metrics and /healthz.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var buf bytes.Buffer
		s.collector.WritePrometheus(r.Context(), &buf)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

// Run waits until the bind device has an IP, then serves /metrics strictly on that IP until ctx is cancelled.
func (s *Server) Run(ctx context.Context) {
	if !s.cfg.Enabled {
		return
	}

	var ip string
	for {
		var err error
		ip, err = s.ipFn(s.cfg.BindDevice)
		if err == nil && ip != "" {
			break
		}
		s.logger.Debug("waiting for metrics bind device IP", "device", s.cfg.BindDevice, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}

	listenAddr := net.JoinHostPort(ip, strconv.Itoa(s.cfg.Port))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		s.logger.Error("metrics server listen failed", "addr", listenAddr, "err", err)
		return
	}

	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	s.logger.Info("metrics server listening on overlay device", "device", s.cfg.BindDevice, "addr", listenAddr)

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		s.logger.Error("metrics server exited with error", "err", err)
	}
}
