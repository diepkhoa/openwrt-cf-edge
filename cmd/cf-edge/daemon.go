package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/diepkhoa/openwrt-cf-edge/internal/cloudflare"
	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ddos"
	"github.com/diepkhoa/openwrt-cf-edge/internal/edgefw"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ipwatch"
	"github.com/diepkhoa/openwrt-cf-edge/internal/netutil"
	"github.com/diepkhoa/openwrt-cf-edge/internal/notify"
	"github.com/diepkhoa/openwrt-cf-edge/internal/pppoeguard"
	"github.com/diepkhoa/openwrt-cf-edge/internal/reconcile"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ubus"
)

type runtimeDeps struct {
	cfg        *config.Config
	store      *state.Store
	ubusClient *ubus.UbusClient
	netInsp    netutil.NetInspector
	pinger     netutil.Pinger
	notifier   *notify.TelegramClient
	discoverer *ipwatch.Discoverer
	updater    *cloudflare.Updater
	firewall   ddos.Firewall
	worker     ddos.WorkerAPI
	shieldMgr  *ddos.ShieldManager
	edgeFW     *edgefw.Manager
}

func buildDeps(cfgPath string, logger *slog.Logger) (*runtimeDeps, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}

	store := state.NewStore(state.DefaultStatePath)
	if _, err := store.Load(); err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}

	ubusClient := ubus.NewClient(nil)
	netInsp := netutil.LinuxInspector{}
	pinger := &netutil.RawPinger{}
	notifier := notify.NewTelegramClient(cfg.Telegram)
	discoverer := ipwatch.NewDiscoverer(cfg, ubusClient, netInsp, logger)
	cfAPI := cloudflare.NewHTTPClient(cfg.Cloudflare.APIToken)
	updater := cloudflare.NewUpdater(cfg, cfAPI, store, notifier, state.DefaultShieldLockPath, logger)
	firewall := ddos.NewNftFirewall(nil)
	worker := ddos.NewHTTPWorkerClient(cfg.DDoSShield.WorkerURL, cfg.DDoSShield.WorkerToken, -1)

	shieldMgr := ddos.NewShieldManager(
		cfg,
		ubusClient,
		pinger,
		ddos.NewProcSysReader(),
		firewall,
		worker,
		store,
		notifier,
		func(ctx context.Context) (string, error) {
			ip, _, err := discoverer.DiscoverIPv4(ctx)
			return ip, err
		},
		func(ctx context.Context) error {
			snap, err := discoverer.Discover(ctx)
			if err != nil {
				return err
			}
			return updater.Sync(ctx, snap, cloudflare.SyncOptions{Force: true})
		},
		state.DefaultShieldLockPath,
		logger,
	)
	edgeFW := edgefw.NewManager(cfg, ubusClient, nil, nil, nil, nil, notifier, logger)

	return &runtimeDeps{
		cfg:        cfg,
		store:      store,
		ubusClient: ubusClient,
		netInsp:    netInsp,
		pinger:     pinger,
		notifier:   notifier,
		discoverer: discoverer,
		updater:    updater,
		firewall:   firewall,
		worker:     worker,
		shieldMgr:  shieldMgr,
		edgeFW:     edgeFW,
	}, nil
}

func runDaemon(args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	cfgPath := fs.String("c", defaultConfigPath, "path to config.yaml")
	debug := fs.Bool("debug", false, "enable debug logging")
	noTimestamp := fs.Bool("no-timestamp", false, "omit timestamp in logs (auto-enabled when stdout is not a TTY)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	logger := newLogger(os.Stdout, level, *noTimestamp)

	deps, err := buildDeps(*cfgPath, logger)
	if err != nil {
		return err
	}

	listener := ubus.NewListener(nil, logger)

	watcher := ipwatch.NewWatcher(
		deps.cfg,
		deps.discoverer,
		listener,
		func(ctx context.Context, snap ipwatch.Snapshot, force bool) error {
			return deps.updater.Sync(ctx, snap, cloudflare.SyncOptions{Force: force})
		},
		state.DefaultShieldLockPath,
		logger,
	)

	resolver := reconcile.NewDirectResolver(deps.cfg.Reconcile.Resolvers, 0)
	cfIPs := reconcile.NewCFProxyCatalog(deps.store, "")
	reconciler := reconcile.NewReconciler(
		deps.cfg,
		deps.store,
		resolver,
		cfIPs,
		deps.discoverer.Discover,
		deps.updater.Sync,
		state.DefaultShieldLockPath,
		logger,
	)

	var pppoeGuard *pppoeguard.Guard
	if deps.cfg.PPPoEGuard.Enabled {
		pppoeGuard = pppoeguard.NewGuard(
			deps.cfg,
			deps.ubusClient,
			listener,
			deps.pinger,
			deps.store,
			deps.notifier,
			logger,
		)
		// Reconstruct shieldMgr with redial hook so PPPoE Guard ignores intentional BRAS flush redials.
		deps.shieldMgr = ddos.NewShieldManager(
			deps.cfg,
			deps.ubusClient,
			deps.pinger,
			ddos.NewProcSysReader(),
			deps.firewall,
			deps.worker,
			deps.store,
			deps.notifier,
			func(ctx context.Context) (string, error) {
				ip, _, err := deps.discoverer.DiscoverIPv4(ctx)
				return ip, err
			},
			func(ctx context.Context) error {
				snap, err := deps.discoverer.Discover(ctx)
				if err != nil {
					return err
				}
				return deps.updater.Sync(ctx, snap, cloudflare.SyncOptions{Force: true})
			},
			state.DefaultShieldLockPath,
			logger,
			ddos.WithRedialHook(pppoeGuard.SetExternalRedialing),
		)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("starting cf-edge daemon",
		"node", deps.cfg.NodeName,
		"version", version,
		"reconcile", deps.cfg.Reconcile.Enabled,
		"pppoe_guard", deps.cfg.PPPoEGuard.Enabled,
		"ddos_shield", deps.cfg.DDoSShield.Enabled,
		"edge_firewall", deps.cfg.EdgeFirewall.Enabled,
		"auto_update", deps.cfg.AutoUpdate.Enabled,
	)

	var wg sync.WaitGroup
	start := func(name string, fn func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Debug("goroutine started", "module", name)
			fn(ctx)
			logger.Debug("goroutine stopped", "module", name)
		}()
	}

	start("ubus.Listener", listener.Run)
	start("ipwatch.Watcher", watcher.Run)
	if deps.cfg.Reconcile.Enabled {
		start("reconcile.Reconciler", reconciler.Run)
	}
	if pppoeGuard != nil {
		start("pppoeguard.Guard", pppoeGuard.Run)
	}
	if deps.cfg.DDoSShield.Enabled || state.IsShielded(state.DefaultShieldLockPath) {
		start("ddos.ShieldManager", deps.shieldMgr.Run)
	}
	if deps.cfg.EdgeFirewall.Enabled {
		deps.edgeFW.SetListener(listener)
		start("edgefw.Manager", deps.edgeFW.Run)
	}
	if deps.cfg.AutoUpdate.Enabled {
		autoUpd := newAutoUpdater(deps.cfg, deps.notifier, state.DefaultShieldLockPath, logger)
		start("autoupdate.Scheduler", autoUpd.Run)
	}

	<-ctx.Done()
	logger.Info("shutting down cf-edge daemon")
	wg.Wait()
	return nil
}
