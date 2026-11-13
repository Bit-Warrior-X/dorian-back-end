package worker

import (
	"context"
	"log"
	"sync"
	"time"

	"vue-project-backend/internal/remotesvc"
	"vue-project-backend/internal/store"
)

const (
	hostMetricsSampleInterval = 60 * time.Second
	hostMetricsProbeTimeout   = 20 * time.Second
	hostMetricsPruneEvery     = 6 * time.Hour
	hostMetricsRetention      = 14 * 24 * time.Hour
	hostMetricsMaxParallel    = 4
)

// StartHostMetricsSampler probes CPU/RAM on edges that currently have an active
// L4 or L7 attack so Attack Console can show host load at the traffic peak.
func StartHostMetricsSampler(
	ctx context.Context,
	servers store.ServerStore,
	samples store.HostMetricsSampleStore,
) {
	if servers == nil || samples == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(hostMetricsSampleInterval)
		defer ticker.Stop()
		pruneTicker := time.NewTicker(hostMetricsPruneEvery)
		defer pruneTicker.Stop()

		runOnce := func() {
			sampleUnderAttackHosts(ctx, servers, samples)
		}
		runOnce()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runOnce()
			case <-pruneTicker.C:
				if n, err := samples.PruneOlderThan(ctx, hostMetricsRetention); err != nil {
					log.Printf("host metrics prune: %v", err)
				} else if n > 0 {
					log.Printf("host metrics prune: removed %d old samples", n)
				}
			}
		}
	}()
}

// SampleServerHostMetrics probes one edge and upserts a minute sample.
func SampleServerHostMetrics(
	ctx context.Context,
	servers store.ServerStore,
	samples store.HostMetricsSampleStore,
	serverID int64,
) {
	if servers == nil || samples == nil || serverID <= 0 {
		return
	}
	view, err := servers.GetView(ctx, serverID)
	if err != nil {
		return
	}
	probeCtx, cancel := context.WithTimeout(ctx, hostMetricsProbeTimeout)
	defer cancel()
	metrics, err := remotesvc.ProbeHostMetrics(probeCtx, remotesvc.SSHTarget{
		Host:          view.IP,
		User:          view.SSHUser,
		Password:      view.SSHPassword,
		Port:          view.SSHPort,
		PrivateKey:    view.SSHPrivateKey,
		KeyPassphrase: view.SSHKeyPassphrase,
	})
	if err != nil {
		log.Printf("host metrics sample server=%d: %v", serverID, err)
		return
	}
	_ = samples.Upsert(ctx, store.HostMetricsSample{
		ServerID:         serverID,
		BucketTS:         time.Now().UTC(),
		CPUPercent:       metrics.CPUPercent,
		MemoryUsedBytes:  metrics.MemoryUsedBytes,
		MemoryTotalBytes: metrics.MemoryTotalBytes,
	})
}

func sampleUnderAttackHosts(
	ctx context.Context,
	servers store.ServerStore,
	samples store.HostMetricsSampleStore,
) {
	ids, err := samples.ListUnderAttackServerIDs(ctx)
	if err != nil {
		log.Printf("host metrics list under attack: %v", err)
		return
	}
	if len(ids) == 0 {
		return
	}

	sem := make(chan struct{}, hostMetricsMaxParallel)
	var wg sync.WaitGroup
	for _, id := range ids {
		serverID := id
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			SampleServerHostMetrics(ctx, servers, samples, serverID)
		}()
	}
	wg.Wait()
}
