package api

import (
	"context"
	"log"
	"strings"
	"time"

	"vue-project-backend/internal/remotesvc"
	"vue-project-backend/internal/store"
)

const remoteRuntimeProbeTimeout = 120 * time.Second

func probeRemoteRuntimeStatuses(ctx context.Context, ip, user, pass, port string) remotesvc.RuntimeStatuses {
	probeCtx, cancel := context.WithTimeout(ctx, remoteRuntimeProbeTimeout)
	defer cancel()

	statuses, err := remotesvc.ProbeDorianServices(probeCtx, remotesvc.SSHTarget{
		Host:     ip,
		User:     user,
		Password: pass,
		Port:     port,
	})
	if err != nil {
		log.Printf("[api] remote runtime probe failed ssh_target=%s@%s:%s: %v",
			strings.TrimSpace(user),
			strings.TrimSpace(ip),
			strings.TrimSpace(port),
			err,
		)
		if strings.TrimSpace(statuses.AngelosReason) == "" &&
			strings.TrimSpace(statuses.L4Reason) == "" &&
			strings.TrimSpace(statuses.L7Reason) == "" {
			return remotesvc.RuntimeStatuses{
				Angelos:       "unknown",
				L4:            "unknown",
				L7:            "unknown",
				AngelosReason: "Probe failed: " + err.Error(),
				L4Reason:      "Probe failed: " + err.Error(),
				L7Reason:      "Probe failed: " + err.Error(),
			}
		}
	}
	return statuses
}

func applyRuntimeStatusesToView(view store.ServerView, statuses remotesvc.RuntimeStatuses) store.ServerView {
	if v := strings.TrimSpace(statuses.Angelos); v != "" {
		view.ServiceStatus = v
	}
	if v := strings.TrimSpace(statuses.L4); v != "" {
		view.L4Status = v
	}
	if v := strings.TrimSpace(statuses.L7); v != "" {
		view.L7Status = v
	}
	view.ServiceStatusReason = strings.TrimSpace(statuses.AngelosReason)
	view.L4StatusReason = strings.TrimSpace(statuses.L4Reason)
	view.L7StatusReason = strings.TrimSpace(statuses.L7Reason)
	return view
}
