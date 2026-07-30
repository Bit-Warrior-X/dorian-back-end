package api

import (
	"context"
	"fmt"

	"vue-project-backend/internal/store"
)

func siteEdgeServerIDs(ctx context.Context, sites store.SiteStore, siteID int64) ([]int64, error) {
	if siteID == 0 {
		return nil, fmt.Errorf("invalid site id")
	}
	site, err := sites.Get(ctx, siteID)
	if err != nil {
		return nil, err
	}
	return uniqueInt64Slice(site.ServerIDs), nil
}

func uniqueInt64Slice(values []int64) []int64 {
	seen := map[int64]struct{}{}
	out := make([]int64, 0, len(values))
	for _, value := range values {
		if value == 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
