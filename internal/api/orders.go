package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"vue-project-backend/internal/acme"
	"vue-project-backend/internal/config"
	"vue-project-backend/internal/store"
)

type orderService struct {
	cfg                config.Config
	orders             store.OrderStore
	users              store.UserStore
	servers            store.ServerStore
	sites              store.SiteStore
	upstreams          store.UpstreamServerStore
	siteListeningPorts store.SiteListeningPortStore
	l7Deps             siteL7Stores
	certIssuer         *acme.Issuer
	notifications      store.NotificationStore
	running            sync.Map
}

type orderPayload struct {
	UserID        int64              `json:"userId"`
	Purpose       string             `json:"purpose"`
	Period        string             `json:"period"`
	ParentOrderID *int64             `json:"parentOrderId"`
	Note          string             `json:"note"`
	Details       store.OrderDetails `json:"details"`
	Submit        bool               `json:"submit"`
}

type orderQuoteResponse struct {
	Items     []store.OrderItem `json:"items"`
	Total     float64           `json:"total"`
	Currency  string            `json:"currency"`
	Period    string            `json:"period"`
	CoTermEnd *time.Time        `json:"coTermEnd,omitempty"`
}

func registerOrderRoutes(mux *http.ServeMux, svc *orderService) {
	mux.HandleFunc("GET /api/v1/orders/catalog", svc.handleCatalog)
	mux.HandleFunc("POST /api/v1/orders/quote", svc.handleQuote)
	mux.HandleFunc("GET /api/v1/orders", svc.handleList)
	mux.HandleFunc("POST /api/v1/orders", svc.handleCreate)
	mux.HandleFunc("GET /api/v1/orders/{id}", svc.handleGet)
	mux.HandleFunc("PUT /api/v1/orders/{id}", svc.handleUpdate)
	mux.HandleFunc("POST /api/v1/orders/{id}/submit", svc.handleSubmit)
	mux.HandleFunc("POST /api/v1/orders/{id}/cancel", svc.handleCancel)
	mux.HandleFunc("POST /api/v1/orders/{id}/payment", requireAdmin(svc.handlePayment))
	mux.HandleFunc("POST /api/v1/orders/{id}/approve", requireAdmin(svc.handleApprove))
	mux.HandleFunc("POST /api/v1/orders/{id}/reject", requireAdmin(svc.handleReject))
	mux.HandleFunc("GET /api/v1/licenses", svc.handleLicenses)
	mux.HandleFunc("POST /api/v1/licenses/renew", svc.handleRenew)
	mux.HandleFunc("POST /api/v1/licenses/{id}/cancel", svc.handleLicenseCancel)
	mux.HandleFunc("POST /api/v1/licenses/{id}/resume", svc.handleLicenseResume)
	mux.HandleFunc("PUT /api/v1/admin/order-catalog/{code}", requireAdmin(svc.handleCatalogPrice))
	mux.HandleFunc("GET /api/v1/admin/server-kinds", requireAdmin(svc.handleServerKinds))
	mux.HandleFunc("PUT /api/v1/admin/server-kinds/{id}", requireAdmin(svc.handleSetServerKind))
}

func principalOf(r *http.Request) (store.User, bool) {
	principal, ok := AuthPrincipalFromContext(r.Context())
	if !ok || principal.UserID <= 0 {
		return store.User{}, false
	}
	return store.User{ID: principal.UserID, Name: principal.Name, Email: principal.Email, Role: principal.Role}, true
}

func isAdminUser(user store.User) bool {
	return strings.EqualFold(user.Role, "Admin")
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

// sanitizeOrder drops SSH secrets before an order leaves the API.
func sanitizeOrder(order store.Order) store.Order {
	edges := make([]store.OrderEdge, len(order.Details.Edges))
	for i, edge := range order.Details.Edges {
		edge.HasSSHPassword = edge.SSHPassword != "" || edge.HasSSHPassword
		edge.HasSSHKey = edge.SSHPrivateKey != "" || edge.HasSSHKey
		edge.SSHPassword, edge.SSHPrivateKey, edge.SSHKeyPassphrase = "", "", ""
		edges[i] = edge
	}
	order.Details.Edges = edges
	return order
}

func writeOrderError(w http.ResponseWriter, err error) {
	var he *httpAPIErr
	if errors.As(err, &he) {
		writeHTTPAPIError(w, he)
		return
	}
	if store.IsNotFound(err) {
		writeError(w, http.StatusNotFound, "order not found")
		return
	}
	log.Printf("[api] orders: %v", err)
	writeError(w, http.StatusInternalServerError, "order request failed")
}

// loadOrderFor returns the order when the caller owns it or is an Admin.
func (svc *orderService) loadOrderFor(r *http.Request) (store.Order, store.User, error) {
	user, ok := principalOf(r)
	if !ok {
		return store.Order{}, user, apiHTTPError(http.StatusUnauthorized, "authentication required")
	}
	id, ok := pathID(r)
	if !ok {
		return store.Order{}, user, apiHTTPError(http.StatusNotFound, "order not found")
	}
	order, err := svc.orders.Get(r.Context(), id)
	if err != nil {
		return store.Order{}, user, err
	}
	if order.UserID != user.ID && !isAdminUser(user) {
		return store.Order{}, user, apiHTTPError(http.StatusNotFound, "order not found")
	}
	return order, user, nil
}

func (svc *orderService) handleCatalog(w http.ResponseWriter, r *http.Request) {
	items, err := svc.orders.ListCatalog(r.Context())
	if err != nil {
		writeOrderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

// buildOrder turns a payload into a normalized, priced order for the given customer.
func (svc *orderService) buildOrder(ctx context.Context, customerID int64, payload orderPayload, base *store.Order) (store.Order, []store.License, error) {
	order := store.Order{UserID: customerID, Status: store.OrderStatusDraft, Currency: "USD"}
	if base != nil {
		order = *base
	}
	order.Purpose = strings.TrimSpace(payload.Purpose)
	order.Period = normalizeOrderPeriod(payload.Period)
	order.Note = strings.TrimSpace(payload.Note)
	order.ParentOrderID = payload.ParentOrderID
	switch order.Purpose {
	case store.OrderPurposeAddon:
		order.Kind = store.OrderKindAddon
	case store.OrderPurposeRenewal:
		order.Kind = store.OrderKindRenewal
	case store.OrderPurposeEdge, store.OrderPurposeEdgeSite, store.OrderPurposeSiteOwn, store.OrderPurposeSitePlatform:
		order.Kind = store.OrderKindNew
	default:
		return order, nil, apiHTTPError(http.StatusBadRequest, "purpose must be edge, site_own, site_platform, edge_site, addon, or renewal")
	}
	order.Details = normalizeOrderDetails(order.Purpose, payload.Details)
	if base != nil {
		mergeOrderSecrets(&order.Details, base.Details)
	}
	for i := range order.Details.Edges {
		edge := &order.Details.Edges[i]
		edge.HasSSHPassword = edge.SSHPassword != ""
		edge.HasSSHKey = edge.SSHPrivateKey != ""
	}
	licenses, err := svc.orders.ListLicenses(ctx, customerID)
	if err != nil {
		return order, nil, err
	}
	if order.Kind == store.OrderKindAddon {
		order.Details.CoTermEnd = coTermEnd(licenses, order.ParentOrderID, order.Period)
	}
	renewals := make([]store.License, 0)
	if len(order.Details.RenewLicenseIDs) > 0 {
		byID := make(map[int64]store.License, len(licenses))
		for _, license := range licenses {
			byID[license.ID] = license
		}
		for _, id := range order.Details.RenewLicenseIDs {
			license, ok := byID[id]
			if !ok || license.Status == store.LicenseStatusCancelled {
				return order, nil, apiHTTPError(http.StatusBadRequest, fmt.Sprintf("license #%d cannot be renewed", id))
			}
			renewals = append(renewals, license)
		}
	}
	catalog, err := svc.orders.ListCatalog(ctx)
	if err != nil {
		return order, nil, err
	}
	priceOrder(&order, catalog, renewals, time.Now().UTC())
	return order, licenses, nil
}

// coTermEnd aligns add-on licenses with the customer's existing licenses of the same period.
func coTermEnd(licenses []store.License, parentOrderID *int64, period string) *time.Time {
	var end *time.Time
	for _, license := range licenses {
		if license.Status == store.LicenseStatusCancelled || license.Status == store.LicenseStatusExpired {
			continue
		}
		if parentOrderID != nil && (license.OrderID == nil || *license.OrderID != *parentOrderID) {
			continue
		}
		if parentOrderID == nil && license.Period != period {
			continue
		}
		if !license.CurrentPeriodEnd.After(time.Now()) {
			continue
		}
		if end == nil || license.CurrentPeriodEnd.After(*end) {
			t := license.CurrentPeriodEnd
			end = &t
		}
	}
	return end
}

// mergeOrderSecrets keeps stored SSH secrets when a draft edit leaves them blank.
func mergeOrderSecrets(next *store.OrderDetails, prev store.OrderDetails) {
	for i := range next.Edges {
		if i >= len(prev.Edges) || prev.Edges[i].IP != next.Edges[i].IP {
			continue
		}
		edge, old := &next.Edges[i], prev.Edges[i]
		if edge.SSHPassword == "" {
			edge.SSHPassword = old.SSHPassword
		}
		if edge.SSHPrivateKey == "" {
			edge.SSHPrivateKey = old.SSHPrivateKey
			if edge.SSHKeyPassphrase == "" {
				edge.SSHKeyPassphrase = old.SSHKeyPassphrase
			}
		}
		if edge.ServerID == 0 {
			edge.ServerID = old.ServerID
		}
	}
}

func ownershipFromLicenses(licenses []store.License) orderOwnership {
	own := orderOwnership{l7ServerIDs: map[int64]bool{}, upgradeable: map[int64]bool{}}
	for _, license := range licenses {
		if license.Scope != store.LicenseScopeServer || license.Status == store.LicenseStatusCancelled || license.Status == store.LicenseStatusExpired {
			continue
		}
		switch license.Kind {
		case store.LicenseKindL7:
			own.l7ServerIDs[license.TargetID] = true
			own.upgradeable[license.TargetID] = true
		case store.LicenseKindUnified:
			own.l7ServerIDs[license.TargetID] = true
		}
	}
	return own
}

func (svc *orderService) existingDomains(ctx context.Context) (map[string]bool, error) {
	list, err := svc.sites.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(list))
	for _, site := range list {
		out[strings.ToLower(site.Domain)] = true
	}
	return out, nil
}

func (svc *orderService) customerFor(user store.User, payload orderPayload) int64 {
	if isAdminUser(user) && payload.UserID > 0 {
		return payload.UserID
	}
	return user.ID
}

func (svc *orderService) handleQuote(w http.ResponseWriter, r *http.Request) {
	user, ok := principalOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var payload orderPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	order, _, err := svc.buildOrder(r.Context(), svc.customerFor(user, payload), payload, nil)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, orderQuoteResponse{Items: order.Items, Total: order.Total, Currency: order.Currency, Period: order.Period, CoTermEnd: order.Details.CoTermEnd})
}

func (svc *orderService) handleList(w http.ResponseWriter, r *http.Request) {
	user, ok := principalOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	userID := user.ID
	if isAdminUser(user) && r.URL.Query().Get("scope") != "mine" {
		userID = 0
	}
	var statuses []string
	for _, status := range strings.Split(r.URL.Query().Get("status"), ",") {
		if status = strings.TrimSpace(status); status != "" {
			statuses = append(statuses, status)
		}
	}
	orders, err := svc.orders.List(r.Context(), userID, statuses)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	for i := range orders {
		orders[i] = sanitizeOrder(orders[i])
	}
	writeJSON(w, http.StatusOK, orders)
}

func (svc *orderService) handleGet(w http.ResponseWriter, r *http.Request) {
	order, _, err := svc.loadOrderFor(r)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sanitizeOrder(order))
}

func (svc *orderService) handleCreate(w http.ResponseWriter, r *http.Request) {
	user, ok := principalOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var payload orderPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	customerID := svc.customerFor(user, payload)
	if customerID != user.ID {
		if _, err := svc.users.FindByID(r.Context(), customerID); err != nil {
			writeError(w, http.StatusBadRequest, "customer account not found")
			return
		}
	}
	order, licenses, err := svc.buildOrder(r.Context(), customerID, payload, nil)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	if payload.Submit {
		if err := svc.validate(r.Context(), order, licenses); err != nil {
			writeOrderError(w, err)
			return
		}
	}
	order.CreatedBy = user.ID
	created, err := svc.orders.Create(r.Context(), order)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	if payload.Submit {
		if created, err = svc.submit(r.Context(), created); err != nil {
			writeOrderError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusCreated, sanitizeOrder(created))
}

func (svc *orderService) handleUpdate(w http.ResponseWriter, r *http.Request) {
	existing, user, err := svc.loadOrderFor(r)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	if existing.Status != store.OrderStatusDraft {
		writeError(w, http.StatusConflict, "only draft orders can be edited")
		return
	}
	var payload orderPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	order, licenses, err := svc.buildOrder(r.Context(), existing.UserID, payload, &existing)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	if payload.Submit {
		if err := svc.validate(r.Context(), order, licenses); err != nil {
			writeOrderError(w, err)
			return
		}
	}
	if err := svc.orders.Save(r.Context(), order); err != nil {
		writeOrderError(w, err)
		return
	}
	saved, err := svc.orders.Get(r.Context(), order.ID)
	if err == nil && payload.Submit {
		saved, err = svc.submit(r.Context(), saved)
	}
	if err != nil {
		writeOrderError(w, err)
		return
	}
	_ = user
	writeJSON(w, http.StatusOK, sanitizeOrder(saved))
}

func (svc *orderService) validate(ctx context.Context, order store.Order, licenses []store.License) error {
	domains, err := svc.existingDomains(ctx)
	if err != nil {
		return err
	}
	if err := validateOrderForSubmit(order, ownershipFromLicenses(licenses), domains); err != nil {
		return apiHTTPError(http.StatusBadRequest, err.Error())
	}
	if order.Total <= 0 && order.Kind != store.OrderKindRenewal && len(order.Items) == 0 {
		return apiHTTPError(http.StatusBadRequest, "the order is empty")
	}
	return nil
}

func (svc *orderService) handleSubmit(w http.ResponseWriter, r *http.Request) {
	order, _, err := svc.loadOrderFor(r)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	if order.Status != store.OrderStatusDraft {
		writeError(w, http.StatusConflict, "only draft orders can be submitted")
		return
	}
	payload := orderPayload{Purpose: order.Purpose, Period: order.Period, ParentOrderID: order.ParentOrderID, Note: order.Note, Details: order.Details}
	rebuilt, licenses, err := svc.buildOrder(r.Context(), order.UserID, payload, &order)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	if err := svc.validate(r.Context(), rebuilt, licenses); err != nil {
		writeOrderError(w, err)
		return
	}
	submitted, err := svc.submit(r.Context(), rebuilt)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sanitizeOrder(submitted))
}

// submit locks the quote, assigns an invoice number and waits for payment.
func (svc *orderService) submit(ctx context.Context, order store.Order) (store.Order, error) {
	now := time.Now().UTC()
	order.Status = store.OrderStatusAwaitingPayment
	order.SubmittedAt = &now
	order.InvoiceNo = fmt.Sprintf("INV-%d-%05d", now.Year(), order.ID)
	if err := svc.orders.Save(ctx, order); err != nil {
		return order, err
	}
	if order.Kind == store.OrderKindRenewal {
		for _, id := range order.Details.RenewLicenseIDs {
			if license, err := svc.orders.GetLicense(ctx, id); err == nil {
				license.RenewalOrderID = &order.ID
				_, _ = svc.orders.SaveLicense(ctx, license)
			}
		}
	}
	if order.Total <= 0 {
		return svc.markPaid(ctx, order)
	}
	svc.notify(ctx, order.UserID, order, "submitted", "info",
		fmt.Sprintf("Order #%d submitted", order.ID),
		fmt.Sprintf("Invoice %s for %s %.2f is awaiting payment.", order.InvoiceNo, order.Currency, order.Total))
	svc.notifyAdmins(ctx, order, "submitted",
		fmt.Sprintf("New order #%d awaiting payment", order.ID),
		fmt.Sprintf("%s ordered %s for %s %.2f.", firstNonEmpty(order.UserName, order.UserEmail, "A customer"), orderPurposeLabel(order.Purpose), order.Currency, order.Total))
	return svc.orders.Get(ctx, order.ID)
}

func (svc *orderService) handleCancel(w http.ResponseWriter, r *http.Request) {
	order, user, err := svc.loadOrderFor(r)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	if order.Status != store.OrderStatusDraft && order.Status != store.OrderStatusAwaitingPayment {
		writeError(w, http.StatusConflict, "only draft or unpaid orders can be cancelled")
		return
	}
	if order.PaidTotal > 0 && !isAdminUser(user) {
		writeError(w, http.StatusConflict, "a payment was recorded for this order; contact support to cancel it")
		return
	}
	cancelled, err := svc.cancel(r.Context(), order, "")
	if err != nil {
		writeOrderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sanitizeOrder(cancelled))
}

func (svc *orderService) cancel(ctx context.Context, order store.Order, note string) (store.Order, error) {
	now := time.Now().UTC()
	order.Status = store.OrderStatusCancelled
	order.CancelledAt = &now
	if note != "" {
		order.Note = strings.TrimSpace(order.Note + "\n" + note)
	}
	if err := svc.orders.Save(ctx, order); err != nil {
		return order, err
	}
	for _, id := range order.Details.RenewLicenseIDs {
		if license, err := svc.orders.GetLicense(ctx, id); err == nil && license.RenewalOrderID != nil && *license.RenewalOrderID == order.ID {
			license.RenewalOrderID = nil
			_, _ = svc.orders.SaveLicense(ctx, license)
		}
	}
	return svc.orders.Get(ctx, order.ID)
}

type orderPaymentPayload struct {
	Amount    float64 `json:"amount"`
	Reference string  `json:"reference"`
	PaidOn    string  `json:"paidOn"`
}

func (svc *orderService) handlePayment(w http.ResponseWriter, r *http.Request) {
	order, user, err := svc.loadOrderFor(r)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	if order.Status != store.OrderStatusAwaitingPayment {
		writeError(w, http.StatusConflict, "this order is not awaiting payment")
		return
	}
	var payload orderPaymentPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if payload.Amount <= 0 {
		writeError(w, http.StatusBadRequest, "amount must be greater than zero")
		return
	}
	paidOn := time.Now().UTC()
	if strings.TrimSpace(payload.PaidOn) != "" {
		parsed, err := time.Parse("2006-01-02", strings.TrimSpace(payload.PaidOn))
		if err != nil {
			writeError(w, http.StatusBadRequest, "paidOn must be YYYY-MM-DD")
			return
		}
		paidOn = parsed
	}
	if err := svc.orders.AddPayment(r.Context(), order.ID, store.OrderPayment{
		Amount: roundCents(payload.Amount), Reference: strings.TrimSpace(payload.Reference), PaidOn: paidOn, RecordedBy: user.ID,
	}); err != nil {
		writeOrderError(w, err)
		return
	}
	order, err = svc.orders.Get(r.Context(), order.ID)
	if err == nil && order.PaidTotal+0.005 >= order.Total {
		order, err = svc.markPaid(r.Context(), order)
	}
	if err != nil {
		writeOrderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sanitizeOrder(order))
}

// markPaid moves a fully paid order on: renewals apply immediately, everything
// else waits for the operator to approve setup.
func (svc *orderService) markPaid(ctx context.Context, order store.Order) (store.Order, error) {
	now := time.Now().UTC()
	order.PaidAt = &now
	if order.Kind == store.OrderKindRenewal {
		return svc.applyRenewal(ctx, order)
	}
	order.Status = store.OrderStatusAwaitingSetup
	if err := svc.orders.Save(ctx, order); err != nil {
		return order, err
	}
	svc.notify(ctx, order.UserID, order, "paid", "info",
		fmt.Sprintf("Payment received for order #%d", order.ID),
		"Your order is paid and queued for setup.")
	return svc.orders.Get(ctx, order.ID)
}

type orderApprovePayload struct {
	Edges []struct {
		Index       int    `json:"index"`
		VersionUUID string `json:"versionUuid"`
	} `json:"edges"`
	PlatformServerIDs []int64 `json:"platformServerIds"`
}

func (svc *orderService) handleApprove(w http.ResponseWriter, r *http.Request) {
	order, _, err := svc.loadOrderFor(r)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	retry := order.Status == store.OrderStatusProvisioning && order.Error != ""
	if order.Status != store.OrderStatusAwaitingSetup && !retry {
		writeError(w, http.StatusConflict, "this order is not waiting for setup")
		return
	}
	if _, busy := svc.running.Load(order.ID); busy {
		writeError(w, http.StatusConflict, "setup is already running for this order")
		return
	}
	var payload orderApprovePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	for _, edge := range payload.Edges {
		if edge.Index >= 0 && edge.Index < len(order.Details.Edges) && strings.TrimSpace(edge.VersionUUID) != "" {
			order.Details.Edges[edge.Index].VersionUUID = strings.TrimSpace(edge.VersionUUID)
		}
	}
	for i, edge := range order.Details.Edges {
		if edge.ServerID == 0 && edge.VersionUUID == "" {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("choose a Dorian version for edge %d (%s)", i+1, edge.Name))
			return
		}
	}
	needsPlatform := false
	for _, site := range order.Details.Sites {
		if site.Placement == "platform" && site.SiteID == 0 {
			needsPlatform = true
		}
	}
	if needsPlatform {
		ids := uniquePositiveIDs(payload.PlatformServerIDs)
		if len(ids) == 0 {
			if ids, err = svc.orders.PlatformServerIDs(r.Context()); err != nil {
				writeOrderError(w, err)
				return
			}
		}
		if len(ids) == 0 {
			writeError(w, http.StatusBadRequest, "no platform edges are configured; mark Dorian edges as platform first")
			return
		}
		order.Details.PlatformServerIDs = ids
	}
	now := time.Now().UTC()
	order.Status = store.OrderStatusProvisioning
	order.Error = ""
	if order.ApprovedAt == nil {
		order.ApprovedAt = &now
	}
	if err := svc.orders.Save(r.Context(), order); err != nil {
		writeOrderError(w, err)
		return
	}
	svc.startProvisioning(order.ID)
	saved, err := svc.orders.Get(r.Context(), order.ID)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, sanitizeOrder(saved))
}

type orderRejectPayload struct {
	Note string `json:"note"`
}

func (svc *orderService) handleReject(w http.ResponseWriter, r *http.Request) {
	order, _, err := svc.loadOrderFor(r)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	switch order.Status {
	case store.OrderStatusAwaitingPayment, store.OrderStatusAwaitingSetup:
	case store.OrderStatusProvisioning:
		if order.Error == "" {
			writeError(w, http.StatusConflict, "setup is running; wait for it to finish or fail")
			return
		}
	default:
		writeError(w, http.StatusConflict, "this order can no longer be rejected")
		return
	}
	var payload orderRejectPayload
	_ = json.NewDecoder(r.Body).Decode(&payload)
	note := strings.TrimSpace(payload.Note)
	if note == "" {
		note = "Rejected by operator."
	} else {
		note = "Rejected: " + note
	}
	cancelled, err := svc.cancel(r.Context(), order, note)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	svc.notify(r.Context(), order.UserID, cancelled, "rejected", "warning", fmt.Sprintf("Order #%d was rejected", order.ID), note)
	writeJSON(w, http.StatusOK, sanitizeOrder(cancelled))
}

func (svc *orderService) handleLicenses(w http.ResponseWriter, r *http.Request) {
	user, ok := principalOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	userID := user.ID
	if isAdminUser(user) && r.URL.Query().Get("scope") != "mine" {
		userID = 0
	}
	licenses, err := svc.orders.ListLicenses(r.Context(), userID)
	if err != nil {
		writeOrderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, licenses)
}

type renewPayload struct {
	LicenseIDs []int64 `json:"licenseIds"`
	Period     string  `json:"period"`
}

func (svc *orderService) handleRenew(w http.ResponseWriter, r *http.Request) {
	user, ok := principalOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var payload renewPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	ids := uniquePositiveIDs(payload.LicenseIDs)
	if len(ids) == 0 {
		writeError(w, http.StatusBadRequest, "select the licenses to renew")
		return
	}
	first, err := svc.orders.GetLicense(r.Context(), ids[0])
	if err != nil {
		writeOrderError(w, err)
		return
	}
	customerID := first.UserID
	if !isAdminUser(user) && customerID != user.ID {
		writeError(w, http.StatusNotFound, "license not found")
		return
	}
	for _, id := range ids {
		license, err := svc.orders.GetLicense(r.Context(), id)
		if err != nil || license.UserID != customerID {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("license #%d cannot be renewed in this order", id))
			return
		}
		if license.RenewalOrderID != nil {
			writeError(w, http.StatusConflict, fmt.Sprintf("license #%d already has renewal order #%d", id, *license.RenewalOrderID))
			return
		}
		if license.Status == store.LicenseStatusCancelled && !isAdminUser(user) {
			writeError(w, http.StatusConflict, fmt.Sprintf("license #%d is cancelled; place a new order to protect it again", id))
			return
		}
	}
	period := payload.Period
	if strings.TrimSpace(period) == "" {
		period = first.Period
	}
	order, err := svc.createRenewalOrder(r.Context(), customerID, user.ID, ids, normalizeOrderPeriod(period))
	if err != nil {
		writeOrderError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, sanitizeOrder(order))
}

func (svc *orderService) createRenewalOrder(ctx context.Context, customerID, createdBy int64, licenseIDs []int64, period string) (store.Order, error) {
	payload := orderPayload{Purpose: store.OrderPurposeRenewal, Period: period, Details: store.OrderDetails{RenewLicenseIDs: licenseIDs}}
	order, _, err := svc.buildOrder(ctx, customerID, payload, nil)
	if err != nil {
		return order, err
	}
	order.CreatedBy = createdBy
	created, err := svc.orders.Create(ctx, order)
	if err != nil {
		return created, err
	}
	return svc.submit(ctx, created)
}

type catalogPricePayload struct {
	MonthlyPrice float64 `json:"monthlyPrice"`
	AnnualPrice  float64 `json:"annualPrice"`
}

func (svc *orderService) handleCatalogPrice(w http.ResponseWriter, r *http.Request) {
	var payload catalogPricePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if payload.MonthlyPrice < 0 || payload.AnnualPrice < 0 {
		writeError(w, http.StatusBadRequest, "prices cannot be negative")
		return
	}
	if err := svc.orders.UpdateCatalogPrice(r.Context(), r.PathValue("code"), roundCents(payload.MonthlyPrice), roundCents(payload.AnnualPrice)); err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "catalog item not found")
			return
		}
		writeOrderError(w, err)
		return
	}
	svc.handleCatalog(w, r)
}

func (svc *orderService) handleServerKinds(w http.ResponseWriter, r *http.Request) {
	list, err := svc.orders.ListServerKinds(r.Context())
	if err != nil {
		writeOrderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (svc *orderService) handleSetServerKind(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	var payload struct {
		Kind string `json:"kind"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := svc.orders.SetServerKind(r.Context(), id, strings.TrimSpace(payload.Kind)); err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "server not found")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	svc.handleServerKinds(w, r)
}

func orderPurposeLabel(purpose string) string {
	switch purpose {
	case store.OrderPurposeEdge:
		return "edge protection"
	case store.OrderPurposeSiteOwn:
		return "site protection on own edge"
	case store.OrderPurposeSitePlatform:
		return "site protection on platform edges"
	case store.OrderPurposeEdgeSite:
		return "edge + site protection"
	case store.OrderPurposeAddon:
		return "an add-on"
	case store.OrderPurposeRenewal:
		return "a renewal"
	}
	return purpose
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (svc *orderService) notify(ctx context.Context, userID int64, order store.Order, event, severity, title, body string) {
	if svc.notifications == nil || userID <= 0 {
		return
	}
	if _, err := svc.notifications.Upsert(ctx, userID, store.NotificationInput{
		EventKey: fmt.Sprintf("order-%d-%s", order.ID, event),
		Kind:     "order",
		Severity: severity,
		Title:    title,
		Body:     body,
		Status:   order.Status,
		At:       time.Now().UTC(),
	}); err != nil {
		log.Printf("[api] orders: notify user=%d order=%d: %v", userID, order.ID, err)
	}
}

func (svc *orderService) notifyAdmins(ctx context.Context, order store.Order, event, title, body string) {
	users, err := svc.users.List(ctx)
	if err != nil {
		return
	}
	for _, user := range users {
		if isAdminUser(user) && user.ID != order.UserID {
			svc.notify(ctx, user.ID, order, "admin-"+event, "info", title, body)
		}
	}
}
