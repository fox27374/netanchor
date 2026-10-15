package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// pushPage is the data for templates/push.html.
type pushPage struct {
	Defs       []CertDefinition
	NeedPass   map[string]bool // definition id: its CA key is encrypted and not unlocked
	Unlocked   map[string]bool // definition id: its encrypted CA is the unlocked SCEP CA
	Devices    []pushDeviceRow
	Definition string // selected definition id
	Username   string // echoed; never the password or CA passphrase
	NeedCreds  bool   // a listed device has no stored credentials, so the form asks for them
	Results    []devicePushResult
	Outcome    string // summary after a push
	Class      string // alert class for Outcome: ok, warn or err
	CSRF       string
}

// pushDeviceRow is one device in the selection list.
type pushDeviceRow struct {
	ID, Name, Site, Address string
	Pinned                  bool
	Tags                    string // comma separated, for the client-side filter
	Stored, Selected        bool
}

// devicePushResult is one row of the results panel.
type devicePushResult struct {
	Device  string
	Status  string // ok, skipped, unverified or failed
	Class   string // alert class: ok, warn or err
	Steps   []gnoiStep
	Outcome string
}

// handlePush is the admin page that pushes one certificate definition to one or
// more devices.
func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", http.StatusForbidden)
		return
	}
	deviceHeaders(w)
	d := s.base(r, "Push certificates to devices", "push")
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	page := pushPage{
		Definition: r.Form.Get("definition"), Username: strings.TrimSpace(r.Form.Get("username")),
	}
	if r.Method == http.MethodPost {
		if !s.backupCSRF(r) {
			http.Error(w, "invalid origin or CSRF token; reload the form", http.StatusForbidden)
			return
		}
		admin := d.Username
		if admin == "" {
			admin = "(auth disabled)"
		}
		page.Results, page.Outcome, page.Class = s.pushFromForm(w, r, admin)
		if flash := pushToast(page.Results); flash != nil {
			// Nothing failed: a toast is enough, the per-device steps are in the log.
			d.Flash, page.Results, page.Outcome = flash, nil, ""
		} else {
			page.Results = pushProblems(page.Results)
		}
	}
	defs, err := s.store.ListDefinitions()
	if err != nil {
		d.Error = err.Error()
	}
	devs, err := s.store.ListDevices()
	if err != nil {
		d.Error = err.Error()
	}
	selected := map[string]bool{}
	for _, id := range r.Form["device"] {
		selected[id] = true
	}
	for _, dev := range devs {
		page.Devices = append(page.Devices, pushDeviceRow{
			ID: dev.ID, Name: dev.Name, Site: dev.Site, Address: net.JoinHostPort(dev.ManagementIP, strconv.Itoa(dev.Port)),
			Pinned: dev.Pin != "", Tags: strings.Join(dev.Tags, ", "), Stored: dev.Credentials != nil, Selected: selected[dev.ID],
		})
		if dev.Credentials == nil {
			page.NeedCreds = true
		}
	}
	page.Defs, page.NeedPass, page.Unlocked = defs, map[string]bool{}, map[string]bool{}
	enc := map[string]bool{}
	for _, ca := range s.getIssueCAs() {
		enc[ca.CAID] = ca.KeyEnc
	}
	for _, def := range defs {
		if enc[def.CAID] {
			_, unlocked := s.scep.unlockedPassphrase(def.CAID)
			page.NeedPass[def.ID], page.Unlocked[def.ID] = !unlocked, unlocked
		}
	}
	page.CSRF = s.backupToken(r)
	d.Data = page
	s.render(w, "push", d)
}

// pushFromForm validates the posted selection and pushes the definition to each
// device in turn. Validation errors return no results.
func (s *Server) pushFromForm(w http.ResponseWriter, r *http.Request, admin string) ([]devicePushResult, string, string) {
	fail := func(msg string) ([]devicePushResult, string, string) { return nil, msg, "err" }
	def, ok, err := s.store.GetDefinition(r.PostForm.Get("definition"))
	if err != nil {
		return fail(err.Error())
	}
	if !ok {
		return fail("select a device certificate definition")
	}
	tmpl, ok := s.store.GetTemplate(def.Profile)
	if !ok {
		return fail("the definition's certificate profile no longer exists")
	}
	ids := r.PostForm["device"]
	if len(ids) == 0 {
		return fail("select at least one device")
	}
	devs := make([]Device, 0, len(ids))
	for _, id := range ids {
		dev, ok, err := s.store.GetDevice(id)
		if err != nil {
			return fail(err.Error())
		}
		if !ok {
			return fail("a selected device no longer exists; reload the page")
		}
		devs = append(devs, dev)
	}
	// Each device may take gnoiPushTimeout, so the response write deadline has to cover all of them.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Duration(len(devs))*gnoiPushTimeout + time.Minute))
	posted := deviceCreds{Username: strings.TrimSpace(r.PostForm.Get("username")), Password: r.PostForm.Get("password")}
	caPass := r.PostForm.Get("ca_passphrase")
	if p, ok := s.scep.unlockedPassphrase(def.CAID); ok && caPass == "" {
		caPass = p
	}
	results := pushDefinitionToDevices(r.Context(), s.store, s.gnoiAllow, def, tmpl, devs, posted, caPass, admin)
	outcome, class := pushSummary(results)
	return results, outcome, class
}

// pushDefinitionToDevices pushes def to each device, one at a time. A failure
// does not stop the rest. posted credentials are used only for devices without
// stored ones. The CA passphrase is held in memory for this call only.
func pushDefinitionToDevices(ctx context.Context, st *Store, allow []*net.IPNet, def CertDefinition, tmpl CertTemplate, devs []Device, posted deviceCreds, caPass, admin string) []devicePushResult {
	out := make([]devicePushResult, 0, len(devs))
	for _, dev := range devs {
		out = append(out, pushOneDevice(ctx, st, allow, def, tmpl, dev, posted, caPass, admin))
	}
	return out
}

// pushOneDevice builds the request from the device and definition and runs one push.
func pushOneDevice(ctx context.Context, st *Store, allow []*net.IPNet, def CertDefinition, tmpl CertTemplate, dev Device, posted deviceCreds, caPass, admin string) devicePushResult {
	res := devicePushResult{Device: dev.Name}
	fail := func(msg string) devicePushResult {
		res.Status, res.Class, res.Outcome = "failed", "err", msg
		return res
	}
	creds := posted
	if dev.Credentials != nil {
		c, err := st.openCredentials(dev.Credentials)
		if err != nil {
			return fail(err.Error())
		}
		creds = c
	}
	if creds.Username == "" || creds.Password == "" {
		return fail("no credentials: enter a username and password on this page")
	}

	target := net.JoinHostPort(dev.ManagementIP, strconv.Itoa(dev.Port))
	cn, dnsNames, ips, err := definitionSubject(def, dev)
	if err != nil {
		return fail(err.Error())
	}
	req := gnoiPushRequest{
		Target: target, Username: creds.Username, Password: creds.Password,
		CAID: def.CAID, Fingerprint: dev.Pin, CAPassphrase: caPass,
		Template: tmpl, CommonName: cn, Country: def.Country, State: def.State, City: def.City, Organization: def.Organization, OU: def.OU,
		DNSNames: dnsNames, IPs: ips, CertID: def.CertID, ValidDays: def.ValidDays, Admin: admin,
		Device: dev.Name,
	}

	pushCtx, cancel := context.WithTimeout(ctx, gnoiPushTimeout)
	steps, der, err := gnoiPush(pushCtx, st, allow, req)
	cancel()
	res.Steps = steps
	switch {
	case err == nil:
		res.Status, res.Class = "ok", "ok"
		res.Outcome = "Installed and verified as certificate " + def.CertID + ". " + afterInstall(ctx, st, allow, dev, creds, der, target)
	case errors.Is(err, errGNOIExists):
		res.Status, res.Class, res.Outcome = "skipped", "warn", err.Error()
	case errors.Is(err, errGNOIUnverified):
		res.Status, res.Class, res.Outcome = "unverified", "warn", err.Error()
	default:
		return fail(err.Error())
	}
	return res
}

// afterInstall re-pins a fingerprint device if its gRPC server now presents the
// certificate just installed. Not every device rebinds, so the pin follows what
// the port actually serves. Then it refreshes the device snapshot. It returns a
// note for the results panel.
func afterInstall(ctx context.Context, st *Store, allow []*net.IPNet, dev Device, creds deviceCreds, der []byte, target string) string {
	note := ""
	served, err := gnoiServedAfterInstall(ctx, allow, target, der)
	switch {
	case err != nil:
		return "Could not read the served certificate, pin kept: " + err.Error() + "."
	case bytes.Equal(served, der):
		sum := sha256.Sum256(der)
		pin := hexColons(sum[:])
		if err := st.UpdateDevice(dev.ID, func(d *Device) { d.Pin, d.PinAddress = pin, target }); err != nil {
			return "Could not save the new pin: " + err.Error() + "."
		}
		dev.Pin = pin
		note = "The gRPC server now uses the new certificate; pin updated. "
	default:
		note = "The gRPC server still presents its previous certificate; pin kept. "
	}
	snapCtx, cancel := context.WithTimeout(ctx, gnoiPushTimeout)
	defer cancel()
	rep, _, err := gnoiInspect(snapCtx, st, allow, dev, creds, true, "push")
	if err != nil {
		return note + "Certificates not refreshed: " + err.Error() + "."
	}
	snap := &DeviceSnapshot{Taken: time.Now().UTC(), Certs: rep.Certs, Served: rep.Served}
	if err := st.UpdateDevice(dev.ID, func(d *Device) { d.Snapshot = snap }); err != nil {
		return note + "Could not save the snapshot: " + err.Error() + "."
	}
	return note + "Certificates refreshed."
}

// gnoiServedAfterInstall returns the certificate the gRPC port presents, giving the
// device a short while to rebind to newDER.
func gnoiServedAfterInstall(ctx context.Context, allow []*net.IPNet, target string, newDER []byte) ([]byte, error) {
	var served []byte
	var err error
	for i := 0; i < gnoiRebindTries; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return served, err
			case <-time.After(gnoiRebindWait):
			}
		}
		served, err = gnoiServedCert(ctx, allow, target)
		if err == nil && bytes.Equal(served, newDER) {
			return served, nil
		}
	}
	return served, err
}

// pushSummary counts the outcomes and picks the worst alert class.
func pushSummary(results []devicePushResult) (string, string) {
	n := map[string]int{}
	class := "ok"
	for _, res := range results {
		n[res.Status]++
		switch {
		case res.Class == "err":
			class = "err"
		case res.Class == "warn" && class == "ok":
			class = "warn"
		}
	}
	return fmt.Sprintf("%d installed, %d skipped, %d unverified, %d failed.", n["ok"], n["skipped"], n["unverified"], n["failed"]), class
}

// pushToast summarises a push in which every device installed or was skipped as
// already installed. It returns nil when a device failed or could not be verified.
func pushToast(results []devicePushResult) *caFlash {
	if len(results) == 0 {
		return nil
	}
	installed := 0
	var skipped []string
	for _, res := range results {
		switch res.Status {
		case "ok":
			installed++
		case "skipped":
			skipped = append(skipped, res.Device)
		default:
			return nil
		}
	}
	f := &caFlash{Title: "Nothing pushed", Body: "Installed and verified on every selected device."}
	if installed > 0 {
		noun := "devices"
		if installed == 1 {
			noun = "device"
		}
		f.Title = fmt.Sprintf("Successfully pushed to %d %s", installed, noun)
	}
	if len(skipped) > 0 {
		f.Body = "Already installed, skipped: " + strings.Join(skipped, ", ") + "."
	}
	return f
}

// pushProblems keeps the devices that did not install cleanly; the summary still counts all.
func pushProblems(results []devicePushResult) []devicePushResult {
	var out []devicePushResult
	for _, res := range results {
		if res.Status != "ok" {
			out = append(out, res)
		}
	}
	return out
}

// sanitizeCertID turns a common name into a default certificate id: ASCII
// letters, digits, '.', '-' and '_' only, at most 64 characters.
func sanitizeCertID(cn string) string {
	var b strings.Builder
	for _, c := range cn {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-.")
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}
