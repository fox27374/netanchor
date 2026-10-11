package main

import (
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
	Defs         []CertDefinition
	Devices      []pushDeviceRow
	Site, Tag    string
	Definition   string // selected definition id
	Username     string // echoed; never the password or CA passphrase
	NeedCreds    bool   // a listed device has no stored credentials, so the form asks for them
	KeyAvailable bool
	Results      []devicePushResult
	Outcome      string // summary after a push
	Class        string // alert class for Outcome: ok, warn or err
	CSRF         string
}

// pushDeviceRow is one device in the selection list.
type pushDeviceRow struct {
	ID, Name, Site, Address, Verify string
	Stored, Selected                bool
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
		Site: strings.TrimSpace(r.Form.Get("site")), Tag: strings.TrimSpace(r.Form.Get("tag")),
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
		if !pushMatches(dev, page.Site, page.Tag) {
			continue
		}
		page.Devices = append(page.Devices, pushDeviceRow{
			ID: dev.ID, Name: dev.Name, Site: dev.Site, Address: net.JoinHostPort(dev.ManagementIP, strconv.Itoa(dev.Port)),
			Verify: dev.Verify, Stored: dev.Credentials != nil, Selected: selected[dev.ID],
		})
		if dev.Credentials == nil {
			page.NeedCreds = true
		}
	}
	page.Defs = defs
	page.KeyAvailable = s.store.CredentialsAvailable()
	page.CSRF = s.backupToken(r)
	d.Data = page
	s.render(w, "push", d)
}

// pushMatches applies the site and tag filters of the selection list.
func pushMatches(dev Device, site, tag string) bool {
	if site != "" && !strings.EqualFold(dev.Site, site) {
		return false
	}
	if tag == "" {
		return true
	}
	for _, t := range dev.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
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
	if r.PostForm.Get("rebind_ack") != "on" {
		return fail("confirm that this push may rebind the device's gRPC server")
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
		if dev.Verify == gnoiVerifyUnverified && r.PostForm.Get("unverified_ack") != "on" {
			return fail("confirm that unverified connections can expose the device credentials")
		}
		devs = append(devs, dev)
	}
	// Each device may take gnoiPushTimeout, so the response write deadline has to cover all of them.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Duration(len(devs))*gnoiPushTimeout + time.Minute))
	posted := deviceCreds{Username: strings.TrimSpace(r.PostForm.Get("username")), Password: r.PostForm.Get("password")}
	results := pushDefinitionToDevices(r.Context(), s.store, s.gnoiAllow, def, tmpl, devs, posted, r.PostForm.Get("ca_passphrase"), admin)
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
	cn := dev.Name
	var dnsNames []string
	var ips []net.IP
	if dev.FQDN != "" {
		cn = dev.FQDN
		dnsNames = append(dnsNames, dev.FQDN)
	}
	if ip := net.ParseIP(dev.ManagementIP); ip != nil {
		ips = append(ips, ip)
	}
	for _, san := range def.ExtraSANs {
		if ip := net.ParseIP(san); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, san)
		}
	}
	req := gnoiPushRequest{
		Target: target, Username: creds.Username, Password: creds.Password,
		Verify: dev.Verify, CAID: def.CAID, TrustCAID: dev.CAID, Fingerprint: dev.Pin, CAPassphrase: caPass,
		Template: tmpl, CommonName: cn, Country: def.Country, State: def.State, City: def.City, Organization: def.Organization, OU: def.OU,
		DNSNames: dnsNames, IPs: ips, CertID: def.CertID, ValidDays: def.ValidDays, Admin: admin,
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

// afterInstall re-pins a fingerprint device to the certificate just installed (the
// device may have rebound its gRPC server to it), then refreshes the device snapshot.
// It returns a note for the results panel.
func afterInstall(ctx context.Context, st *Store, allow []*net.IPNet, dev Device, creds deviceCreds, der []byte, target string) string {
	if dev.Verify == gnoiVerifyFingerprint {
		sum := sha256.Sum256(der)
		pin := hexColons(sum[:])
		if err := st.UpdateDevice(dev.ID, func(d *Device) { d.Pin, d.PinAddress = pin, target }); err != nil {
			return "Could not save the new pin: " + err.Error() + "."
		}
		dev.Pin = pin
	}
	snapCtx, cancel := context.WithTimeout(ctx, gnoiPushTimeout)
	defer cancel()
	rep, _, err := gnoiInspect(snapCtx, st, allow, dev, creds, true)
	if err != nil {
		return "Certificates not refreshed: " + err.Error() + "."
	}
	snap := &DeviceSnapshot{Taken: time.Now().UTC(), Certs: rep.Certs, Served: rep.Served}
	if err := st.UpdateDevice(dev.ID, func(d *Device) { d.Snapshot = snap }); err != nil {
		return "Could not save the snapshot: " + err.Error() + "."
	}
	return "Certificates refreshed."
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
