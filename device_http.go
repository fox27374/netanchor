package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	devicePlatformIOSXE = "IOS-XE"
	devicePlatformNXOS  = "NX-OS"
	deviceDefaultPort   = 57400
)

// deviceForm is the add/edit form. It echoes posted values; the password is never echoed.
type deviceForm struct {
	ID                              string
	Editing                         bool
	Name, FQDN, ManagementIP, Port  string
	Platform, Site, Tags, Notes     string
	Model, Serial                   string
	Verify, CAID                    string
	Fingerprint                     string // value in the form
	ProbedTarget, ProbedFingerprint string // from the last probe; a new pin must match them
	Username                        string
	UnverifiedAck, RemoveCreds      bool
	Stored, KeyAvailable            bool
	CAs                             []caOptionData
	CSRF                            string
	Info                            string
}

type deviceDetailPage struct {
	Device       Device
	Stored       bool
	KeyAvailable bool
	CSRF         string
	Snapshot     []deviceCertRow
	Served       *deviceCertRow
	Taken        time.Time
	Check        *deviceCheckResult
	Pushes       []devicePushRow
}

// devicePushRow is one certificate push to a device, read from the certificate records.
type devicePushRow struct {
	Time                           time.Time
	CertID, Serial, Admin, Outcome string
}

// devicePushes lists the pushes whose target is this device's gRPC address, newest first.
func (s *Server) devicePushes(dev Device) ([]devicePushRow, error) {
	recs, err := s.store.Records()
	if err != nil {
		return nil, err
	}
	target := net.JoinHostPort(dev.ManagementIP, strconv.Itoa(dev.Port))
	var rows []devicePushRow
	for _, rec := range recs {
		for _, p := range rec.Pushes {
			if p.Target == target {
				rows = append(rows, devicePushRow{Time: p.Time, CertID: p.CertID, Serial: rec.Serial, Admin: p.Admin, Outcome: p.Outcome})
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Time.After(rows[j].Time) })
	return rows, nil
}

// IsForm tells device.html whether to render the add/edit form or the details.
func (deviceForm) IsForm() bool       { return true }
func (deviceDetailPage) IsForm() bool { return false }

func deviceHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	// no-referrer makes browsers send "Origin: null" on form POSTs, which backupCSRF rejects.
	w.Header().Set("Referrer-Policy", "same-origin")
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	d := s.base(r, "Devices", "devices")
	devs, err := s.store.ListDevices()
	if err != nil {
		d.Error = err.Error()
	}
	d.Data = devs
	s.render(w, "devices", d)
}

func (s *Server) handleDeviceDetail(w http.ResponseWriter, r *http.Request) {
	deviceHeaders(w)
	dev, ok, err := s.store.GetDevice(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.renderDeviceDetail(w, r, dev, nil, "")
}

// renderDeviceDetail shows the device page. check is the outcome of the last test or refresh, if any.
func (s *Server) renderDeviceDetail(w http.ResponseWriter, r *http.Request, dev Device, check *deviceCheckResult, errMsg string) {
	deviceHeaders(w)
	d := s.base(r, dev.Name, "devices")
	d.Error = errMsg
	page := deviceDetailPage{Device: dev, Stored: dev.Credentials != nil, KeyAvailable: s.store.CredentialsAvailable(), CSRF: s.backupToken(r), Check: check}
	pushes, err := s.devicePushes(dev)
	if err != nil {
		d.Error = err.Error()
	}
	page.Pushes = pushes
	if dev.Snapshot != nil {
		page.Snapshot, page.Served = deviceSnapshotView(dev.Snapshot, time.Now())
		page.Taken = dev.Snapshot.Taken
	}
	d.Data = page
	s.render(w, "device", d)
}

func (s *Server) handleDeviceNew(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", http.StatusForbidden)
		return
	}
	s.renderDeviceForm(w, r, deviceForm{Port: strconv.Itoa(deviceDefaultPort), Platform: devicePlatformIOSXE, Verify: gnoiVerifyFingerprint}, "")
}

func (s *Server) handleDeviceEdit(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", http.StatusForbidden)
		return
	}
	dev, ok, err := s.store.GetDevice(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	f := deviceForm{
		ID: dev.ID, Name: dev.Name, FQDN: dev.FQDN, ManagementIP: dev.ManagementIP, Port: strconv.Itoa(dev.Port),
		Platform: dev.Platform, Site: dev.Site, Tags: strings.Join(dev.Tags, ", "), Notes: dev.Notes,
		Model: dev.Model, Serial: dev.Serial, Verify: dev.Verify, CAID: dev.CAID, Fingerprint: dev.Pin,
	}
	var errMsg string
	if dev.Credentials != nil && s.store.CredentialsAvailable() {
		if c, err := s.store.openCredentials(dev.Credentials); err != nil {
			errMsg = err.Error()
		} else {
			f.Username = c.Username
		}
	}
	s.renderDeviceForm(w, r, f, errMsg)
}

// fillDeviceForm adds the state every form render needs.
func (s *Server) fillDeviceForm(f *deviceForm, r *http.Request) error {
	f.Editing = f.ID != ""
	f.KeyAvailable = s.store.CredentialsAvailable()
	f.CSRF = s.backupToken(r)
	f.CAs = s.getIssueCAs()
	if f.Editing {
		dev, ok, err := s.store.GetDevice(f.ID)
		if err != nil {
			return err
		}
		if !ok {
			return errDeviceNotFound
		}
		f.Stored = dev.Credentials != nil
	}
	return nil
}

func (s *Server) renderDeviceForm(w http.ResponseWriter, r *http.Request, f deviceForm, errMsg string) {
	deviceHeaders(w)
	if err := s.fillDeviceForm(&f, r); err != nil {
		errMsg = err.Error()
	}
	title := "Add device"
	if f.Editing {
		title = "Edit device"
	}
	d := s.base(r, title, "devices")
	d.Error = errMsg
	d.Data = f
	s.render(w, "device", d)
}

// deviceFormFromPost reads the posted form. Only the password is never read back out.
func deviceFormFromPost(r *http.Request) deviceForm {
	p := r.PostForm
	return deviceForm{
		ID: strings.TrimSpace(p.Get("id")), Name: strings.TrimSpace(p.Get("name")),
		FQDN: strings.TrimSpace(p.Get("fqdn")), ManagementIP: strings.TrimSpace(p.Get("management_ip")),
		Port: strings.TrimSpace(p.Get("port")), Platform: p.Get("platform"),
		Site: strings.TrimSpace(p.Get("site")), Tags: p.Get("tags"), Notes: p.Get("notes"),
		Model: strings.TrimSpace(p.Get("model")), Serial: strings.TrimSpace(p.Get("serial")),
		Verify: p.Get("verify"), CAID: p.Get("ca"), Fingerprint: strings.TrimSpace(p.Get("fingerprint")),
		ProbedTarget: p.Get("probed_target"), ProbedFingerprint: p.Get("probed_fingerprint"),
		Username:      strings.TrimSpace(p.Get("username")),
		UnverifiedAck: p.Get("unverified_ack") == "on", RemoveCreds: p.Get("remove_credentials") == "on",
	}
}

// handleDeviceProbe fetches the device's server certificate fingerprint. It sends no credentials.
func (s *Server) handleDeviceProbe(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.backupCSRF(r) {
		http.Error(w, "invalid origin or CSRF token; reload the form", http.StatusForbidden)
		return
	}
	f := deviceFormFromPost(r)
	f.Info, f.ProbedTarget, f.ProbedFingerprint = "", "", ""
	ip := net.ParseIP(f.ManagementIP)
	port, perr := parsePort(f.Port)
	if ip == nil || perr != nil {
		s.renderDeviceForm(w, r, f, "enter a valid management IP and port before fetching the fingerprint")
		return
	}
	target := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	ctx, cancel := context.WithTimeout(r.Context(), gnoiConnectTimeout)
	defer cancel()
	fp, err := gnoiProbe(ctx, s.gnoiAllow, target)
	if err != nil {
		s.renderDeviceForm(w, r, f, "fingerprint fetch failed: "+err.Error())
		return
	}
	f.Fingerprint, f.ProbedTarget, f.ProbedFingerprint = fp, target, fp
	f.Info = "Fingerprint fetched for " + target + ". Compare it with the device before you save."
	s.renderDeviceForm(w, r, f, "")
}

func (s *Server) handleDeviceSave(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.backupCSRF(r) {
		http.Error(w, "invalid origin or CSRF token; reload the form", http.StatusForbidden)
		return
	}
	f := deviceFormFromPost(r)
	dev, err := s.deviceFromForm(r, f)
	if err == nil {
		err = s.store.SaveDevice(&dev)
	}
	if err != nil {
		s.renderDeviceForm(w, r, f, err.Error())
		return
	}
	http.Redirect(w, r, "/devices/"+dev.ID, http.StatusSeeOther)
}

// deviceFromForm validates the form, enforces the server pin rule and seals the
// credentials. It returns the device to save. Nothing is stored here.
func (s *Server) deviceFromForm(r *http.Request, f deviceForm) (Device, error) {
	var dev Device
	if f.ID != "" {
		old, ok, err := s.store.GetDevice(f.ID)
		if err != nil {
			return dev, err
		}
		if !ok {
			return dev, errDeviceNotFound
		}
		dev = old
	}
	if f.Name == "" {
		return dev, errors.New("name is required")
	}
	ip := net.ParseIP(f.ManagementIP)
	if ip == nil {
		return dev, errors.New("management IP must be a valid IPv4 or IPv6 address")
	}
	port, err := parsePort(f.Port)
	if err != nil {
		return dev, err
	}
	if f.Platform != devicePlatformIOSXE && f.Platform != devicePlatformNXOS {
		return dev, errors.New("choose a platform")
	}
	dev.Name, dev.FQDN, dev.ManagementIP, dev.Port, dev.Platform = f.Name, f.FQDN, ip.String(), port, f.Platform
	dev.Site, dev.Notes, dev.Model, dev.Serial = f.Site, f.Notes, f.Model, f.Serial
	dev.Tags = nil
	for _, t := range strings.Split(f.Tags, ",") {
		if t = strings.TrimSpace(t); t != "" {
			dev.Tags = append(dev.Tags, t)
		}
	}
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))

	oldPin, oldAddr := dev.Pin, dev.PinAddress
	dev.Verify, dev.CAID, dev.Pin, dev.PinAddress = f.Verify, "", "", ""
	switch f.Verify {
	case gnoiVerifyCA:
		if !s.store.ValidCAID(f.CAID) {
			return dev, errors.New("select a valid NetAnchor CA")
		}
		dev.CAID = f.CAID
	case gnoiVerifyUnverified:
		if !f.UnverifiedAck {
			return dev, errors.New("confirm that unverified connections can expose the device credentials")
		}
	case gnoiVerifyFingerprint:
		fp := normalizeFingerprint(f.Fingerprint)
		if fp == "" {
			return dev, errors.New("fetch and confirm the device fingerprint first")
		}
		switch {
		case f.ID != "" && oldAddr == addr && normalizeFingerprint(oldPin) == fp:
			// unchanged pin for an unchanged address: keep the stored values
			dev.Pin, dev.PinAddress = oldPin, oldAddr
		case f.ProbedTarget == addr && normalizeFingerprint(f.ProbedFingerprint) == fp:
			dev.Pin, dev.PinAddress = f.Fingerprint, addr
		default:
			return dev, errors.New("fetch and confirm the device fingerprint for this address first")
		}
	default:
		return dev, errors.New("choose how to verify the device")
	}

	if err := s.deviceCredentials(&dev, f, r.PostForm.Get("password")); err != nil {
		return dev, err
	}
	return dev, nil
}

// deviceCredentials applies the username/password rules. A blank username and
// password on edit keep what is stored; "remove" clears it.
func (s *Server) deviceCredentials(dev *Device, f deviceForm, password string) error {
	switch {
	case f.RemoveCreds:
		dev.Credentials = nil
	case f.Username == "" && password == "":
		// keep existing credentials (none on create)
	case !s.store.CredentialsAvailable():
		return errCredentialsDisabled
	case f.Username == "":
		return errors.New("username is required")
	case password == "":
		if dev.Credentials == nil {
			return errors.New("password is required")
		}
		c, err := s.store.openCredentials(dev.Credentials)
		if err != nil || c.Username != f.Username {
			return errors.New("enter the password to store the username and password")
		}
	default:
		blob, err := s.store.sealCredentials(deviceCreds{Username: f.Username, Password: password})
		if err != nil {
			return err
		}
		dev.Credentials = blob
	}
	return nil
}

func (s *Server) handleDeviceDelete(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "administrator required", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.backupCSRF(r) {
		http.Error(w, "invalid origin or CSRF token; reload the form", http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	dev, ok, err := s.store.GetDevice(id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.PostForm.Get("confirm_delete") != "on" {
		s.renderDeviceDetail(w, r, dev, nil, "tick the confirmation box to delete this device")
		return
	}
	if err := s.store.DeleteDevice(id); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/devices", http.StatusSeeOther)
}

// parsePort reads a gRPC port, defaulting to 57400 when blank.
func parsePort(v string) (int, error) {
	if strings.TrimSpace(v) == "" {
		return deviceDefaultPort, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 1 || n > 65535 {
		return 0, errors.New("port must be 1-65535")
	}
	return n, nil
}
