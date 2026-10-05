package main

import (
	"bytes"
	"encoding/asn1"
	"testing"
	"time"
)

func asn1TestObject(t *testing.T, tag int, constructed bool, content []byte) []byte {
	t.Helper()
	b, err := asn1.Marshal(asn1.RawValue{Tag: tag, IsCompound: constructed, Bytes: content})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func nestedSCEPASN1(t *testing.T, depth int, leaf []byte) []byte {
	t.Helper()
	for range depth {
		leaf = asn1TestObject(t, asn1.TagSequence, true, leaf)
	}
	return leaf
}

func TestSCEPASN1ResourceBudgets(t *testing.T) {
	leaf := []byte{4, 0}
	valid := nestedSCEPASN1(t, scepASN1Depth-1, leaf)
	if err := boundedSCEPASN1(valid); err != nil {
		t.Fatalf("depth boundary rejected: %v", err)
	}
	wide := asn1TestObject(t, asn1.TagSequence, true, bytes.Repeat(leaf, scepASN1Nodes-1))
	if err := boundedSCEPASN1(wide); err != nil {
		t.Fatalf("node boundary rejected: %v", err)
	}
	// The payload alone is under 1 MiB and nesting is under 32, but repeatedly
	// reconstructing its ancestors would exceed the separate conversion budget.
	large := asn1TestObject(t, asn1.TagOctetString, false, make([]byte, 600<<10))
	work := nestedSCEPASN1(t, 16, large)
	if len(work) > scepMaxMessage {
		t.Fatal("test must isolate work limit from byte limit")
	}
	indefinite := append(bytes.Repeat([]byte{0x30, 0x80}, 100000), leaf...)
	indefinite = append(indefinite, make([]byte, 200000)...)
	cases := map[string][]byte{
		"depth":                    nestedSCEPASN1(t, scepASN1Depth, leaf),
		"extreme-definite-depth":   nestedSCEPASN1(t, 2000, leaf),
		"extreme-indefinite-depth": indefinite,
		"nodes":                    asn1TestObject(t, asn1.TagSequence, true, bytes.Repeat(leaf, scepASN1Nodes)),
		"conversion-work":          work,
		"bytes":                    make([]byte, scepMaxMessage+1),
		"truncated-tag":            {0x30},
		"high-tag":                 {0x3f, 0x81, 0x80},
		"indefinite":               {0x30, 0x80, 0, 0},
		"truncated-length":         {0x30, 0x83, 1},
		"oversized-length":         {0x30, 0x83, 0xff, 0xff, 0xff},
		"nonminimal-length":        {0x30, 0x81, 0x02, 4, 0},
		"leading-zero-length":      {0x30, 0x82, 0, 0x80},
		"child-crosses-parent":     {0x30, 2, 4, 2, 0, 0},
		"trailing-root":            {4, 0, 4, 0},
		"eoc":                      {0, 0},
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if err := boundedSCEPASN1(raw); err == nil {
				t.Fatal("resource/framing violation accepted")
			}
			if _, _, err := parseSCEP(raw, nil, nil); err == nil {
				t.Fatal("parse boundary accepted invalid framing")
			}
			if allocs := testing.AllocsPerRun(5, func() { _ = boundedSCEPASN1(raw) }); allocs != 0 {
				t.Fatalf("preflight allocated: %g", allocs)
			}
		})
	}
}

func TestSCEPASN1RejectsBeforeStateLock(t *testing.T) {
	e := newSCEPService(&Store{})
	e.store.scepMu.Lock()
	defer e.store.scepMu.Unlock()
	result := make(chan int, 1)
	raw := nestedSCEPASN1(t, scepASN1Depth, []byte{4, 0})
	go func() { _, status := e.enroll(raw); result <- status }()
	select {
	case status := <-result:
		if status != 400 {
			t.Fatalf("status %d", status)
		}
	case <-time.After(time.Second):
		t.Fatal("untrusted ASN.1 waited for shared state lock")
	}
}

func TestSCEPASN1EmbeddedEnvelopeGuard(t *testing.T) {
	f := newSCEPFixture(t)
	malicious := nestedSCEPASN1(t, scepASN1Depth, []byte{4, 0})
	// Primitive CMS content is opaque to the outer framing walk. Confirm the
	// embedded envelope receives an independent budget before its library parse.
	raw := f.signedEnvelope(t, malicious, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, false, "19")
	if err := boundedSCEPASN1(raw); err != nil {
		t.Fatalf("outer CMS should pass framing: %v", err)
	}
	if _, err := inspectEnvelope(malicious); err == nil {
		t.Fatal("inner depth violation accepted")
	}
	if _, status := f.e.enroll(raw); status != 400 {
		t.Fatalf("embedded malicious envelope status: %d", status)
	}
}
