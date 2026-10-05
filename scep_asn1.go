package main

const (
	scepASN1Depth = 32
	scepASN1Nodes = 8192
	scepASN1Work  = 8 * scepMaxMessage
)

// boundedSCEPASN1 is an iterative, allocation-free TLV framing preflight, not a
// CMS parser. It accepts definite, minimally length-encoded ASN.1 only. The
// library's BER converter recursively rebuilds every constructed object, so a
// byte limit alone does not bound its stack or copying. Bound depth, object count
// and cumulative encoded lengths (the converter's copy work) before calling it.
// Opaque primitive contents are skipped; embedded CMS envelopes are independently
// checked at inspectEnvelope before the library parses them.
func boundedSCEPASN1(raw []byte) error {
	if len(raw) == 0 || len(raw) > scepMaxMessage {
		return errSCEPRequest
	}
	var ends [scepASN1Depth + 1]int
	ends[0] = len(raw)
	pos, depth, nodes, work, roots := 0, 0, 0, 0, 0
	for {
		if pos == ends[depth] {
			if depth == 0 {
				return nil
			}
			depth--
			continue
		}
		if depth == 0 {
			roots++
			if roots != 1 {
				return errSCEPRequest
			}
		}
		if depth >= scepASN1Depth || ends[depth]-pos < 2 {
			return errSCEPRequest
		}
		start := pos
		tag := raw[pos]
		pos++
		// CMS/X.509 uses low tags. Reject EOC and high-tag encodings rather than
		// exposing the dependency's separate unchecked high-tag loop.
		if tag == 0 || tag&31 == 31 {
			return errSCEPRequest
		}
		lengthByte := raw[pos]
		pos++
		length := int(lengthByte)
		if lengthByte&128 != 0 {
			n := int(lengthByte & 127)
			if n == 0 || n > 3 || n > ends[depth]-pos || raw[pos] == 0 {
				return errSCEPRequest
			}
			length = 0
			for range n {
				length = length*256 + int(raw[pos])
				pos++
			}
			if length < 128 {
				return errSCEPRequest
			}
		}
		if length > ends[depth]-pos {
			return errSCEPRequest
		}
		end := pos + length
		nodes++
		work += end - start
		if nodes > scepASN1Nodes || work > scepASN1Work {
			return errSCEPRequest
		}
		if tag&32 != 0 && length > 0 {
			depth++
			ends[depth] = end
		} else {
			pos = end
		}
	}
}
