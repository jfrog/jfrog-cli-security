package githubactions

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// RefAdvertisement is a parsed git smart-HTTP upload-pack reference advertisement
type RefAdvertisement struct {
	// ObjectFormat is "sha1" or "sha256".
	ObjectFormat string
	// HEAD is the advertised HEAD object ID; empty for an empty repository.
	HEAD string
	// DefaultBranch is the short name of the branch HEAD points at, from the symref capability;
	// empty when HEAD has no symref.
	DefaultBranch string
	// Refs maps each full ref name ("refs/heads/main", "refs/tags/v1", "refs/pull/1/head") to its
	// advertised object ID. For an annotated tag this is the tag object, not the commit.
	Refs map[string]string
	// Peeled maps a full tag ref name to the object its annotated tag ultimately points at, from
	// the "<ref>^{}" record. Absent for lightweight tags.
	Peeled map[string]string
}

const (
	pktHeaderLen = 4
	// pktMaxLen is git's LARGE_PACKET_MAX: the largest total packet length, header included.
	pktMaxLen = 65520

	uploadPackServiceLine = "# service=git-upload-pack"
	protocolVersion1      = "version 1"
	emptyRepoCapabilities = "capabilities^{}"
	peeledSuffix          = "^{}"

	objectFormatSHA1   = "sha1"
	objectFormatSHA256 = "sha256"

	refsPrefix  = "refs/"
	tagsPrefix  = "refs/tags/"
	headsPrefix = "refs/heads/"
	headRefName = "HEAD"
)

// ParseGitRefs parses a protocol v0/v1 upload-pack reference advertisement.
//
// The body is binary pkt-line framing, whatever Content-Type the server declares - getRefs
// labels it application/json. A payload may contain a NUL, and the last one need not end in LF,
// so this reads length-prefixed packets and never splits on newlines.
func ParseGitRefs(r io.Reader) (*RefAdvertisement, error) {
	pr := &pktReader{r: r}

	if err := readServiceHeader(pr); err != nil {
		return nil, err
	}
	adv := &RefAdvertisement{
		ObjectFormat: objectFormatSHA1,
		Refs:         map[string]string{},
		Peeled:       map[string]string{},
	}
	if err := readRefRecords(pr, adv); err != nil {
		return nil, err
	}
	if err := pr.expectEOF(); err != nil {
		return nil, err
	}
	return adv, nil
}

// readServiceHeader consumes the "# service=git-upload-pack" packet and the flush after it.
func readServiceHeader(pr *pktReader) error {
	payload, flush, err := pr.next()
	if err != nil {
		return fmt.Errorf("reading the git refs service header: %w", err)
	}
	if flush || trimLF(payload) != uploadPackServiceLine {
		return fmt.Errorf("git refs advertisement does not start with %q", uploadPackServiceLine)
	}
	if _, flush, err = pr.next(); err != nil {
		return fmt.Errorf("reading the flush after the git refs service header: %w", err)
	}
	if !flush {
		return errors.New("git refs service header is not followed by a flush packet")
	}
	return nil
}

// readRefRecords reads every ref record up to and including the terminating flush.
func readRefRecords(pr *pktReader, adv *RefAdvertisement) error {
	sawFirst, sawVersion, emptyRepo := false, false, false
	for {
		payload, flush, err := pr.next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return errors.New("git refs advertisement ends without a terminating flush packet")
			}
			return fmt.Errorf("reading a git refs record: %w", err)
		}
		if flush {
			return nil
		}
		line := trimLF(payload)
		if !sawFirst && !sawVersion && strings.HasPrefix(line, "version ") {
			if line != protocolVersion1 {
				return fmt.Errorf("unsupported git protocol %q - only a v0/v1 advertisement is understood", line)
			}
			sawVersion = true
			continue
		}
		if emptyRepo {
			return errors.New("git refs advertisement lists a ref after the empty-repository record")
		}
		if !sawFirst {
			sawFirst = true
			if emptyRepo, err = parseFirstRecord(line, adv); err != nil {
				return err
			}
			continue
		}
		if strings.IndexByte(line, 0) >= 0 {
			return errors.New("git refs record other than the first carries a NUL")
		}
		if err = addRefRecord(line, adv); err != nil {
			return err
		}
	}
}

// parseFirstRecord handles the first ref record, which alone carries the capability list after
// a NUL. It reports whether the record is the synthetic one an empty repository sends.
func parseFirstRecord(line string, adv *RefAdvertisement) (emptyRepo bool, err error) {
	record, capList, found := strings.Cut(line, "\x00")
	if !found {
		return false, errors.New("first git refs record has no NUL-delimited capability list")
	}
	if strings.IndexByte(capList, 0) >= 0 {
		return false, errors.New("first git refs record carries more than one NUL")
	}
	if err = applyCapabilities(capList, adv); err != nil {
		return false, err
	}
	oid, name, err := splitRecord(record)
	if err != nil {
		return false, err
	}
	if name == emptyRepoCapabilities {
		if oid != zeroObjectID(adv.ObjectFormat) {
			return false, fmt.Errorf("empty-repository record has non-zero object ID %q", oid)
		}
		// Neither a ref nor a peeled tag: the record exists only to carry the capabilities.
		return true, nil
	}
	return false, addRefRecord(record, adv)
}

// applyCapabilities reads object-format and symref from the space-delimited capability list,
// ignoring any other well-formed capability so a server adding one does not break the parse.
func applyCapabilities(capList string, adv *RefAdvertisement) error {
	sawFormat, sawHeadSymref := false, false
	for _, token := range strings.Split(capList, " ") {
		key, value, hasValue := strings.Cut(token, "=")
		if !validCapabilityKey(key) {
			return fmt.Errorf("malformed git capability %q", token)
		}
		switch key {
		case "object-format":
			if !hasValue || (value != objectFormatSHA1 && value != objectFormatSHA256) {
				return fmt.Errorf("unsupported git object format %q", value)
			}
			if sawFormat && adv.ObjectFormat != value {
				return fmt.Errorf("conflicting git object formats %q and %q", adv.ObjectFormat, value)
			}
			adv.ObjectFormat, sawFormat = value, true
		case "symref":
			source, target, ok := strings.Cut(value, ":")
			if !hasValue || !ok {
				return fmt.Errorf("malformed git symref capability %q", token)
			}
			if source != headRefName {
				// Only HEAD's symref is meaningful here; others are ignored like unknown capabilities.
				continue
			}
			if sawHeadSymref {
				return errors.New("git refs advertisement carries more than one symref for HEAD")
			}
			branch, isBranch := strings.CutPrefix(target, headsPrefix)
			if !isBranch || branch == "" || !validRefName(target) {
				return fmt.Errorf("git symref for HEAD targets %q, not a branch", target)
			}
			adv.DefaultBranch, sawHeadSymref = branch, true
		}
	}
	return nil
}

// addRefRecord stores one "<object-id> SP <ref-name>" record.
func addRefRecord(record string, adv *RefAdvertisement) error {
	oid, name, err := splitRecord(record)
	if err != nil {
		return err
	}
	if err = validateObjectID(oid, adv.ObjectFormat); err != nil {
		return fmt.Errorf("git ref %q: %w", name, err)
	}
	if name == headRefName {
		if adv.HEAD != "" {
			return errors.New("git refs advertisement lists HEAD more than once")
		}
		adv.HEAD = oid
		return nil
	}
	if base, peeled := strings.CutSuffix(name, peeledSuffix); peeled {
		if !strings.HasPrefix(base, tagsPrefix) {
			return fmt.Errorf("peeled git ref %q is not a tag", name)
		}
		if _, known := adv.Refs[base]; !known {
			return fmt.Errorf("peeled git ref %q has no preceding tag record", name)
		}
		if _, dup := adv.Peeled[base]; dup {
			return fmt.Errorf("peeled git ref %q appears more than once", name)
		}
		adv.Peeled[base] = oid
		return nil
	}
	if !strings.HasPrefix(name, refsPrefix) || !validRefName(name) {
		return fmt.Errorf("invalid git ref name %q", name)
	}
	if _, dup := adv.Refs[name]; dup {
		return fmt.Errorf("git ref %q appears more than once", name)
	}
	adv.Refs[name] = oid
	return nil
}

func splitRecord(record string) (oid, name string, err error) {
	oid, name, found := strings.Cut(record, " ")
	if !found || oid == "" || name == "" {
		return "", "", fmt.Errorf("malformed git refs record %q", record)
	}
	return oid, name, nil
}

func validateObjectID(oid, objectFormat string) error {
	if len(oid) != objectIDLen(objectFormat) || !isLowerHex(oid) {
		return fmt.Errorf("object ID %q is not %d lowercase hex characters", oid, objectIDLen(objectFormat))
	}
	if oid == zeroObjectID(objectFormat) {
		return fmt.Errorf("object ID %q is the zero ID", oid)
	}
	return nil
}

func objectIDLen(objectFormat string) int {
	if objectFormat == objectFormatSHA256 {
		return 64
	}
	return 40
}

func zeroObjectID(objectFormat string) string {
	return strings.Repeat("0", objectIDLen(objectFormat))
}

func isLowerHex(s string) bool {
	for i := range len(s) {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validCapabilityKey(key string) bool {
	if key == "" {
		return false
	}
	for i := range len(key) {
		c := key[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// validRefName applies git-check-ref-format's rules to a full ref name.
func validRefName(name string) bool {
	if name == "" || name == "@" || strings.HasSuffix(name, "/") || strings.HasSuffix(name, ".") ||
		strings.Contains(name, "..") || strings.Contains(name, "//") || strings.Contains(name, "@{") {
		return false
	}
	for i := range len(name) {
		c := name[i]
		if c < 0x20 || c == 0x7f || strings.IndexByte(" ~^:?*[\\", c) >= 0 {
			return false
		}
	}
	for _, component := range strings.Split(name, "/") {
		if component == "" || strings.HasPrefix(component, ".") || strings.HasSuffix(component, ".lock") {
			return false
		}
	}
	return true
}

// trimLF removes at most one trailing LF: the last packet of an advertisement need not end in one.
func trimLF(payload []byte) string {
	return string(bytes.TrimSuffix(payload, []byte("\n")))
}

// pktReader reads git pkt-line packets.
type pktReader struct {
	r io.Reader
}

// next returns the next data packet's payload, or flush=true for a flush packet. It returns
// io.EOF, unwrapped, only when the stream ends cleanly before a packet header.
func (p *pktReader) next() (payload []byte, flush bool, err error) {
	var header [pktHeaderLen]byte
	if _, err = io.ReadFull(p.r, header[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, false, errors.New("truncated pkt-line length header")
		}
		return nil, false, err
	}
	length, err := parsePktLength(header)
	if err != nil {
		return nil, false, err
	}
	switch {
	case length == 0:
		return nil, true, nil
	case length == 1 || length == 2:
		return nil, false, fmt.Errorf("unexpected pkt-line control packet %04x in a v0/v1 advertisement", length)
	case length == 3:
		return nil, false, errors.New("invalid pkt-line length 0003")
	case length == pktHeaderLen:
		return nil, false, errors.New("empty pkt-line data packet 0004")
	case length > pktMaxLen:
		return nil, false, fmt.Errorf("pkt-line length %d exceeds the maximum of %d", length, pktMaxLen)
	}
	payload = make([]byte, length-pktHeaderLen)
	if _, err = io.ReadFull(p.r, payload); err != nil {
		return nil, false, fmt.Errorf("truncated pkt-line payload: want %d bytes: %w", len(payload), err)
	}
	return payload, false, nil
}

// expectEOF fails when anything follows the terminating flush packet.
func (p *pktReader) expectEOF() error {
	var b [1]byte
	n, err := p.r.Read(b[:])
	if n > 0 {
		return errors.New("git refs advertisement has bytes after the terminating flush packet")
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// parsePktLength decodes a pkt-line header: exactly four lowercase hexadecimal digits.
func parsePktLength(header [pktHeaderLen]byte) (int, error) {
	if !isLowerHex(string(header[:])) {
		return 0, fmt.Errorf("pkt-line length header %q is not four lowercase hex digits", header[:])
	}
	length, err := strconv.ParseUint(string(header[:]), 16, 32)
	if err != nil {
		return 0, fmt.Errorf("parsing pkt-line length header %q: %w", header[:], err)
	}
	return int(length), nil
}
