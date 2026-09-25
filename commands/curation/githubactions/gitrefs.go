package githubactions

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// RefAdvertisement is the part of a git smart-HTTP upload-pack reference advertisement that ref
// classification reads. Every record is parsed, but only refs/... records are kept and validated:
// HEAD, peeled "<tag>^{}" records and the capabilities other than object-format are skipped, since
// no ref an action can be pinned to resolves through them - uses: always names a ref, and the
// download APIs peel annotated tags themselves.
type RefAdvertisement struct {
	// ObjectFormat is "sha1" or "sha256".
	ObjectFormat string
	// Refs maps each full ref name ("refs/heads/main", "refs/tags/v1", "refs/pull/1/head") to its
	// advertised object ID. For an annotated tag this is the tag object, not the commit.
	Refs map[string]string
}

const (
	pktHeaderLen = 4
	// pktMaxLen is git's LARGE_PACKET_MAX: the largest total packet length, header included.
	pktMaxLen = 65520

	uploadPackServiceLine = "# service=git-upload-pack"
	protocolVersion1      = "version 1"
	peeledSuffix          = "^{}"

	objectFormatSHA1   = "sha1"
	objectFormatSHA256 = "sha256"

	refsPrefix  = "refs/"
	tagsPrefix  = "refs/tags/"
	headsPrefix = "refs/heads/"
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

// readRefRecords reads every record up to and including the terminating flush, keeping the refs.
func readRefRecords(pr *pktReader, adv *RefAdvertisement) error {
	sawFirst := false
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
		if !sawFirst && strings.HasPrefix(line, "version ") {
			// A v2 response is a different format altogether and would be misread as refs.
			if line != protocolVersion1 {
				return fmt.Errorf("unsupported git protocol %q - only a v0/v1 advertisement is understood", line)
			}
			continue
		}
		if !sawFirst {
			sawFirst = true
			// Only the first record carries capabilities, after a NUL; they must be read before
			// any record, since object-format sets the object ID length.
			var capList string
			line, capList, _ = strings.Cut(line, "\x00")
			if err = applyObjectFormat(capList, adv); err != nil {
				return err
			}
		}
		if err = addRefRecord(line, adv); err != nil {
			return err
		}
	}
}

// applyObjectFormat reads object-format from the space-delimited capability list; it defaults to
// sha1 when absent. Every other capability is ignored.
func applyObjectFormat(capList string, adv *RefAdvertisement) error {
	sawFormat := false
	for _, token := range strings.Split(capList, " ") {
		value, isFormat := strings.CutPrefix(token, "object-format=")
		if !isFormat {
			continue
		}
		if value != objectFormatSHA1 && value != objectFormatSHA256 {
			return fmt.Errorf("unsupported git object format %q", value)
		}
		if sawFormat && adv.ObjectFormat != value {
			return fmt.Errorf("conflicting git object formats %q and %q", adv.ObjectFormat, value)
		}
		adv.ObjectFormat, sawFormat = value, true
	}
	return nil
}

// addRefRecord stores one "<object-id> SP <ref-name>" record when it is a refs/... ref; any other
// record - HEAD, a peeled "^{}" record, an empty repository's "capabilities^{}" - is skipped.
func addRefRecord(record string, adv *RefAdvertisement) error {
	oid, name, err := splitRecord(record)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(name, refsPrefix) || strings.HasSuffix(name, peeledSuffix) {
		return nil
	}
	if err = validateObjectID(oid, adv.ObjectFormat); err != nil {
		return fmt.Errorf("git ref %q: %w", name, err)
	}
	if !validRefName(name) {
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
