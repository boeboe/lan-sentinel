package decoders

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"

	"lan-sentinel/internal/observation"
)

// NetBIOS name service (RFC 1002 §4.2) and browser announcements
// ([MS-BRWS]): what Windows hosts, Samba servers and some printers say about
// themselves on the broadcast domain, without a WINS server. NetBIOS is IPv4
// only.

const (
	nbnsHeader        = 12
	nbnsTypeNB        = 0x0020
	nbnsResponse      = 0x8000 // header flags: R
	nbnsGroup         = 0x8000 // NB_FLAGS: G, a group name
	nbnsOpQuery       = 0
	nbnsOpRegister    = 5
	nbnsOpRefresh     = 8
	nbnsOpRefreshAlt  = 9
	nbnsOpMultiHomed  = 15
	nbEncodedNameSize = 32

	// Name suffixes (the 16th byte of a NetBIOS name).
	nbSuffixWorkstation         = 0x00
	nbSuffixServer              = 0x20
	nbSuffixDomainMasterBrowser = 0x1b
	nbSuffixDomainControllers   = 0x1c
	nbSuffixMasterBrowser       = 0x1d

	// Datagram message types (RFC 1002 §4.4.1): direct unique, direct
	// group, broadcast.
	nbDatagramFirst = 0x10
	nbDatagramLast  = 0x12
	nbDatagramFixed = 14 // header before the source name

	// Browser announcement opcodes ([MS-BRWS] §2.2).
	browserHostAnnouncement        = 0x01
	browserWorkgroupAnnouncement   = 0x0c
	browserLocalMasterAnnouncement = 0x0f
	browserAnnouncementFixed       = 32 // the fields before the comment

	smbHeader          = 32
	smbComTransaction  = 0x25
	smbTransWordCount  = 14 // without the setup words
	browseMailslotName = `\MAILSLOT\BROWSE`
)

// serverTypes are the browser server-type bits kept in meta ([MS-BRWS]
// §2.2.1.2, SV_TYPE_*): what a host offers and which roles it holds.
var serverTypes = []struct {
	bit  uint32
	name string
}{
	{0x00000001, "workstation"},
	{0x00000002, "server"},
	{0x00000004, "sql_server"},
	{0x00000008, "domain_controller"},
	{0x00000010, "backup_domain_controller"},
	{0x00000020, "time_source"},
	{0x00000200, "print_server"},
	{0x00000800, "unix"}, // SV_TYPE_SERVER_UNIX: Samba sets it
	{0x00001000, "nt"},
	{0x00008000, "server_nt"},
	{0x00040000, "master_browser"},
	{0x00080000, "domain_master"},
	{0x02000000, "terminal_server"},
}

// nbns decodes a name service packet from UDP 137: a registration or
// refresh of the sender's own name (broadcast where no WINS server is
// used), or a positive answer to a name query that gives the sender's own
// address (seen on a mirror port). Queries, releases and answers about
// other hosts (a WINS server's) say nothing about the sender.
func (f *frame) nbns(src netip.Addr, b []byte) {
	if len(b) < nbnsHeader {
		return
	}
	flags := be16(b[2:])
	op, rcode := int(flags>>11)&0xf, flags&0xf
	questions, answers, additional := be16(b[4:]), be16(b[6:]), be16(b[10:])
	off, kind := nbnsHeader, ""
	switch {
	case flags&nbnsResponse == 0 && additional == 1 && questions == 1 &&
		(op == nbnsOpRegister || op == nbnsOpRefresh || op == nbnsOpRefreshAlt || op == nbnsOpMultiHomed):
		kind = "registration"
		_, _, next, ok := nbName(b, off) // the question: name, type, class
		if !ok || next+4 > len(b) {
			return
		}
		off = next + 4
	case flags&nbnsResponse != 0 && op == nbnsOpQuery && rcode == 0 && answers == 1:
		kind = "answer"
	default:
		return
	}
	// The resource record: name, type NB, class, TTL, length, then an
	// NB_FLAGS and address pair per address.
	name, suffix, next, ok := nbName(b, off)
	if !ok || next+10 > len(b) || be16(b[next:]) != nbnsTypeNB {
		return
	}
	rdata := b[next+10:]
	if n := int(be16(b[next+8:])); n < len(rdata) {
		rdata = rdata[:n]
	}
	for i := 0; i+6 <= len(rdata); i += 6 {
		if addr4(rdata[i+2:]) == src {
			f.netbiosName(src, kind, name, suffix, be16(rdata[i:])&nbnsGroup != 0)
			return
		}
	}
}

// netbiosName reports one name the sender holds: a unique workstation or
// server name is its computer name; the group name with suffix 0x00 is its
// workgroup or domain; the domain controllers' group (0x1c) and the master
// browser names (0x1b, 0x1d) name the domain and a role. Other names are
// not kept: messenger names (0x03) can be user names.
func (f *frame) netbiosName(src netip.Addr, kind, name string, suffix byte, group bool) {
	o := observation.Observation{Source: observation.PassiveNetBIOS, MAC: f.src, IP: src, Meta: map[string]string{"netbios": kind}}
	switch {
	case !group && (suffix == nbSuffixWorkstation || suffix == nbSuffixServer):
		o.Hostname, o.NameType = name, observation.NameNetBIOS
	case group && suffix == nbSuffixWorkstation:
		o.Meta["workgroup"] = name
	case group && suffix == nbSuffixDomainControllers:
		o.Meta["workgroup"], o.Meta["role"] = name, "domain_controller"
	case !group && suffix == nbSuffixDomainMasterBrowser:
		o.Meta["workgroup"], o.Meta["role"] = name, "domain_master_browser"
	case !group && suffix == nbSuffixMasterBrowser:
		o.Meta["workgroup"], o.Meta["role"] = name, "master_browser"
	default:
		return
	}
	f.add(o)
}

// nbDatagram decodes a NetBIOS datagram from UDP 138 (RFC 1002 §4.4). The
// source name is the sender's own; a browser announcement on
// \MAILSLOT\BROWSE adds its OS version, server type and comment, or, for a
// workgroup announcement, the workgroup. A datagram relayed for another host
// (the source address in the header is not the sender's) is skipped.
func (f *frame) nbDatagram(src netip.Addr, b []byte) {
	if len(b) < nbDatagramFixed || b[0] < nbDatagramFirst || b[0] > nbDatagramLast || addr4(b[4:]) != src {
		return
	}
	name, suffix, next, ok := nbName(b, nbDatagramFixed)
	if !ok {
		return
	}
	if _, _, next, ok = nbName(b, next); !ok { // the destination name
		return
	}
	o := observation.Observation{Source: observation.PassiveNetBIOS, MAC: f.src, IP: src, Meta: map[string]string{"netbios": "datagram"}}
	if suffix == nbSuffixWorkstation || suffix == nbSuffixServer {
		o.Hostname, o.NameType = name, observation.NameNetBIOS
	}
	if data, ok := browseData(b[next:]); ok {
		if server := browserAnnouncement(o.Meta, data); o.Hostname == "" && server != "" {
			o.Hostname, o.NameType = server, observation.NameNetBIOS
		}
	}
	if o.Hostname == "" && len(o.Meta) == 1 {
		return // a datagram from a group or service name, nothing else
	}
	f.add(o)
}

// browseData returns the data of an SMB Transaction to the \MAILSLOT\BROWSE
// mailslot, which carries browser announcements ([MS-BRWS] §2.1).
func browseData(smb []byte) ([]byte, bool) {
	if len(smb) < smbHeader+1 || !bytes.HasPrefix(smb, []byte("\xffSMB")) || smb[4] != smbComTransaction {
		return nil, false
	}
	words := int(smb[smbHeader])
	params := smb[smbHeader+1:]
	if words < smbTransWordCount || len(params) < 2*words+2 {
		return nil, false
	}
	dataCount, dataOffset := int(le16(params[22:])), int(le16(params[24:]))
	name := params[2*words+2:]
	if n := int(le16(params[2*words:])); n < len(name) {
		name = name[:n]
	}
	if !bytes.HasPrefix(name, []byte(browseMailslotName+"\x00")) || dataCount < 1 || dataOffset+dataCount > len(smb) {
		return nil, false
	}
	return smb[dataOffset : dataOffset+dataCount], true
}

// browserAnnouncement puts a browser announcement's fields into meta and
// returns the announced server name of a host announcement ([MS-BRWS]
// §2.2.1, §2.2.6): opcode, update count, periodicity, the 16-byte name, OS
// major and minor version, server type, browser version, signature, then a
// NUL-terminated comment.
func browserAnnouncement(meta map[string]string, d []byte) string {
	if len(d) < browserAnnouncementFixed {
		return ""
	}
	name := text(bytes.TrimRight(d[6:22], "\x00 "), 16)
	switch d[0] {
	case browserHostAnnouncement, browserLocalMasterAnnouncement:
		meta["netbios"] = "host_announcement"
		meta["os_version"] = strconv.Itoa(int(d[22])) + "." + strconv.Itoa(int(d[23]))
		if t := serverTypeNames(binary.LittleEndian.Uint32(d[24:])); t != "" {
			meta["server_type"] = t
		}
		comment, _, _ := bytes.Cut(d[browserAnnouncementFixed:], []byte{0})
		setText(meta, "comment", comment)
		return name
	case browserWorkgroupAnnouncement:
		meta["netbios"] = "workgroup_announcement"
		if name != "" {
			meta["workgroup"] = name
		}
	}
	return ""
}

func serverTypeNames(bits uint32) string {
	var out []string
	for _, t := range serverTypes {
		if bits&t.bit != 0 {
			out = append(out, t.name)
		}
	}
	return strings.Join(out, ",")
}

// nbName reads a first-level encoded NetBIOS name at off in msg (RFC 1001
// §14.1: 32 letters 'A' to 'P', a nibble each, then scope labels), following
// compression pointers backwards only, so a loop cannot occur. It returns
// the 15-character name without its padding, the suffix byte and the offset
// after the name.
func nbName(msg []byte, off int) (name string, suffix byte, next int, ok bool) {
	if off >= len(msg) {
		return "", 0, 0, false
	}
	if msg[off]&0xc0 == 0xc0 {
		if off+2 > len(msg) {
			return "", 0, 0, false
		}
		ptr := int(be16(msg[off:]) & 0x3fff)
		if ptr >= off {
			return "", 0, 0, false
		}
		name, suffix, _, ok = nbName(msg, ptr)
		return name, suffix, off + 2, ok
	}
	if msg[off] != nbEncodedNameSize || off+1+nbEncodedNameSize > len(msg) {
		return "", 0, 0, false
	}
	var raw [16]byte
	for i := range raw {
		hi, lo := msg[off+1+2*i]-'A', msg[off+2+2*i]-'A'
		if hi > 0xf || lo > 0xf {
			return "", 0, 0, false
		}
		raw[i] = hi<<4 | lo
	}
	next = off + 1 + nbEncodedNameSize
	for { // scope labels, up to the root
		if next >= len(msg) || msg[next]&0xc0 != 0 {
			return "", 0, 0, false
		}
		n := int(msg[next])
		next++
		if n == 0 {
			break
		}
		if next+n > len(msg) {
			return "", 0, 0, false
		}
		next += n
	}
	name = text(bytes.TrimRight(raw[:15], " \x00"), 15)
	return name, raw[15], next, name != ""
}

func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
