package platform

import (
	"errors"
	"fmt"
	"net"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"
)

// PeerUser names the Unix user of the process at the other end of a Unix
// socket connection (SO_PEERCRED): the actor of kill-switch and scan
// events. Without a passwd entry it is "uid N".
func PeerUser(c net.Conn) (string, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return "", errors.New("peer credentials: not a Unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return "", fmt.Errorf("peer credentials: %w", err)
	}
	var cred *unix.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) { cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return "", fmt.Errorf("peer credentials: %w", err)
	}
	if serr != nil {
		return "", fmt.Errorf("peer credentials: %w", serr)
	}
	uid := strconv.FormatUint(uint64(cred.Uid), 10)
	if u, err := user.LookupId(uid); err == nil {
		return u.Username, nil
	}
	return "uid " + uid, nil
}
