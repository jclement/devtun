package probe

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Protocol markers framing the prober's output stream. They are chosen to be
// improbable in the output of any listing tool.
const (
	markReady   = "@@DEVTUN-READY"
	markScan    = "@@DEVTUN-SCAN"
	markSockMap = "@@DEVTUN-SOCKMAP"
	markEnd     = "@@DEVTUN-END"
	markError   = "@@DEVTUN-ERROR"
)

// proberScript is piped to the remote `sh -s`. It writes nothing to disk, picks
// the best available listing tool, then loops emitting framed scans until the
// session is torn down.
//
// Kept deliberately POSIX: no arrays, no [[ ]], no local. It must run under
// dash, busybox ash and ksh as well as bash.
const proberScript = `
LC_ALL=C; export LC_ALL
PATH=$PATH:/usr/sbin:/sbin:/usr/local/sbin; export PATH

uname_s=$(uname -s 2>/dev/null || echo unknown)

mode=
if [ "$uname_s" = Darwin ]; then
	if command -v lsof >/dev/null 2>&1; then mode=lsof; fi
fi
if [ -z "$mode" ] && command -v ss >/dev/null 2>&1 && ss -ltn >/dev/null 2>&1; then
	mode=ss
fi
if [ -z "$mode" ] && command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP -sTCP:LISTEN >/dev/null 2>&1; then
	mode=lsof
fi
if [ -z "$mode" ] && command -v netstat >/dev/null 2>&1 && netstat -ltn >/dev/null 2>&1; then
	mode=netstat
fi
if [ -z "$mode" ] && [ -r /proc/net/tcp ]; then
	mode=proc
fi
if [ -z "$mode" ]; then
	echo "@@DEVTUN-ERROR no usable port discovery tool (need ss, lsof, netstat or /proc/net/tcp)"
	exit 3
fi

echo "@@DEVTUN-READY 1 $mode $uname_s"

while :; do
	echo "@@DEVTUN-SCAN"
	case $mode in
	ss)
		ss -ltnp 2>/dev/null
		;;
	lsof)
		lsof -nP -iTCP -sTCP:LISTEN -Fpcn 2>/dev/null
		;;
	netstat)
		netstat -ltnp 2>/dev/null
		;;
	proc)
		cat /proc/net/tcp /proc/net/tcp6 2>/dev/null
		echo "@@DEVTUN-SOCKMAP"
		ls -l /proc/[0-9]*/fd/ 2>/dev/null | grep -e 'socket:\[' -e '^/proc/'
		;;
	esac
	echo "@@DEVTUN-END"
	sleep __INTERVAL__
done
`

// Script renders the prober for the given scan interval.
func Script(interval time.Duration) string {
	secs := interval.Seconds()
	if secs < 0.1 {
		secs = 0.1
	}
	// Busybox sleep only understands whole seconds, so avoid a decimal point
	// whenever the interval is integral.
	var s string
	if secs == float64(int(secs)) {
		s = fmt.Sprint(int(secs))
	} else {
		s = strconv.FormatFloat(secs, 'f', 1, 64)
	}
	return strings.ReplaceAll(proberScript, "__INTERVAL__", s)
}

// CmdlineScript renders a one-shot script that prints the command line of each
// requested pid as "<pid>\t<cmdline>". Unknown pids are simply omitted.
//
// It is run in its own short-lived SSH session rather than being folded into
// the scan loop: command lines never change for a given pid, so fetching them
// once on demand keeps the steady-state scan small even on a busy host.
func CmdlineScript(pids []int) string {
	var b strings.Builder
	b.WriteString("LC_ALL=C; export LC_ALL\n")
	b.WriteString("for p in")
	for _, p := range pids {
		if p > 0 {
			fmt.Fprintf(&b, " %d", p)
		}
	}
	b.WriteString("; do\n")
	// /proc is the cheap path; ps is the portable fallback for macOS and BSD.
	b.WriteString(`	c=
	if [ -r "/proc/$p/cmdline" ]; then
		c=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)
	fi
	if [ -z "$c" ]; then
		c=$(ps -o command= -p "$p" 2>/dev/null | head -n1)
	fi
	if [ -z "$c" ] && [ -r "/proc/$p/comm" ]; then
		c=$(cat "/proc/$p/comm" 2>/dev/null)
	fi
	if [ -n "$c" ]; then
		printf '%s\t%s\n' "$p" "$c"
	fi
done
`)
	return b.String()
}

// ParseCmdlines parses the output of CmdlineScript.
func ParseCmdlines(out string) map[int]string {
	res := map[int]string{}
	for _, line := range strings.Split(out, "\n") {
		pidStr, cmd, ok := strings.Cut(strings.TrimRight(line, "\r"), "\t")
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(pidStr))
		if err != nil {
			continue
		}
		cmd = strings.Join(strings.Fields(cmd), " ")
		if cmd != "" {
			res[pid] = cmd
		}
	}
	return res
}
