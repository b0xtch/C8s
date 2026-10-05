package sessionagent

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/session"
	"github.com/confidential-dot-ai/c8s/pkg/session/disclosure"
)

func TestSchemaGuard(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	own := SchemaGuard{Disclosure: write("disclosure.json", disclosure.Document()), Bind: write("bind.json", session.BindSchema())}
	if err := own.Check(); err != nil {
		t.Fatalf("an image with this agent's schemas: %v", err)
	}
	if err := (SchemaGuard{}).Check(); err != nil {
		t.Fatalf("no file to check: %v", err)
	}
	for name, guard := range map[string]SchemaGuard{
		"another disclosure schema": {Disclosure: write("d2.json", append(disclosure.Document(), ' ')), Bind: own.Bind},
		"another bind schema":       {Disclosure: own.Disclosure, Bind: write("b2.json", []byte(strings.Replace(string(session.BindSchema()), `"start"`, `"start","fork"`, 1)))},
		"the two swapped":           {Disclosure: own.Bind, Bind: own.Disclosure},
		"no disclosure schema":      {Disclosure: filepath.Join(dir, "absent"), Bind: own.Bind},
		"an empty bind schema":      {Disclosure: own.Disclosure, Bind: write("empty.json", nil)},
	} {
		if err := guard.Check(); err == nil {
			t.Errorf("%s: the agent would serve", name)
		}
	}
}

func TestConsoleGuard(t *testing.T) {
	for name, tc := range map[string]struct {
		consoles string
		serves   bool
	}{
		"no console at all":        {"", true},
		"the null console":         {"ttynull0             -W- (EC    )  242:0\n", true},
		"a serial console":         {"ttyS0                -W- (EC p a)    4:64\n", false},
		"a virtio console":         {"hvc0                 -W- (EC p  )  229:0\n", false},
		"the virtual terminal":     {"tty0                 -WU (EC    )    4:1\n", false},
		"a network console":        {"netcon0              -W- (E     )\n", false},
		"the null console and one": {"ttynull0             -W- (EC    )  242:0\nhvc0                 -W- (E  p  )  229:0\n", false},
		"a name that begins alike": {"ttynullx0            -W- (EC    )  242:0\n", false},
	} {
		path := filepath.Join(t.TempDir(), "consoles")
		if err := os.WriteFile(path, []byte(tc.consoles), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := (ConsoleGuard{Consoles: path}).Check(); (err == nil) != tc.serves {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := (ConsoleGuard{Consoles: filepath.Join(t.TempDir(), "absent")}).Check(); err == nil {
		t.Error("a guest that cannot list its consoles would serve")
	}
}

// kernelConfig reads a resolved kernel configuration: every symbol that is
// set, without its CONFIG_ prefix.
func kernelConfig(t *testing.T, path string) map[string]string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	config := map[string]string{}
	lines := bufio.NewScanner(file)
	for lines.Scan() {
		if symbol, value, ok := strings.Cut(lines.Text(), "="); ok && strings.HasPrefix(symbol, "CONFIG_") {
			config[strings.TrimPrefix(symbol, "CONFIG_")] = value
		}
	}
	if err := lines.Err(); err != nil || len(config) < 1000 {
		t.Fatalf("%s holds %d symbols: %v", path, len(config), err)
	}
	return config
}

// A locked image's kernel has one console, the one that discards. The
// snapshot is that kernel's whole configuration as the image builder
// resolved it from this profile's fragment, and an image's manifest carries
// its digest. The agent checks the running kernel's consoles too: this holds
// the build to the same rule, drivers that register no console until a host
// attaches a device included.
func TestLockedKernelHasNoConsole(t *testing.T) {
	const kernels = "../../../session-guest-image/kernel/"
	locked := kernelConfig(t, kernels+"config-x86_64-session.snapshot")
	for _, symbol := range []string{
		"VT", "VT_CONSOLE", "VGA_CONSOLE", "FRAMEBUFFER_CONSOLE", "FB", "DRM",
		"VIRTIO_CONSOLE", "HVC_DRIVER", "SERIAL_8250", "SERIAL_CORE", "TTY_PRINTK",
		"EARLY_PRINTK", "SERIAL_EARLYCON", "EFI_EARLYCON", "X86_VERBOSE_BOOTUP",
		"NETCONSOLE", "ACPI_SPCR_TABLE", "PSTORE", "KGDB",
	} {
		if value, set := locked[symbol]; set {
			t.Errorf("the locked kernel has CONFIG_%s=%s", symbol, value)
		}
	}
	for _, symbol := range []string{"NULL_TTY", "NULL_TTY_DEFAULT_CONSOLE"} {
		if locked[symbol] != "y" {
			t.Errorf("the locked kernel has CONFIG_%s=%q, want y: with no console at all a program cannot open /dev/console", symbol, locked[symbol])
		}
	}
	// A console driver this test has not heard of names itself one. Of the
	// four that do and are none: the null console, two log levels, and a slot
	// in the fixed map that x86 always reserves and nothing here fills.
	known := map[string]bool{
		"NULL_TTY_DEFAULT_CONSOLE": true, "CONSOLE_LOGLEVEL_DEFAULT": true, "CONSOLE_LOGLEVEL_QUIET": true, "FIX_EARLYCON_MEM": true,
	}
	for symbol, value := range locked {
		for _, word := range []string{"CONSOLE", "EARLYCON", "EARLY_PRINTK"} {
			if strings.Contains(symbol, word) && !known[symbol] {
				t.Errorf("the locked kernel has CONFIG_%s=%s: is it a console a host could read?", symbol, value)
			}
		}
	}
	// The dev kernel is the one with a console, which is what tells the two
	// snapshots apart.
	if dev := kernelConfig(t, kernels+"config-x86_64-session-dev.snapshot"); dev["VIRTIO_CONSOLE"] != "y" || dev["SERIAL_8250_CONSOLE"] != "y" {
		t.Error("the dev kernel has no console: the two snapshots are no longer told apart")
	}
}

// A guest checks its devices and its console once, before it serves, and
// its binds rest on that: the kernel takes no device a host adds later, and
// loads no code that could add a console or a driver. Both fragments say so,
// and this holds the two kernels' resolved configurations to it.
func TestGuestKernelTakesNoDeviceAndNoCodeOnceItRuns(t *testing.T) {
	const kernels = "../../../session-guest-image/kernel/"
	for _, name := range []string{"config-x86_64-session.snapshot", "config-x86_64-session-dev.snapshot"} {
		config := kernelConfig(t, kernels+name)
		for _, symbol := range []string{"HOTPLUG_PCI", "HOTPLUG_PCI_PCIE", "HOTPLUG_PCI_ACPI", "PCIEPORTBUS", "MODULES", "MEMORY_HOTPLUG"} {
			if value, set := config[symbol]; set {
				t.Errorf("%s: the kernel has CONFIG_%s=%s, and a guest's bind rests on a check made before it served", name, symbol, value)
			}
		}
	}
	for _, name := range []string{"session.config", "session-dev.config"} {
		fragment, err := os.ReadFile(kernels + name)
		if err != nil {
			t.Fatal(err)
		}
		common, _, marked := strings.Cut(string(fragment), "# end of common\n")
		if !marked {
			t.Fatalf("%s has no end of its common block", name)
		}
		for _, line := range []string{"# CONFIG_HOTPLUG_PCI is not set\n", "# CONFIG_PCIEPORTBUS is not set\n", "# CONFIG_MODULES is not set\n"} {
			if !strings.Contains(common, line) {
				t.Errorf("%s does not say %q in the block both kernels share", name, strings.TrimSpace(line))
			}
		}
	}
}

// The agent asks the kernel for its listening TCP sockets through sock_diag,
// so both kernels answer it for TCP. They answer it for nothing else, and
// close no socket through it: what a sandbox's code can ask the kernel is no
// more than the agent's check needs.
func TestGuestKernelAnswersSockDiagForTCPAlone(t *testing.T) {
	const kernels = "../../../session-guest-image/kernel/"
	for _, name := range []string{"config-x86_64-session.snapshot", "config-x86_64-session-dev.snapshot"} {
		config := kernelConfig(t, kernels+name)
		for _, symbol := range []string{"INET_DIAG", "INET_TCP_DIAG"} {
			if config[symbol] != "y" {
				t.Errorf("%s: the kernel has CONFIG_%s=%q, and the agent asks it for its listening sockets", name, symbol, config[symbol])
			}
		}
		for _, symbol := range []string{"INET_UDP_DIAG", "INET_RAW_DIAG", "INET_DIAG_DESTROY", "INET_MPTCP_DIAG", "INET_SCTP_DIAG", "UNIX_DIAG", "NETLINK_DIAG", "PACKET_DIAG"} {
			if value, set := config[symbol]; set {
				t.Errorf("%s: the kernel has CONFIG_%s=%s, which nothing in the guest asks for", name, symbol, value)
			}
		}
	}
	for _, name := range []string{"session.config", "session-dev.config"} {
		fragment, err := os.ReadFile(kernels + name)
		if err != nil {
			t.Fatal(err)
		}
		common, _, marked := strings.Cut(string(fragment), "# end of common\n")
		if !marked {
			t.Fatalf("%s has no end of its common block", name)
		}
		for _, line := range []string{"CONFIG_INET_DIAG=y\n", "CONFIG_INET_TCP_DIAG=y\n", "# CONFIG_INET_UDP_DIAG is not set\n", "# CONFIG_INET_DIAG_DESTROY is not set\n"} {
			if !strings.Contains(common, line) {
				t.Errorf("%s does not say %q in the block both kernels share", name, strings.TrimSpace(line))
			}
		}
	}
}

// The guest's packet filter is its nftables ruleset and nothing beside it:
// no iptables table of the old kind, and no xtables match inside nftables.
// The agent lists the ruleset once and from then on asks the kernel for its
// generation, which moves with every change to an nftables ruleset, so the
// check covers the filter only while nothing else filters. Both fragments
// say so, and this holds the two kernels' resolved configurations to it.
func TestGuestKernelFiltersWithNftablesAlone(t *testing.T) {
	const kernels = "../../../session-guest-image/kernel/"
	for _, name := range []string{"config-x86_64-session.snapshot", "config-x86_64-session-dev.snapshot"} {
		config := kernelConfig(t, kernels+name)
		if config["NF_TABLES"] != "y" {
			t.Errorf("%s: the kernel has no nftables", name)
		}
		for _, symbol := range []string{
			"NETFILTER_XTABLES_LEGACY", "NFT_COMPAT",
			"IP_NF_IPTABLES_LEGACY", "IP6_NF_IPTABLES_LEGACY", "IP_NF_ARPTABLES", "BRIDGE_NF_EBTABLES", "BRIDGE_NF_EBTABLES_LEGACY",
			"IP_NF_FILTER", "IP_NF_MANGLE", "IP_NF_RAW", "IP_NF_NAT", "IP_NF_SECURITY", "IP_NF_ARPFILTER",
			"IP6_NF_FILTER", "IP6_NF_MANGLE", "IP6_NF_RAW", "IP6_NF_NAT", "IP6_NF_SECURITY",
		} {
			if value, set := config[symbol]; set {
				t.Errorf("%s: the kernel has CONFIG_%s=%s: a packet filter beside nftables, which the ruleset's generation says nothing of", name, symbol, value)
			}
		}
	}
	for _, name := range []string{"session.config", "session-dev.config"} {
		fragment, err := os.ReadFile(kernels + name)
		if err != nil {
			t.Fatal(err)
		}
		common, _, marked := strings.Cut(string(fragment), "# end of common\n")
		if !marked {
			t.Fatalf("%s has no end of its common block", name)
		}
		for _, line := range []string{"# CONFIG_NETFILTER_XTABLES_LEGACY is not set\n", "# CONFIG_NFT_COMPAT is not set\n"} {
			if !strings.Contains(common, line) {
				t.Errorf("%s does not say %q in the block both kernels share", name, strings.TrimSpace(line))
			}
		}
	}
}
