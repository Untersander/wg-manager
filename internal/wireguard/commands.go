package wireguard

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type Runner struct {
	InterfaceName string
	ConfigPath    string
}

func (r Runner) GenerateKeyPair() (privateKey string, publicKey string, err error) {
	privOut, err := runCmd("wg", "genkey")
	if err != nil {
		return "", "", err
	}
	privateKey = strings.TrimSpace(privOut)

	pubCmd := exec.Command("wg", "pubkey")
	pubCmd.Stdin = strings.NewReader(privateKey)
	var pubStdout bytes.Buffer
	var pubStderr bytes.Buffer
	pubCmd.Stdout = &pubStdout
	pubCmd.Stderr = &pubStderr
	if err := pubCmd.Run(); err != nil {
		return "", "", fmt.Errorf("wg pubkey failed: %w: %s", err, strings.TrimSpace(pubStderr.String()))
	}

	return privateKey, strings.TrimSpace(pubStdout.String()), nil
}

func (r Runner) EnsureInterfaceUp() error {
	if _, err := runCmd("wg", "show", r.InterfaceName); err == nil {
		return nil
	}
	_, err := runCmd("wg-quick", "up", r.ConfigPath)
	return err
}

func (r Runner) SyncConfig() error {
	strip, err := runCmd("wg-quick", "strip", r.ConfigPath)
	if err != nil {
		return err
	}
	tmp := filepath.Join(os.TempDir(), r.InterfaceName+"-sync.conf")
	if err := os.WriteFile(tmp, []byte(strip), 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)

	if _, err := runCmd("wg", "syncconf", r.InterfaceName, tmp); err == nil {
		return nil
	}

	_, _ = runCmd("wg-quick", "down", r.ConfigPath)
	_, err = runCmd("wg-quick", "up", r.ConfigPath)
	return err
}

func (r Runner) ShowRuntime() (map[string]PeerRuntime, error) {
	out, err := runCmd("wg", "show", r.InterfaceName, "dump")
	if err != nil {
		if strings.Contains(err.Error(), "No such device") {
			return map[string]PeerRuntime{}, nil
		}
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) <= 1 {
		return map[string]PeerRuntime{}, nil
	}

	runtime := make(map[string]PeerRuntime)
	for i := 1; i < len(lines); i++ {
		cols := strings.Split(lines[i], "\t")
		if len(cols) < 8 {
			continue
		}

		handshake, _ := strconv.ParseInt(cols[4], 10, 64)
		rx, _ := strconv.ParseUint(cols[5], 10, 64)
		tx, _ := strconv.ParseUint(cols[6], 10, 64)

		runtime[cols[0]] = PeerRuntime{
			PublicKey:            cols[0],
			Endpoint:             cols[2],
			AllowedIPs:           splitList(cols[3]),
			LatestHandshakeEpoch: handshake,
			TransferRx:           rx,
			TransferTx:           tx,
		}
	}
	return runtime, nil
}

func ApplyMasquerade(egressInterface string) error {
	if strings.TrimSpace(egressInterface) == "" {
		return errors.New("egress interface cannot be empty")
	}

	nftCmds := []string{
		"add table inet wg_manager",
		"flush table inet wg_manager",
		"add chain inet wg_manager postrouting { type nat hook postrouting priority srcnat; policy accept; }",
		fmt.Sprintf("add rule inet wg_manager postrouting oifname %q ip saddr 10.0.0.0/8 masquerade", egressInterface),
		fmt.Sprintf("add rule inet wg_manager postrouting oifname %q ip6 saddr fd00::/8 masquerade", egressInterface),
	}

	for _, cmd := range nftCmds {
		if _, err := runCmd("nft", cmd); err != nil {
			return err
		}
	}
	return nil
}

func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}
