package wireguard

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func (r Runner) GenerateKeyPairFromPrivate(privateKey string) (string, string, error) {
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
