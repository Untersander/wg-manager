package handlers

import "wg-manager/internal/wireguard"

// RunnerIface abstracts the wireguard runner for testability.
type RunnerIface interface {
	GenerateKeyPair() (privateKey, publicKey string, err error)
	GenerateKeyPairFromPrivate(privateKey string) (string, string, error)
	SyncConfig() error
	ShowRuntime() (map[string]wireguard.PeerRuntime, error)
}
