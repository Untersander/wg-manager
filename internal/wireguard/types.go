package wireguard

type Interface struct {
	Addresses  []string
	PrivateKey string
	ListenPort int
	MTU        int
}

type Peer struct {
	Name                string
	PublicKey           string
	PrivateKey          string
	PresharedKey        string
	AllowedIPs          []string
	PersistentKeepalive int
}

type Config struct {
	Interface Interface
	Peers     []Peer
}

type PeerRuntime struct {
	PublicKey            string
	Endpoint             string
	AllowedIPs           []string
	LatestHandshakeEpoch int64
	TransferRx           uint64
	TransferTx           uint64
}
