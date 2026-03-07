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
	DNS                 []string // per-peer override; empty = use default
	ClientAllowedIPs    []string // per-peer override; empty = use default
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
