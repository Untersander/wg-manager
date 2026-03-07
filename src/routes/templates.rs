use askama::Template;
use crate::wg::Interface;

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub interfaces: Vec<String>,
    pub nft_available: bool,
}

#[derive(Template)]
#[template(path = "interfaces.html")]
pub struct InterfacesTemplate {
    pub interfaces: Vec<Interface>,
}

#[derive(Template)]
#[template(path = "interface_detail.html")]
pub struct InterfaceDetailTemplate {
    pub interface: Interface,
    pub masquerade_enabled: bool,
}

#[derive(Template)]
#[template(path = "peers.html")]
pub struct PeersTemplate {
    pub interface: Interface,
}

#[derive(Template)]
#[template(path = "generate_peer.html")]
pub struct GeneratePeerTemplate {
    pub interface_name: String,
}

#[derive(Template)]
#[template(path = "peer_config.html")]
pub struct PeerConfigTemplate {
    pub interface_name: String,
    pub peer_name: String,
    pub public_key: String,
    pub private_key: String,
    pub config: String,
}

#[derive(Template)]
#[template(path = "create_interface.html")]
pub struct CreateInterfaceTemplate;
