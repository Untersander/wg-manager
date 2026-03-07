use axum::{
    extract::{Path, State},
    http::{StatusCode, HeaderMap},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use askama::Template;
use serde::Deserialize;

use crate::{config::Config, nft, wg, peer};

mod templates;
use templates::{
    DashboardTemplate, InterfaceDetailTemplate, InterfacesTemplate, PeersTemplate,
};

/// Health check endpoint
pub async fn health() -> &'static str {
    "OK"
}

/// Dashboard - main page
pub async fn dashboard(State(_config): State<Config>) -> Result<Html<String>, AppError> {
    let interfaces = wg::list_interfaces()?;
    let nft_available = nft::check_availability();

    let template = DashboardTemplate {
        interfaces,
        nft_available,
    };

    Ok(Html(template.render()?))
}

/// List all WireGuard interfaces
pub async fn list_interfaces(State(_config): State<Config>) -> Result<Html<String>, AppError> {
    let interface_names = wg::list_interfaces()?;
    let mut interfaces = Vec::new();

    for name in interface_names {
        match wg::get_interface(&name) {
            Ok(iface) => interfaces.push(iface),
            Err(e) => {
                tracing::error!("Failed to get interface {}: {}", name, e);
            }
        }
    }

    let template = InterfacesTemplate { interfaces };
    Ok(Html(template.render()?))
}

/// Show details for a specific interface
pub async fn interface_detail(
    State(_config): State<Config>,
    Path(name): Path<String>,
) -> Result<Html<String>, AppError> {
    let interface = wg::get_interface(&name)?;
    let masquerade_enabled = nft::is_masquerade_enabled(&name).unwrap_or(false);

    let template = InterfaceDetailTemplate {
        interface,
        masquerade_enabled,
    };

    Ok(Html(template.render()?))
}

/// List peers for an interface
pub async fn list_peers(
    State(_config): State<Config>,
    Path(name): Path<String>,
) -> Result<Html<String>, AppError> {
    let interface = wg::get_interface(&name)?;
    let template = PeersTemplate { interface };
    Ok(Html(template.render()?))
}

#[derive(Deserialize)]
pub struct AddPeerForm {
    public_key: String,
    allowed_ips: String,
    endpoint: Option<String>,
}

/// Add a peer to an interface
pub async fn add_peer(
    State(_config): State<Config>,
    Path(name): Path<String>,
    Form(form): Form<AddPeerForm>,
) -> Result<Response, AppError> {
    let allowed_ips: Vec<String> = form
        .allowed_ips
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    wg::add_peer(
        &name,
        &form.public_key,
        &allowed_ips,
        form.endpoint.as_deref(),
    )?;

    tracing::info!("Added peer {} to interface {}", form.public_key, name);

    Ok(Redirect::to(&format!("/interfaces/{}", name)).into_response())
}

/// Delete a peer from an interface
pub async fn delete_peer(
    State(_config): State<Config>,
    Path((name, pubkey)): Path<(String, String)>,
) -> Result<Response, AppError> {
    wg::remove_peer(&name, &pubkey)?;

    tracing::info!("Removed peer {} from interface {}", pubkey, name);

    Ok(Redirect::to(&format!("/interfaces/{}", name)).into_response())
}

#[derive(Deserialize)]
pub struct MasqueradeForm {
    enabled: Option<String>,
}

/// Toggle masquerade for an interface
pub async fn toggle_masquerade(
    State(_config): State<Config>,
    Path(name): Path<String>,
    Form(form): Form<MasqueradeForm>,
) -> Result<Response, AppError> {
    let enable = form.enabled.is_some();

    if enable {
        nft::enable_masquerade(&name)?;
        tracing::info!("Enabled masquerade for {}", name);
    } else {
        nft::disable_masquerade(&name)?;
        tracing::info!("Disabled masquerade for {}", name);
    }

    Ok(Redirect::to(&format!("/interfaces/{}", name)).into_response())
}

#[derive(Deserialize)]
pub struct GeneratePeerForm {
    peer_name: String,
    allowed_ips: String,
    server_endpoint: String,
}

/// Show form to generate a new peer
pub async fn generate_peer_form(
    State(_config): State<Config>,
    Path(name): Path<String>,
) -> Result<Html<String>, AppError> {
    let _interface = wg::get_interface(&name)?;

    let template = templates::GeneratePeerTemplate {
        interface_name: name,
    };

    Ok(Html(template.render()?))
}

/// Generate a new peer with keys
pub async fn generate_peer(
    State(_config): State<Config>,
    Path(name): Path<String>,
    Form(form): Form<GeneratePeerForm>,
) -> Result<Html<String>, AppError> {
    let interface = wg::get_interface(&name)?;

    // Generate keypair
    let (private_key, public_key) = peer::generate_keypair()?;

    let allowed_ips: Vec<String> = form
        .allowed_ips
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Build peer config
    let config = peer::build_peer_config(
        &form.peer_name,
        &private_key,
        &interface.public_key,
        &form.server_endpoint,
        &allowed_ips,
    );

    // Add peer to interface (with public key only)
    wg::add_peer(
        &name,
        &public_key,
        &allowed_ips,
        None,
    )?;

    tracing::info!("Generated new peer {} for interface {}", form.peer_name, name);

    let template = templates::PeerConfigTemplate {
        interface_name: name,
        peer_name: form.peer_name,
        public_key: public_key.clone(),
        private_key: private_key.clone(),
        config: config.full_config.clone(),
    };

    Ok(Html(template.render()?))
}

/// Download peer configuration file
pub async fn download_peer_config(
    State(_config): State<Config>,
    Path((name, pubkey)): Path<(String, String)>,
) -> Result<(HeaderMap, String), AppError> {
    let interface = wg::get_interface(&name)?;

    // Find the peer
    let peer = interface
        .peers
        .iter()
        .find(|p| p.public_key == pubkey)
        .ok_or_else(|| anyhow::anyhow!("Peer not found"))?;

    // Note: In a production system, you'd store the generated config
    // For now, we'll generate a basic config based on peer info
    let config = format!(
        "[Interface]\nPrivateKey = <YOUR_PRIVATE_KEY>\nAddress = {}\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = {}\nEndpoint = <SERVER_IP>:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
        peer.allowed_ips.join(", "),
        interface.public_key
    );

    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", "text/plain; charset=utf-8".parse()?);
    headers.insert(
        "Content-Disposition",
        format!("attachment; filename=\"wg_peer_{}.conf\"", pubkey.chars().take(8).collect::<String>()).parse()?
    );

    Ok((headers, config))
}

/// Serve peer configuration as QR code (SVG)
pub async fn peer_qrcode(
    State(_config): State<Config>,
    Path((name, _pubkey)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    let interface = wg::get_interface(&name)?;

    // Generate dummy config for QR (in production, fetch from storage)
    let qr_content = format!(
        "WireGuard Peer\nInterface: {}\nServer Key: {}\n",
        name, &interface.public_key[..16]
    );

    // Generate QR code
    let code = qrcode::QrCode::new(&qr_content)
        .map_err(|e| anyhow::anyhow!("QR code generation failed: {}", e))?;

    let svg = code.render::<qrcode::render::svg::Color>()
        .min_dimensions(200, 200)
        .build();

    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", "image/svg+xml; charset=utf-8".parse()?);

    Ok((headers, svg))
}

#[derive(Deserialize)]
pub struct CreateInterfaceForm {
    name: String,
    listen_port: u16,
}

/// Show form to create a new interface
pub async fn create_interface_form(
    State(_config): State<Config>,
) -> Result<Html<String>, AppError> {
    let template = templates::CreateInterfaceTemplate;
    Ok(Html(template.render()?))
}

/// Create a new WireGuard interface
pub async fn create_interface(
    State(config): State<Config>,
    Form(form): Form<CreateInterfaceForm>,
) -> Result<Response, AppError> {
    // Validate interface name (alphanumeric + underscore only)
    if !form.name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(AppError(
            anyhow::anyhow!("Interface name must contain only alphanumeric characters and underscores")
        ));
    }

    wg::create_interface(&form.name, form.listen_port, &config.wireguard.config_dir)?;
    tracing::info!("Created new interface {}", form.name);

    Ok(Redirect::to("/interfaces").into_response())
}

/// Delete a WireGuard interface
pub async fn delete_interface(
    State(config): State<Config>,
    Path(name): Path<String>,
) -> Result<Response, AppError> {
    wg::delete_interface(&name, &config.wireguard.config_dir)?;
    tracing::info!("Deleted interface {}", name);

    Ok(Redirect::to("/interfaces").into_response())
}

// Error handling
pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("Application error: {}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Error: {}", self.0),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
