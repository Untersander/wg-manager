mod auth;
mod config;
mod nft;
mod peer;
mod routes;
mod wg;

use anyhow::Result;
use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "wg_manager=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::load()?;
    tracing::info!("Configuration loaded successfully");

    // Build application router
    let app = Router::new()
        .route("/", get(routes::dashboard))
        .route("/health", get(routes::health))
        .route("/interfaces", get(routes::list_interfaces))
        .route("/interfaces/create", get(routes::create_interface_form))
        .route("/interfaces/create", post(routes::create_interface))
        .route("/interfaces/:name", get(routes::interface_detail))
        .route("/interfaces/:name/delete", post(routes::delete_interface))
        .route("/interfaces/:name/peers", get(routes::list_peers))
        .route("/interfaces/:name/peers/add", post(routes::add_peer))
        .route("/interfaces/:name/peers/generate", get(routes::generate_peer_form))
        .route("/interfaces/:name/peers/generate", post(routes::generate_peer))
        .route("/interfaces/:name/peers/:pubkey/delete", post(routes::delete_peer))
        .route("/interfaces/:name/peers/:pubkey/config", get(routes::download_peer_config))
        .route("/interfaces/:name/peers/:pubkey/qrcode", get(routes::peer_qrcode))
        .route("/interfaces/:name/masquerade", post(routes::toggle_masquerade))
        .with_state(config.clone())
        // Authentication disabled for now
        // .layer(axum::middleware::from_fn_with_state(config.clone(), auth::basic_auth_middleware))
        .layer(TraceLayer::new_for_http());

    // Start server
    let addr: SocketAddr = "0.0.0.0:8080".parse()?;
    tracing::info!("Starting WireGuard Manager on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
