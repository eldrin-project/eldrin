use std::net::SocketAddr;
use std::sync::Arc;
use axum::{Router, routing::get};
use tokio::net::TcpListener;
use tracing::info;

mod api;
mod models;
mod services;
mod repository;
mod utils;
mod modules;

use modules::ModuleManager;

#[derive(Clone)]
pub struct AppState {
    module_manager: Arc<tokio::sync::Mutex<ModuleManager>>,
}

#[tokio::main]
async fn main() {
    // Initialize logger
    tracing_subscriber::fmt::init();
    
    // Initialize module manager
    let mut module_manager = ModuleManager::new();
    if let Err(e) = module_manager.initialize() {
        panic!("Failed to initialize module manager: {}", e);
    }
    
    let app_state = AppState {
        module_manager: Arc::new(tokio::sync::Mutex::new(module_manager)),
    };
    
    // Build our application with routes
    let app = Router::new()
        .route("/", get(|| async { "Hello, Eldrin!" }))
        .nest("/api", api::module_routes())
        .with_state(app_state);
    
    // Run the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("Listening on {}", addr);
    
    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}