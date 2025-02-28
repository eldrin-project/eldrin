use std::net::SocketAddr;
use std::sync::Arc;
use axum::{Router, routing::get};
use tokio::net::TcpListener;
use tracing::{info, error};
use dotenv::dotenv;
use std::env;

mod api;
mod models;
mod services;
mod repository;
mod utils;
mod modules;

use modules::ModuleManager;
use utils::db;

#[derive(Clone)]
pub struct AppState {
    module_manager: Arc<tokio::sync::Mutex<ModuleManager>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv().ok();
    
    // Initialize logger
    tracing_subscriber::fmt::init();
    
    // Get database URL from environment variables
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://eldrin:eldrin_password@localhost:5432/eldrin_dev".to_string());
    
    // Get server host and port from environment variables
    let server_host = env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let server_port = env::var("SERVER_PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()
        .expect("SERVER_PORT must be a valid port number");
    
    // Connect to the database
    let db_pool = match db::create_db_pool(&database_url).await {
        Ok(pool) => pool,
        Err(e) => {
            error!("Failed to connect to database: {}", e);
            panic!("Database connection failed");
        }
    };
    
    // Run database migrations
    if let Err(e) = db::run_migrations(&db_pool).await {
        error!("Failed to run database migrations: {}", e);
        panic!("Database migrations failed");
    }
    
    // Initialize module manager with database support
    let mut module_manager = ModuleManager::with_database(db_pool);
    
    if let Err(e) = module_manager.initialize().await {
        error!("Failed to initialize module manager: {}", e);
        panic!("Module manager initialization failed: {}", e);
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
    let addr = SocketAddr::new(server_host.parse()?, server_port);
    info!("Listening on {}", addr);
    
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}