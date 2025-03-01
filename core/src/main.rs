use std::net::SocketAddr;
use std::sync::Arc;
use axum::{Router, routing::get, http::{Method, HeaderName, HeaderValue}};
use tokio::net::TcpListener;
use tracing::{info, error, warn};
use dotenv::dotenv;
use std::env;
use tower_http::cors::{CorsLayer, Any};

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
    db_pool: sqlx::Pool<sqlx::Postgres>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv().ok();
    
    // Initialize logger with more detailed settings
    let env_filter = env::var("RUST_LOG")
        .unwrap_or_else(|_| "eldrin_core=debug,tower_http=debug,axum=debug".to_string());
        
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(true)
        .init();
        
    info!("Logger initialized with filter: {}", env_filter);
    
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
    match db::run_migrations(&db_pool).await {
        Ok(_) => info!("Database migrations completed successfully"),
        Err(e) => {
            // We'll continue even if migrations fail with "already exists" error
            // since we might have manually run the migrations already
            warn!("Database migration issue (continuing anyway): {}", e);
        }
    }
    
    // Initialize module manager with database support
    let mut module_manager = ModuleManager::with_database(db_pool.clone());
    
    if let Err(e) = module_manager.initialize().await {
        error!("Failed to initialize module manager: {}", e);
        panic!("Module manager initialization failed: {}", e);
    }
    
    // Initialize the user module
    if let Err(e) = modules::user::init(db_pool.clone()).await {
        error!("Failed to initialize user module: {}", e);
        panic!("User module initialization failed: {}", e);
    }
    
    let app_state = AppState {
        module_manager: Arc::new(tokio::sync::Mutex::new(module_manager)),
        db_pool: db_pool.clone(),
    };
    
    // Configure CORS
    // Get the Angular app URL from environment or use default
    let frontend_url = env::var("FRONTEND_URL")
        .unwrap_or_else(|_| "http://localhost:4200".to_string());
    
    let cors = CorsLayer::new()
        // Only allow requests from our Angular app
        .allow_origin(frontend_url.parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            HeaderName::from_static("content-type"),
            HeaderName::from_static("authorization"),
            HeaderName::from_static("x-requested-with"),
            HeaderName::from_static("accept"),
            HeaderName::from_static("origin"),
        ])
        .allow_credentials(true);
    
    // Build our application with routes
    let app = Router::new()
        .route("/", get(|| async { "Hello, Eldrin!" }))
        .nest("/api", api::routes())
        .nest("/api/modules", api::module_routes())
        .with_state(app_state)
        .layer(cors.clone());
    
    // Create a router for the user API 
    let user_app = Router::new()
        .nest("/api/users", modules::user::handlers::user_routes(db_pool.clone()))
        .layer(cors.clone());
    
    // Create a router for OAuth callbacks
    let auth_app = Router::new()
        .route("/auth/:provider/callback", get(modules::user::handlers::oauth_callback_handler))
        .layer(cors.clone());
        
    // Combine the routers
    let app = app.merge(user_app).merge(auth_app);
    
    // Run the server
    let addr = SocketAddr::new(server_host.parse()?, server_port);
    info!("Listening on {}", addr);
    
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}