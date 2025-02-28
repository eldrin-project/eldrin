pub mod models;
mod repository;
mod service;
pub mod handlers;
pub mod auth;

pub use models::{User, UserRole, UserProfile};
pub use service::UserService;

/// Initialize the user module
pub async fn init(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("Initializing user management module");
    
    // Create admin user if it doesn't exist
    let admin_email = std::env::var("ADMIN_EMAIL").unwrap_or_else(|_| "admin@example.com".to_string());
    let admin_password = std::env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "adminpassword".to_string());
    
    let pool_clone = pool.clone();
    let user_service = service::UserService::new(pool);
    
    // Check if admin user exists
    let admin_exists = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)",
        admin_email
    )
    .fetch_one(&pool_clone)
    .await?;
    
    if !admin_exists.unwrap_or(false) {
        tracing::info!("Creating admin user with email: {}", admin_email);
        
        // Create admin user
        let _ = user_service.register_email_password(
            admin_email,
            admin_password,
            Some("admin".to_string()),
        ).await?;
    }
    
    Ok(())
}