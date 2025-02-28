use crate::modules::user::auth::{AuthError, TokenManager, TokenType};
use crate::modules::user::repository::UserRepository;
use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use sqlx::types::Uuid;
use std::sync::Arc;

/// Manages magic link authentication
pub struct MagicLinkManager {
    token_manager: Arc<TokenManager>,
    user_repo: UserRepository,
    expiry: Duration,
}

impl MagicLinkManager {
    /// Create a new magic link manager
    pub fn new(
        pool: PgPool,
        token_manager: Arc<TokenManager>,
        expiry: Option<Duration>,
    ) -> Self {
        Self {
            token_manager,
            user_repo: UserRepository::new(pool),
            expiry: expiry.unwrap_or_else(|| Duration::minutes(15)),
        }
    }
    
    /// Generate a magic link token for email
    pub async fn generate_magic_link(
        &self,
        email: &str,
        create_user_if_not_exists: bool,
    ) -> Result<String, AuthError> {
        // Look up user by email
        let user = self.user_repo.find_by_email(email).await
            .map_err(AuthError::DatabaseError)?;
        
        let user_id = if let Some(user) = user {
            user.id
        } else if create_user_if_not_exists {
            // Create a provisional user
            let username = format!("user_{}", Uuid::new_v4());
            let new_user = self.user_repo.create_provisional_user(email, &username).await
                .map_err(AuthError::DatabaseError)?;
            new_user.id
        } else {
            return Err(AuthError::UserNotFound);
        };
        
        // Generate a random token
        let token = self.token_manager.generate_random_token(32);
        
        // Store the token
        let expires_at = Utc::now() + self.expiry;
        
        let metadata = serde_json::json!({
            "email": email,
        });
        
        self.token_manager.store_token(
            Some(user_id),
            &token,
            TokenType::MagicLink,
            expires_at,
            Some(metadata),
        ).await?;
        
        Ok(token)
    }
    
    /// Verify a magic link token
    pub async fn verify_magic_link(&self, token: &str) -> Result<Uuid, AuthError> {
        let (token_id, user_id) = self.token_manager.verify_stored_token(token, TokenType::MagicLink).await?;
        
        let user_id = user_id.ok_or(AuthError::InvalidToken)?;
        
        // Mark the token as used
        self.token_manager.mark_token_used(token_id).await?;
        
        // Look up the user
        let user = self.user_repo.find_by_id(user_id).await
            .map_err(AuthError::DatabaseError)?
            .ok_or(AuthError::UserNotFound)?;
        
        // Update the user's last login
        self.user_repo.update_last_login(user_id).await
            .map_err(AuthError::DatabaseError)?;
        
        Ok(user_id)
    }
    
    /// Send a magic link email (stub for now)
    pub async fn send_magic_link_email(&self, email: &str, token: &str, base_url: &str) -> Result<(), AuthError> {
        // In a real implementation, this would send an email with the magic link
        let magic_link = format!("{}/auth/verify-magic-link?token={}", base_url, token);
        
        tracing::info!("Magic link for {}: {}", email, magic_link);
        
        // Here you would use an email service to send the actual email
        
        Ok(())
    }
}