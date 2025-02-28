use crate::modules::user::auth::{AuthError, TokenManager, TokenType};
use crate::modules::user::repository::UserRepository;
use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use sqlx::types::Uuid;
use std::sync::Arc;
use rand::Rng;

/// Manages SMS code authentication
pub struct SmsManager {
    token_manager: Arc<TokenManager>,
    user_repo: UserRepository,
    expiry: Duration,
}

impl SmsManager {
    /// Create a new SMS manager
    pub fn new(
        pool: PgPool,
        token_manager: Arc<TokenManager>,
        expiry: Option<Duration>,
    ) -> Self {
        Self {
            token_manager,
            user_repo: UserRepository::new(pool),
            expiry: expiry.unwrap_or_else(|| Duration::minutes(10)),
        }
    }
    
    /// Generate an SMS verification code
    pub async fn generate_sms_code(
        &self,
        phone: &str,
        create_user_if_not_exists: bool,
    ) -> Result<String, AuthError> {
        // Look up user by phone
        let user = self.user_repo.find_by_phone(phone).await
            .map_err(AuthError::DatabaseError)?;
        
        let user_id = if let Some(user) = user {
            user.id
        } else if create_user_if_not_exists {
            // Create a provisional user
            let username = format!("user_{}", Uuid::new_v4());
            let new_user = self.user_repo.create_provisional_user_with_phone(phone, &username).await
                .map_err(AuthError::DatabaseError)?;
            new_user.id
        } else {
            return Err(AuthError::UserNotFound);
        };
        
        // Generate a random 6-digit code
        let code = self.generate_code(6);
        
        // Store the code
        let expires_at = Utc::now() + self.expiry;
        
        let metadata = serde_json::json!({
            "phone": phone,
        });
        
        self.token_manager.store_token(
            Some(user_id),
            &code,
            TokenType::SmsVerification,
            expires_at,
            Some(metadata),
        ).await?;
        
        Ok(code)
    }
    
    /// Verify an SMS code
    pub async fn verify_sms_code(&self, code: &str) -> Result<Uuid, AuthError> {
        let (token_id, user_id) = self.token_manager.verify_stored_token(code, TokenType::SmsVerification).await?;
        
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
    
    /// Send an SMS code (stub for now)
    pub async fn send_sms_code(&self, phone: &str, code: &str) -> Result<(), AuthError> {
        // In a real implementation, this would send an SMS with the code
        tracing::info!("SMS code for {}: {}", phone, code);
        
        // Here you would use an SMS service (Twilio, etc.) to send the actual SMS
        
        Ok(())
    }
    
    // Helper to generate a random code
    fn generate_code(&self, length: usize) -> String {
        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| rng.gen_range(0..10).to_string())
            .collect()
    }
}