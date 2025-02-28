use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use sqlx::types::Uuid;
use std::sync::Arc;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use crate::modules::user::models::User;
use crate::modules::user::auth::AuthError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    Access,
    Refresh,
    MagicLink,
    PasswordReset,
    EmailVerification,
    SmsVerification,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Subject (user ID)
    pub sub: String,
    
    /// Issued at
    pub iat: i64,
    
    /// Expiration time
    pub exp: i64,
    
    /// Token type
    pub token_type: TokenType,
    
    /// Optional token ID (for revocation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    
    /// Optional email (for verification tokens)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    
    /// Optional phone (for verification tokens)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
}

pub struct TokenManager {
    pool: PgPool,
    jwt_secret: String,
    pub access_token_expiry: Duration,
    pub refresh_token_expiry: Duration,
}

impl TokenManager {
    /// Create a new token manager
    pub fn new(
        pool: PgPool, 
        jwt_secret: String,
        access_token_expiry: Option<Duration>,
        refresh_token_expiry: Option<Duration>,
    ) -> Self {
        Self {
            pool,
            jwt_secret,
            access_token_expiry: access_token_expiry.unwrap_or_else(|| Duration::hours(1)),
            refresh_token_expiry: refresh_token_expiry.unwrap_or_else(|| Duration::days(7)),
        }
    }
    
    /// Generate a JWT token for a user
    pub fn generate_jwt(&self, user: &User, token_type: TokenType) -> Result<String, AuthError> {
        let now = Utc::now();
        let expiry = match token_type {
            TokenType::Access => now + self.access_token_expiry,
            TokenType::Refresh => now + self.refresh_token_expiry,
            _ => now + Duration::minutes(15), // Default for other token types
        };
        
        let claims = TokenClaims {
            sub: user.id.to_string(),
            iat: now.timestamp(),
            exp: expiry.timestamp(),
            token_type,
            jti: None,
            email: user.email.clone(),
            phone: user.phone.clone(),
        };
        
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )?;
        
        Ok(token)
    }
    
    /// Verify a JWT token
    pub fn verify_jwt(&self, token: &str, expected_type: Option<TokenType>) -> Result<TokenClaims, AuthError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        
        let token_data = decode::<TokenClaims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )?;
        
        let claims = token_data.claims;
        
        // Verify token type if expected
        if let Some(expected) = expected_type {
            if claims.token_type != expected {
                return Err(AuthError::InvalidToken);
            }
        }
        
        Ok(claims)
    }
    
    /// Generate a random token for magic links, etc.
    pub fn generate_random_token(&self, length: usize) -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }
    
    /// Store a token in the database
    pub async fn store_token(
        &self,
        user_id: Option<Uuid>,
        token: &str,
        token_type: TokenType,
        expires_at: DateTime<Utc>,
        metadata: Option<serde_json::Value>,
    ) -> Result<Uuid, AuthError> {
        let token_id = Uuid::new_v4();
        
        let token_type_str = format!("{:?}", token_type);
        
        sqlx::query!(
            r#"
            INSERT INTO auth_tokens (id, user_id, token, token_type, expires_at, created_at, used, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            token_id,
            user_id,
            token,
            token_type_str,
            expires_at,
            Utc::now(),
            false,
            metadata,
        )
        .execute(&self.pool)
        .await
        .map_err(AuthError::DatabaseError)?;
        
        Ok(token_id)
    }
    
    /// Verify a stored token
    pub async fn verify_stored_token(
        &self,
        token: &str,
        token_type: TokenType,
    ) -> Result<(Uuid, Option<Uuid>), AuthError> {
        let token_type_str = format!("{:?}", token_type);
        
        let record = sqlx::query!(
            r#"
            SELECT id, user_id, expires_at, used
            FROM auth_tokens
            WHERE token = $1 AND token_type = $2
            "#,
            token,
            token_type_str,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AuthError::DatabaseError)?
        .ok_or(AuthError::InvalidToken)?;
        
        // Check if token is expired
        if record.expires_at < Utc::now() {
            return Err(AuthError::TokenExpired);
        }
        
        // Check if token is already used
        if record.used {
            return Err(AuthError::InvalidToken);
        }
        
        Ok((record.id, record.user_id))
    }
    
    /// Mark a token as used
    pub async fn mark_token_used(&self, token_id: Uuid) -> Result<(), AuthError> {
        sqlx::query!(
            r#"
            UPDATE auth_tokens
            SET used = true
            WHERE id = $1
            "#,
            token_id,
        )
        .execute(&self.pool)
        .await
        .map_err(AuthError::DatabaseError)?;
        
        Ok(())
    }
}