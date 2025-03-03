use crate::modules::user::models::{User, UserProfile, UserRole, AuthMethod, ExternalAuth};
use crate::modules::user::repository::UserRepository;
use crate::modules::user::auth::{
    AuthError, PasswordManager, TokenManager, TokenType,
    MagicLinkManager, SmsManager, OAuthManager, OAuthProvider,
};
use oauth2::TokenResponse;
use sqlx::{PgPool, Transaction, Postgres};
use sqlx::types::Uuid;
use thiserror::Error;
use std::collections::HashMap;
use std::sync::Arc;
use chrono::{Utc, Duration};
use serde::Serialize;

#[derive(Error, Debug)]
pub enum UserError {
    #[error("User not found")]
    NotFound,

    #[error("Authentication failed")]
    AuthFailed,

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("External provider error: {0}")]
    ProviderError(String),

    #[error("Authentication error: {0}")]
    AuthError(#[from] AuthError),
}

#[derive(Debug, Serialize)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub token_type: String,
}

pub struct UserService {
    repo: UserRepository,
    pool: PgPool,
    password_manager: PasswordManager,
    token_manager: Arc<TokenManager>,
    magic_link_manager: MagicLinkManager,
    sms_manager: SmsManager,
    oauth_manager: OAuthManager,
}

impl UserService {
    /// Create a new user service
    pub fn new(pool: PgPool) -> Self {
        let repo = UserRepository::new(pool.clone());

        // Create token manager
        let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "super-secret-jwt-key".to_string());
        let token_manager = Arc::new(TokenManager::new(
            pool.clone(),
            jwt_secret,
            None,
            None,
        ));

        // Create auth managers
        let magic_link_manager = MagicLinkManager::new(pool.clone(), token_manager.clone(), None);
        let sms_manager = SmsManager::new(pool.clone(), token_manager.clone(), None);
        let mut oauth_manager = OAuthManager::new(pool.clone());

        // Configure OAuth providers if environment variables are available
        Self::configure_oauth_providers(&mut oauth_manager);

        Self {
            repo,
            pool,
            password_manager: PasswordManager,
            token_manager,
            magic_link_manager,
            sms_manager,
            oauth_manager,
        }
    }

    // Helper to configure OAuth providers from environment variables
    fn configure_oauth_providers(oauth_manager: &mut OAuthManager) {
        // Github
        tracing::info!("Configuring GitHub OAuth provider");

        // Get GitHub client ID and secret
        let client_id = std::env::var("GITHUB_CLIENT_ID")
            .unwrap_or_else(|_| "Ov23liIEe8Q5DMHCweJE".to_string());

        let client_secret = std::env::var("GITHUB_CLIENT_SECRET")
            .unwrap_or_else(|_| "1191e6d7e015fbe688474ed596214af482512dcc".to_string());

        tracing::info!("Using GitHub client ID: {}", client_id);

        let redirect_uri = std::env::var("GITHUB_REDIRECT_URI")
            .unwrap_or_else(|_| "http://localhost:3000/auth/github/callback".to_string());

        tracing::info!("Registering GitHub OAuth provider with redirect URI: {}", redirect_uri);

        oauth_manager.register_provider(
            OAuthProvider::Github,
            crate::modules::user::auth::oauth::OAuthConfig {
                client_id: client_id.clone(),
                client_secret,
                redirect_uri,
                auth_url: "https://github.com/login/oauth/authorize".to_string(),
                token_url: "https://github.com/login/oauth/access_token".to_string(),
                user_info_url: "https://api.github.com/user".to_string(),
                scopes: vec!["user".to_string(), "user:email".to_string(), "read:user".to_string()],
            },
        );
        tracing::info!("Successfully registered GitHub OAuth provider with client ID: {}", client_id);


        // Google
        tracing::info!("Configuring Google OAuth provider");

        // Get Google client ID and secret
        let google_client_id_result = std::env::var("GOOGLE_CLIENT_ID")
            .unwrap_or_else(|_| "724483832760-le7b80nsmk9mljonc80bupsvujc5j6ki.apps.googleusercontent.com".to_string());
        let google_client_secret_result = std::env::var("GOOGLE_CLIENT_SECRET")
            .unwrap_or_else(|_| "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".to_string());

        tracing::debug!("Using Google client ID: {}", client_id);

        let redirect_uri = std::env::var("GOOGLE_REDIRECT_URI")
            .unwrap_or_else(|_| "http://localhost:3000/auth/google/callback".to_string());


        tracing::info!("Registering Google OAuth provider with redirect URI: {}", redirect_uri);

        oauth_manager.register_provider(
            OAuthProvider::Google,
            crate::modules::user::auth::oauth::OAuthConfig {
                client_id: google_client_id_result.clone(),
                client_secret: google_client_secret_result,
                redirect_uri,
                auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
                token_url: "https://oauth2.googleapis.com/token".to_string(),
                user_info_url: "https://www.googleapis.com/oauth2/v3/userinfo".to_string(),
                scopes: vec!["profile".to_string(), "email".to_string()],
            },
        );
        tracing::info!("Successfully registered Google OAuth provider with client ID: {}", client_id);


        // Keycloak
        tracing::info!("Configuring Keycloak OAuth provider");

        let keycloak_client_id = std::env::var("KEYCLOAK_CLIENT_ID");
        let keycloak_client_secret = std::env::var("KEYCLOAK_CLIENT_SECRET");
        let keycloak_base_url = std::env::var("KEYCLOAK_BASE_URL");

        tracing::debug!("Keycloak client ID found: {}", keycloak_client_id.is_ok());
        tracing::debug!("Keycloak client secret found: {}", keycloak_client_secret.is_ok());
        tracing::debug!("Keycloak base URL found: {}", keycloak_base_url.is_ok());

        if let (Ok(client_id), Ok(client_secret), Ok(base_url)) =
            (keycloak_client_id, keycloak_client_secret, keycloak_base_url) {
            let redirect_uri = std::env::var("KEYCLOAK_REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:3000/auth/keycloak/callback".to_string());

            let realm = std::env::var("KEYCLOAK_REALM").unwrap_or_else(|_| "master".to_string());

            tracing::info!("Registering Keycloak OAuth provider with base URL: {} and realm: {}", base_url, realm);

            oauth_manager.register_provider(
                OAuthProvider::Keycloak,
                crate::modules::user::auth::oauth::OAuthConfig {
                    client_id: client_id.clone(),
                    client_secret,
                    redirect_uri,
                    auth_url: format!("{}/realms/{}/protocol/openid-connect/auth", base_url, realm),
                    token_url: format!("{}/realms/{}/protocol/openid-connect/token", base_url, realm),
                    user_info_url: format!("{}/realms/{}/protocol/openid-connect/userinfo", base_url, realm),
                    scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
                },
            );
            tracing::info!("Successfully registered Keycloak OAuth provider with client ID: {}", client_id);
        }
    }

    /// Initialize the user service, creating default admin if needed
    pub async fn init(&self) -> Result<(), UserError> {
        // Check if we have any admin users
        let admin_exists = self.repo.has_admin_users().await?;

        if !admin_exists {
            tracing::info!("Creating default admin user");

            // Create the default admin user
            let user = self.register_email_password(
                "admin@eldrin.io".to_string(),
                "Nimda_123!".to_string(),
                Some("admin".to_string()),
            ).await?;

            // Set the user role to Admin and mark email as verified
            let mut admin_user = user;
            admin_user.role = UserRole::Admin;
            admin_user.email_verified = true;

            // Update the user
            self.repo.update_user(&admin_user).await?;

            tracing::info!("Default admin user created successfully");
        }

        Ok(())
    }

    /// Register a new user with email and password
    pub async fn register_email_password(
        &self,
        email: String,
        password: String,
        username: Option<String>,
    ) -> Result<User, UserError> {
        // Validate the email and password
        if email.is_empty() {
            return Err(UserError::InvalidInput("Email cannot be empty".to_string()));
        }

        if password.len() < 8 {
            return Err(UserError::InvalidInput("Password must be at least 8 characters".to_string()));
        }

        // Check if user already exists
        if let Some(_) = self.repo.find_by_email(&email).await? {
            return Err(UserError::InvalidInput("Email already in use".to_string()));
        }

        // Hash the password
        let password_hash = PasswordManager::hash_password(&password)?;

        // Create the user
        let user = User {
            id: Uuid::new_v4(),
            email: Some(email),
            phone: None,
            username: username.unwrap_or_else(|| format!("user_{}", Uuid::new_v4())),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: None,
            active: true,
            email_verified: false,
            phone_verified: false,
            role: UserRole::User,
            roles: None,
            permissions: None,
        };

        // Create the user in the database
        let user = self.repo.create_user(&user).await?;

        // Store the password hash
        self.repo.store_password_hash(user.id, &password_hash).await?;

        // In a real implementation, we'd send a verification email here

        Ok(user)
    }

    /// Send a magic link authentication email
    pub async fn send_magic_link(&self, email: &str, base_url: &str) -> Result<(), UserError> {
        // Validate the email
        if email.is_empty() {
            return Err(UserError::InvalidInput("Email cannot be empty".to_string()));
        }

        // Generate the magic link token
        let token = self.magic_link_manager.generate_magic_link(email, true).await?;

        // Send the magic link email
        self.magic_link_manager.send_magic_link_email(email, &token, base_url).await?;

        Ok(())
    }

    /// Verify a magic link token
    pub async fn verify_magic_link(&self, token: &str) -> Result<(User, AuthTokens), UserError> {
        // Verify the token
        let user_id = self.magic_link_manager.verify_magic_link(token).await?;

        // Get the user
        let user = self.repo.find_by_id(user_id).await?
            .ok_or(UserError::NotFound)?;

        // Generate JWT tokens
        let tokens = self.generate_auth_tokens(&user)?;

        Ok((user, tokens))
    }

    /// Send an SMS verification code
    pub async fn send_sms_code(&self, phone: &str) -> Result<(), UserError> {
        // Validate the phone
        if phone.is_empty() {
            return Err(UserError::InvalidInput("Phone cannot be empty".to_string()));
        }

        // Generate the SMS code
        let code = self.sms_manager.generate_sms_code(phone, true).await?;

        // Send the SMS code
        self.sms_manager.send_sms_code(phone, &code).await?;

        Ok(())
    }

    /// Verify an SMS code
    pub async fn verify_sms_code(&self, code: &str) -> Result<(User, AuthTokens), UserError> {
        // Verify the code
        let user_id = self.sms_manager.verify_sms_code(code).await?;

        // Get the user
        let user = self.repo.find_by_id(user_id).await?
            .ok_or(UserError::NotFound)?;

        // Generate JWT tokens
        let tokens = self.generate_auth_tokens(&user)?;

        Ok((user, tokens))
    }

    /// Authenticate a user with email and password
    pub async fn authenticate_email_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<(User, AuthTokens), UserError> {
        // Validate inputs
        if email.is_empty() || password.is_empty() {
            return Err(UserError::AuthFailed);
        }

        // Find the user by email
        let user = self.repo.find_by_email(email).await?
            .ok_or(UserError::AuthFailed)?;

        // Check if the user is active
        if !user.active {
            return Err(UserError::AuthFailed);
        }

        // Get the password hash
        let hash = sqlx::query!(
            r#"
            SELECT password_hash FROM users WHERE id = $1
            "#,
            user.id
        )
            .fetch_one(&self.pool)
            .await?
            .password_hash
            .ok_or(UserError::AuthFailed)?;

        // Verify the password
        if !PasswordManager::verify_password(password, &hash)? {
            return Err(UserError::AuthFailed);
        }

        // Update the last login time
        self.repo.update_last_login(user.id).await?;

        // Generate JWT tokens
        let tokens = self.generate_auth_tokens(&user)?;

        Ok((user, tokens))
    }

    /// Get an OAuth authorization URL
    pub async fn get_oauth_authorization_url(
        &self,
        provider: OAuthProvider,
    ) -> Result<String, UserError> {
        // Generate a random state parameter for CSRF protection
        let state = self.token_manager.generate_random_token(32);

        // Get the authorization URL
        let url = self.oauth_manager.get_authorization_url(provider, &state)?;

        // Store the state in the session
        // In a real implementation, we'd store this in Redis or similar

        Ok(url)
    }

    /// Handle OAuth callback
    pub async fn handle_oauth_callback(
        &self,
        provider: OAuthProvider,
        code: &str,
    ) -> Result<(User, AuthTokens, bool, bool), UserError> {
        // Authenticate with the provider
        let (user_id, is_new_user, is_account_linked) = self.oauth_manager.authenticate(
            provider,
            code,
            true,
        ).await?;

        // Get the user
        let user = self.repo.find_by_id(user_id).await?
            .ok_or(UserError::NotFound)?;

        // Generate JWT tokens
        let tokens = self.generate_auth_tokens(&user)?;

        Ok((user, tokens, is_new_user, is_account_linked))
    }

    /// Generate JWT tokens for a user
    pub fn generate_auth_tokens(&self, user: &User) -> Result<AuthTokens, UserError> {
        // Generate access token
        let access_token = self.token_manager.generate_jwt(user, TokenType::Access)?;

        // Generate refresh token
        let refresh_token = self.token_manager.generate_jwt(user, TokenType::Refresh)?;

        Ok(AuthTokens {
            access_token,
            refresh_token,
            expires_in: self.token_manager.access_token_expiry.num_seconds(),
            token_type: "Bearer".to_string(),
        })
    }

    /// Refresh an access token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<AuthTokens, UserError> {
        // Verify the refresh token
        let claims = self.token_manager.verify_jwt(refresh_token, Some(TokenType::Refresh))?;

        // Get the user ID from the token
        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| AuthError::InvalidToken)?;

        // Get the user
        let user = self.repo.find_by_id(user_id).await?
            .ok_or(UserError::NotFound)?;

        // Generate new tokens
        let tokens = self.generate_auth_tokens(&user)?;

        Ok(tokens)
    }

    /// Connect a user to an external auth provider
    pub async fn connect_provider(
        &self,
        user_id: Uuid,
        provider: OAuthProvider,
        code: &str,
    ) -> Result<(), UserError> {
        // Check if the user exists
        let user = self.repo.find_by_id(user_id).await?
            .ok_or(UserError::NotFound)?;

        // Exchange the code for tokens
        let token_response = self.oauth_manager.exchange_code(provider, code).await?;

        // Get user info from the provider
        let user_info = self.oauth_manager.get_user_info(
            provider,
            &token_response.access_token().secret(),
        ).await?;

        // Extract provider user ID based on provider
        let provider_id = match provider {
            OAuthProvider::Github => user_info["id"].as_i64()
                .map(|id| id.to_string())
                .or_else(|| user_info["id"].as_str().map(String::from)),
            OAuthProvider::Google => user_info["sub"].as_str().map(String::from),
            OAuthProvider::Keycloak => user_info["sub"].as_str().map(String::from),
        }.ok_or_else(|| AuthError::ProviderError("Provider did not return user ID".to_string()))?;

        // Check if this provider account is already connected to another user
        let provider_name = format!("{:?}", provider).to_lowercase();
        if let Some((existing_user_id, _)) = self.repo.find_by_external_auth(&provider_name, &provider_id).await? {
            if existing_user_id != user_id {
                return Err(UserError::ProviderError("This account is already connected to another user".to_string()));
            }

            // Update the existing connection
            let refresh_token = token_response.refresh_token()
                .map(|t| t.secret().clone());

            let expires_in = token_response.expires_in()
                .map(|d| Utc::now() + Duration::seconds(d.as_secs() as i64));

            self.repo.update_external_auth(
                user_id,
                &provider_name,
                token_response.access_token().secret(),
                refresh_token.as_deref(),
                expires_in,
                Some(&user_info),
            ).await?;
        } else {
            // Add the new connection
            let refresh_token = token_response.refresh_token()
                .map(|t| t.secret().clone());

            let expires_in = token_response.expires_in()
                .map(|d| Utc::now() + Duration::seconds(d.as_secs() as i64));

            self.repo.add_external_auth(
                user_id,
                &provider_name,
                &provider_id,
                token_response.access_token().secret(),
                refresh_token.as_deref(),
                expires_in,
                Some(&user_info),
            ).await?;
        }

        Ok(())
    }

    /// Get a user's profile
    pub async fn get_profile(&self, user_id: Uuid) -> Result<UserProfile, UserError> {
        // Check if the user exists
        let user = self.repo.find_by_id(user_id).await?
            .ok_or(UserError::NotFound)?;

        // Get the profile
        let profile = self.repo.get_profile(user_id).await?
            .unwrap_or_else(|| UserProfile {
                user_id,
                display_name: None,
                avatar_url: None,
                locale: None,
                timezone: None,
                metadata: None,
            });

        Ok(profile)
    }

    /// Update a user's profile
    pub async fn update_profile(&self, profile: UserProfile) -> Result<UserProfile, UserError> {
        // Check if the user exists
        let user = self.repo.find_by_id(profile.user_id).await?
            .ok_or(UserError::NotFound)?;

        // Update the profile
        let profile = self.repo.update_profile(&profile).await?;

        Ok(profile)
    }

    /// Get external auth providers for a user
    pub async fn get_external_auth(&self, user_id: Uuid) -> Result<Vec<ExternalAuth>, UserError> {
        // Check if the user exists
        let user = self.repo.find_by_id(user_id).await?
            .ok_or(UserError::NotFound)?;

        // Get the external auth providers
        let providers = self.repo.get_external_auth(user_id).await?;

        Ok(providers)
    }
}