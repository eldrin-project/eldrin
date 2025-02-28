use crate::modules::user::auth::AuthError;
use crate::modules::user::models::ExternalAuth;
use crate::modules::user::repository::UserRepository;
use chrono::{DateTime, Duration, Utc};
use oauth2::{
    basic::BasicClient,
    AuthUrl, ClientId, ClientSecret, RedirectUrl, 
    TokenUrl, Scope, AuthorizationCode, TokenResponse, CsrfToken,
    reqwest::async_http_client,
    StandardTokenResponse, EmptyExtraTokenFields, basic::BasicTokenType,
};
use reqwest::{Client as HttpClient};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use sqlx::types::Uuid;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OAuthProvider {
    Github,
    Google,
    Keycloak,
}

pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub auth_url: String,
    pub token_url: String,
    pub user_info_url: String,
    pub scopes: Vec<String>,
}

/// Manages OAuth authentication with various providers
pub struct OAuthManager {
    user_repo: UserRepository,
    http_client: HttpClient,
    providers: std::collections::HashMap<OAuthProvider, OAuthConfig>,
}

impl OAuthManager {
    /// Create a new OAuth manager
    pub fn new(pool: PgPool) -> Self {
        Self {
            user_repo: UserRepository::new(pool),
            http_client: HttpClient::new(),
            providers: std::collections::HashMap::new(),
        }
    }
    
    /// Register an OAuth provider
    pub fn register_provider(&mut self, provider: OAuthProvider, config: OAuthConfig) {
        self.providers.insert(provider, config);
    }
    
    /// Get a redirect URL for a provider
    pub fn get_authorization_url(&self, provider: OAuthProvider, state: &str) -> Result<String, AuthError> {
        let config = self.providers.get(&provider)
            .ok_or_else(|| AuthError::ProviderError(format!("Provider {:?} not configured", provider)))?;
            
        let client = self.create_oauth_client(provider)?;
        
        let csrf_token = CsrfToken::new(state.to_string());
        let mut auth_url = client.authorize_url(|| csrf_token);
        
        // Add scopes
        for scope in &config.scopes {
            auth_url = auth_url.add_scope(Scope::new(scope.clone()));
        }
        
        let (url, _csrf_token) = auth_url.url();
        Ok(url.to_string())
    }
    
    /// Exchange an authorization code for tokens
    pub async fn exchange_code(
        &self,
        provider: OAuthProvider,
        code: &str,
    ) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>, AuthError> {
        let client = self.create_oauth_client(provider)?;
        
        let token_response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await
            .map_err(|e| AuthError::ProviderError(format!("Failed to exchange code: {}", e)))?;
            
        Ok(token_response)
    }
    
    /// Get user information from the provider
    pub async fn get_user_info(
        &self,
        provider: OAuthProvider,
        access_token: &str,
    ) -> Result<Value, AuthError> {
        let config = self.providers.get(&provider)
            .ok_or_else(|| AuthError::ProviderError(format!("Provider {:?} not configured", provider)))?;
            
        let response = self.http_client
            .get(&config.user_info_url)
            .bearer_auth(access_token)
            .send()
            .await?;
            
        if !response.status().is_success() {
            return Err(AuthError::ProviderError(format!(
                "Failed to get user info: HTTP {}",
                response.status()
            )));
        }
        
        let user_info = response.json::<Value>().await?;
        
        Ok(user_info)
    }
    
    /// Authenticate a user with an OAuth provider
    pub async fn authenticate(
        &self,
        provider: OAuthProvider,
        code: &str,
        create_user_if_not_exists: bool,
    ) -> Result<(Uuid, bool), AuthError> {
        // Exchange the code for tokens
        let token_response = self.exchange_code(provider, code).await?;
        
        // Get user info from the provider
        let user_info = self.get_user_info(
            provider,
            token_response.access_token().secret(),
        ).await?;
        
        // Extract provider user ID based on provider
        let provider_id = match provider {
            OAuthProvider::Github => user_info["id"].as_i64()
                .map(|id| id.to_string())
                .or_else(|| user_info["id"].as_str().map(String::from)),
            OAuthProvider::Google => user_info["sub"].as_str().map(String::from),
            OAuthProvider::Keycloak => user_info["sub"].as_str().map(String::from),
        }.ok_or_else(|| AuthError::ProviderError("Provider did not return user ID".to_string()))?;
        
        // Get email from provider
        let email = match provider {
            OAuthProvider::Github => user_info["email"].as_str(),
            OAuthProvider::Google => user_info["email"].as_str(),
            OAuthProvider::Keycloak => user_info["email"].as_str(),
        };
        
        // Check if we already have this user
        let provider_name = format!("{:?}", provider).to_lowercase();
        let existing = self.user_repo.find_by_external_auth(&provider_name, &provider_id).await
            .map_err(AuthError::DatabaseError)?;
        
        if let Some((user_id, _)) = existing {
            // Update the user's last login
            self.user_repo.update_last_login(user_id).await
                .map_err(AuthError::DatabaseError)?;
            
            // Update the external auth with new tokens
            let refresh_token = token_response.refresh_token()
                .map(|t| t.secret().clone());
                
            let expires_in = token_response.expires_in()
                .map(|d| Utc::now() + Duration::seconds(d.as_secs() as i64));
                
            self.user_repo.update_external_auth(
                user_id,
                &provider_name,
                token_response.access_token().secret(),
                refresh_token.as_deref(),
                expires_in,
                Some(&user_info),
            ).await
                .map_err(AuthError::DatabaseError)?;
            
            return Ok((user_id, false));
        } else if create_user_if_not_exists {
            // Create a new user
            let username = match provider {
                OAuthProvider::Github => user_info["login"].as_str()
                    .or_else(|| user_info["username"].as_str()),
                OAuthProvider::Google => user_info["given_name"].as_str(),
                OAuthProvider::Keycloak => user_info["preferred_username"].as_str(),
            }.unwrap_or(&provider_id).to_string();
            
            let name = match provider {
                OAuthProvider::Github => user_info["name"].as_str(),
                OAuthProvider::Google => user_info["name"].as_str(),
                OAuthProvider::Keycloak => user_info["name"].as_str(),
            }.unwrap_or(&username).to_string();
            
            let avatar_url = match provider {
                OAuthProvider::Github => user_info["avatar_url"].as_str(),
                OAuthProvider::Google => user_info["picture"].as_str(),
                OAuthProvider::Keycloak => None,
            }.map(String::from);
            
            // Create the user
            let email_str = email.map(String::from);
            let user_id = self.user_repo.create_oauth_user(
                email_str.as_deref(),
                &username,
                &name,
                avatar_url.as_deref(),
            ).await
                .map_err(AuthError::DatabaseError)?;
            
            // Add the external auth
            let refresh_token = token_response.refresh_token()
                .map(|t| t.secret().clone());
                
            let expires_in = token_response.expires_in()
                .map(|d| Utc::now() + Duration::seconds(d.as_secs() as i64));
                
            self.user_repo.add_external_auth(
                user_id,
                &provider_name,
                &provider_id,
                token_response.access_token().secret(),
                refresh_token.as_deref(),
                expires_in,
                Some(&user_info),
            ).await
                .map_err(AuthError::DatabaseError)?;
            
            return Ok((user_id, true));
        } else {
            return Err(AuthError::UserNotFound);
        }
    }
    
    // Helper to create an OAuth client
    fn create_oauth_client(&self, provider: OAuthProvider) -> Result<BasicClient, AuthError> {
        let config = self.providers.get(&provider)
            .ok_or_else(|| AuthError::ProviderError(format!("Provider {:?} not configured", provider)))?;
            
        Ok(BasicClient::new(
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
            AuthUrl::new(config.auth_url.clone())
                .map_err(|e| AuthError::ProviderError(format!("Invalid auth URL: {}", e)))?,
            Some(TokenUrl::new(config.token_url.clone())
                .map_err(|e| AuthError::ProviderError(format!("Invalid token URL: {}", e)))?),
        )
        .set_redirect_uri(RedirectUrl::new(config.redirect_uri.clone())
            .map_err(|e| AuthError::ProviderError(format!("Invalid redirect URI: {}", e)))?))
    }
}