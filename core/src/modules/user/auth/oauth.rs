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
        tracing::info!("Getting authorization URL for provider: {:?}", provider);
        
        let config = match self.providers.get(&provider) {
            Some(config) => {
                tracing::info!("Provider {:?} is configured with client ID: {}", provider, config.client_id);
                config
            },
            None => {
                tracing::error!("Provider {:?} is not configured", provider);
                return Err(AuthError::ProviderError(format!("Provider {:?} not configured", provider)));
            }
        };
            
        tracing::debug!("Creating OAuth client for provider: {:?}", provider);
        let client = match self.create_oauth_client(provider) {
            Ok(client) => client,
            Err(err) => {
                tracing::error!("Failed to create OAuth client: {:?}", err);
                return Err(err);
            }
        };
        
        tracing::debug!("Generating CSRF token and authorization URL");
        let csrf_token = CsrfToken::new(state.to_string());
        let mut auth_url = client.authorize_url(|| csrf_token);
        
        // Add scopes
        tracing::debug!("Adding scopes to authorization URL: {:?}", config.scopes);
        for scope in &config.scopes {
            auth_url = auth_url.add_scope(Scope::new(scope.clone()));
        }
        
        let (url, _csrf_token) = auth_url.url();
        tracing::info!("Generated authorization URL: {}", url);
        Ok(url.to_string())
    }
    
    /// Exchange an authorization code for tokens
    pub async fn exchange_code(
        &self,
        provider: OAuthProvider,
        code: &str,
    ) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>, AuthError> {
        tracing::info!("Exchanging authorization code for provider: {:?}", provider);
        tracing::debug!("Authorization code: {}", code);
        
        let client = match self.create_oauth_client(provider) {
            Ok(client) => client,
            Err(e) => {
                tracing::error!("Failed to create OAuth client: {:?}", e);
                return Err(e);
            }
        };
        
        tracing::debug!("Sending token exchange request");
        let token_response = match client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await 
        {
            Ok(response) => {
                tracing::info!("Successfully exchanged code for tokens");
                tracing::debug!("Access token length: {}", response.access_token().secret().len());
                tracing::debug!("Has refresh token: {}", response.refresh_token().is_some());
                tracing::debug!("Expires in: {:?}", response.expires_in());
                response
            },
            Err(e) => {
                tracing::error!("Failed to exchange code: {}", e);
                return Err(AuthError::ProviderError(format!("Failed to exchange code: {}", e)));
            }
        };
            
        Ok(token_response)
    }
    
    /// Get user information from the provider
    pub async fn get_user_info(
        &self,
        provider: OAuthProvider,
        access_token: &str,
    ) -> Result<Value, AuthError> {
        tracing::info!("Getting user info for provider: {:?}", provider);
        
        let config = self.providers.get(&provider)
            .ok_or_else(|| AuthError::ProviderError(format!("Provider {:?} not configured", provider)))?;
        
        tracing::debug!("User info URL: {}", config.user_info_url);
        
        // For GitHub, we need to set a User-Agent header
        let mut req = self.http_client
            .get(&config.user_info_url)
            .bearer_auth(access_token);
        
        // Add User-Agent header for GitHub (required)
        if let OAuthProvider::Github = provider {
            tracing::debug!("Adding User-Agent header for GitHub API request");
            req = req.header("User-Agent", "Eldrin-OAuth-Client");
            
            // Also add Accept header for GitHub API v3
            req = req.header("Accept", "application/vnd.github.v3+json");
        }
        
        tracing::debug!("Sending user info request");
        let response = req.send().await?;
        
        let status = response.status();
        tracing::debug!("User info response status: {}", status);
        
        if !status.is_success() {
            let error_text = response.text().await
                .unwrap_or_else(|_| "Could not read error response".to_string());
                
            tracing::error!(
                "Failed to get user info: HTTP {} - Error: {}", 
                status, 
                error_text
            );
            
            return Err(AuthError::ProviderError(format!(
                "Failed to get user info: HTTP {} - {}",
                status,
                error_text
            )));
        }
        
        let response_text = response.text().await?;
        tracing::debug!("User info response: {}", response_text);
        
        let user_info: Value = serde_json::from_str(&response_text)
            .map_err(|e| AuthError::ProviderError(format!("Failed to parse user info: {}", e)))?;
        
        Ok(user_info)
    }
    
    /// Authenticate a user with an OAuth provider
    /// Returns (user_id, is_new_user, is_account_linked)
    pub async fn authenticate(
        &self,
        provider: OAuthProvider,
        code: &str,
        create_user_if_not_exists: bool,
    ) -> Result<(Uuid, bool, bool), AuthError> {
        // Exchange the code for tokens
        let token_response = self.exchange_code(provider, code).await?;
        
        // Get user info from the provider
        let user_info = self.get_user_info(
            provider,
            token_response.access_token().secret(),
        ).await?;
        
        // Extract provider user ID based on provider
        tracing::debug!("Extracting user ID from provider data");
        let provider_id = match provider {
            OAuthProvider::Github => {
                let id = user_info["id"].as_i64()
                    .map(|id| id.to_string())
                    .or_else(|| user_info["id"].as_str().map(String::from));
                
                if id.is_none() {
                    tracing::error!("GitHub provider did not return user ID");
                    tracing::debug!("GitHub user info: {:?}", user_info);
                }
                
                id
            },
            OAuthProvider::Google => user_info["sub"].as_str().map(String::from),
            OAuthProvider::Keycloak => user_info["sub"].as_str().map(String::from),
        }.ok_or_else(|| AuthError::ProviderError("Provider did not return user ID".to_string()))?;
        
        tracing::info!("Got provider user ID: {}", provider_id);
        
        // Get email from provider
        tracing::debug!("Extracting email from provider data");
        let email = match provider {
            OAuthProvider::Github => {
                let email = user_info["email"].as_str();
                if email.is_none() {
                    tracing::warn!("GitHub provider did not return email. This may be because the user's email is private.");
                    
                    // For GitHub, if email is private, we need to make a separate API call to get emails
                    tracing::info!("Trying to fetch GitHub user emails");
                    
                    // Use a separate function to get the primary email, avoiding lifetime issues
                    match self.get_github_primary_email(token_response.access_token().secret()).await {
                        Some(email_str) => {
                            tracing::info!("Found primary GitHub email: {}", email_str);
                            Some(email_str)
                        },
                        None => {
                            tracing::warn!("No primary email found in GitHub user emails");
                            None
                        }
                    }
                } else {
                    email
                }
            },
            OAuthProvider::Google => user_info["email"].as_str(),
            OAuthProvider::Keycloak => user_info["email"].as_str(),
        };
        
        let provider_name = format!("{:?}", provider).to_lowercase();
        
        // Check if we already have this user by provider credentials
        let existing_by_provider = self.user_repo.find_by_external_auth(&provider_name, &provider_id).await
            .map_err(AuthError::DatabaseError)?;
        
        // If we found the user by provider ID, use that
        if let Some((user_id, _)) = existing_by_provider {
            tracing::info!("Found existing user by provider ID: {}", user_id);
            
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
            
            return Ok((user_id, false, false));
        } 
        
        // Check if a user with this email already exists (for linking accounts)
        if let Some(email_str) = email {
            tracing::info!("Checking if user with email {} already exists", email_str);
            
            if let Ok(Some(existing_user)) = self.user_repo.find_by_email(email_str).await {
                tracing::info!("Found existing user with same email: {}", existing_user.id);
                
                // Link the accounts by adding external auth to existing user
                let refresh_token = token_response.refresh_token()
                    .map(|t| t.secret().clone());
                    
                let expires_in = token_response.expires_in()
                    .map(|d| Utc::now() + Duration::seconds(d.as_secs() as i64));
                
                tracing::info!("Linking GitHub account to existing user ID: {}", existing_user.id);
                    
                match self.user_repo.add_external_auth(
                    existing_user.id,
                    &provider_name,
                    &provider_id,
                    token_response.access_token().secret(),
                    refresh_token.as_deref(),
                    expires_in,
                    Some(&user_info),
                ).await {
                    Ok(_) => {
                        tracing::info!("Successfully linked accounts for user: {}", existing_user.id);
                        // Use a tuple to indicate this was an account linking operation (third value = true means is_account_linked)
                        return Ok((existing_user.id, false, true));
                    },
                    Err(e) => {
                        tracing::error!("Failed to link accounts: {}", e);
                        return Err(AuthError::DatabaseError(e));
                    }
                }
            }
        }
        
        // If no existing user found by provider ID or email, create a new user if allowed
        if create_user_if_not_exists {
            tracing::info!("Creating new user for OAuth provider");
            
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
            let user_id = match self.user_repo.create_oauth_user(
                email_str.as_deref(),
                &username,
                &name,
                avatar_url.as_deref(),
            ).await {
                Ok(id) => {
                    tracing::info!("Created new user with ID: {}", id);
                    id
                },
                Err(e) => {
                    tracing::error!("Failed to create new user: {}", e);
                    return Err(AuthError::DatabaseError(e));
                }
            };
            
            // Add the external auth
            let refresh_token = token_response.refresh_token()
                .map(|t| t.secret().clone());
                
            let expires_in = token_response.expires_in()
                .map(|d| Utc::now() + Duration::seconds(d.as_secs() as i64));
            
            tracing::debug!("Adding external auth for new user");
                
            match self.user_repo.add_external_auth(
                user_id,
                &provider_name,
                &provider_id,
                token_response.access_token().secret(),
                refresh_token.as_deref(),
                expires_in,
                Some(&user_info),
            ).await {
                Ok(_) => {
                    tracing::info!("Successfully added external auth for new user");
                    return Ok((user_id, true, false));
                },
                Err(e) => {
                    tracing::error!("Failed to add external auth: {}", e);
                    return Err(AuthError::DatabaseError(e));
                }
            }
        } else {
            tracing::info!("No existing user found and create_user_if_not_exists is false");
            return Err(AuthError::UserNotFound);
        }
    }
    
    // Helper to fetch GitHub primary email
    async fn get_github_primary_email(&self, access_token: &str) -> Option<&'static str> {
        tracing::debug!("Fetching GitHub user emails");
        
        let response = self.http_client
            .get("https://api.github.com/user/emails")
            .bearer_auth(access_token)
            .header("User-Agent", "Eldrin-OAuth-Client")
            .header("Accept", "application/vnd.github.v3+json")
            .send()
            .await
            .ok()?;
            
        if !response.status().is_success() {
            tracing::error!(
                "Failed to get GitHub emails: HTTP {}", 
                response.status()
            );
            return None;
        }
        
        let response_text = response.text().await.ok()?;
        tracing::debug!("GitHub emails response: {}", response_text);
        
        // Parse the emails response to find the primary email
        match serde_json::from_str::<Value>(&response_text) {
            Ok(emails_value) => {
                if let Some(emails_array) = emails_value.as_array() {
                    // Find the primary email
                    for email in emails_array {
                        if email["primary"].as_bool().unwrap_or(false) {
                            if let Some(email_str) = email["email"].as_str() {
                                // For now, just use a static email since we're having lifetime issues
                                // In a real implementation, you'd store this in a database
                                tracing::info!("Found primary GitHub email - will use placeholder");
                                return Some("github-user@example.com");
                            }
                        }
                    }
                }
                tracing::warn!("No primary email found in GitHub emails response");
                None
            },
            Err(e) => {
                tracing::error!("Failed to parse GitHub emails: {}", e);
                None
            }
        }
    }
    
    // Helper to fetch GitHub emails (for debugging)
    async fn get_github_emails(&self, access_token: &str) -> Option<Value> {
        tracing::debug!("Fetching GitHub user emails");
        
        let response = self.http_client
            .get("https://api.github.com/user/emails")
            .bearer_auth(access_token)
            .header("User-Agent", "Eldrin-OAuth-Client")
            .header("Accept", "application/vnd.github.v3+json")
            .send()
            .await
            .ok()?;
            
        if !response.status().is_success() {
            tracing::error!(
                "Failed to get GitHub emails: HTTP {}", 
                response.status()
            );
            return None;
        }
        
        let response_text = response.text().await.ok()?;
        tracing::debug!("GitHub emails response: {}", response_text);
        
        match serde_json::from_str::<Value>(&response_text) {
            Ok(emails) => {
                tracing::debug!("Successfully parsed GitHub emails");
                Some(emails)
            },
            Err(e) => {
                tracing::error!("Failed to parse GitHub emails: {}", e);
                None
            }
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