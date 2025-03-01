use crate::modules::user::models::{User, UserProfile, AuthMethod};
use crate::modules::user::service::{UserService, UserError, AuthTokens};
use crate::modules::user::auth::OAuthProvider;
use axum::{
    extract::{Json, State, Path, Query, Form},
    http::{StatusCode, HeaderMap, HeaderValue, HeaderName, header},
    response::{IntoResponse, Response, Redirect, Html},
    routing::{post, get, put},
    Router,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use sqlx::types::Uuid;
use std::sync::Arc;
use std::str::FromStr;
use time::Duration;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    email: String,
    password: String,
    username: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
pub struct MagicLinkRequest {
    email: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyMagicLinkRequest {
    token: String,
}

#[derive(Debug, Deserialize)]
pub struct SmsCodeRequest {
    phone: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifySmsCodeRequest {
    code: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct ConnectProviderRequest {
    code: String,
    provider: String,
}

#[derive(Debug, Deserialize)]
pub struct ProfileUpdateRequest {
    display_name: Option<String>,
    avatar_url: Option<String>,
    locale: Option<String>,
    timezone: Option<String>,
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    user: User,
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    token_type: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    token_type: String,
}

// Error handling
impl IntoResponse for UserError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            UserError::NotFound => (StatusCode::NOT_FOUND, "User not found"),
            UserError::AuthFailed => (StatusCode::UNAUTHORIZED, "Authentication failed"),
            UserError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, "Invalid input"),
            UserError::DatabaseError(e) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
            UserError::ProviderError(msg) => (StatusCode::BAD_REQUEST, "Provider error"),
            UserError::AuthError(e) => {
                use crate::modules::user::auth::AuthError;
                match e {
                    AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid credentials"),
                    AuthError::TokenExpired => (StatusCode::UNAUTHORIZED, "Token expired"),
                    AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
                    AuthError::UserNotFound => (StatusCode::NOT_FOUND, "User not found"),
                    AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
                    AuthError::ProviderError(_) => (StatusCode::BAD_REQUEST, "Provider error"),
                    AuthError::InternalError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal authentication error"),
                    AuthError::DatabaseError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
                    AuthError::StorageError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Storage error"),
                    AuthError::RequestError(_) => (StatusCode::BAD_REQUEST, "Request error"),
                    AuthError::JwtError(_) => (StatusCode::UNAUTHORIZED, "Authentication error"),
                }
            },
        };
        
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

pub fn user_routes(pool: PgPool) -> Router {
    let user_service = Arc::new(UserService::new(pool));
    
    Router::new()
        // Email/password auth
        .route("/register", post(register))
        .route("/login", post(login))
        // Magic link auth
        .route("/auth/magic-link", post(magic_link))
        .route("/auth/verify-magic-link", post(verify_magic_link))
        // SMS auth
        .route("/auth/sms-code", post(sms_code))
        .route("/auth/verify-sms-code", post(verify_sms_code))
        // OAuth
        .route("/auth/:provider/authorize", get(oauth_authorize))
        .route("/auth/:provider/callback", get(oauth_callback))
        .route("/auth/:user_id/connect-provider", post(connect_provider))
        // Tokens
        .route("/auth/refresh", post(refresh_token))
        // Profile
        .route("/profile/:user_id", get(get_profile))
        .route("/profile/:user_id", put(update_profile))
        .with_state(user_service)
}

/// Register a new user with email and password
async fn register(
    State(service): State<Arc<UserService>>,
    Json(req): Json<RegisterRequest>,
) -> Result<impl IntoResponse, UserError> {
    let user = service.register_email_password(
        req.email,
        req.password,
        req.username,
    ).await?;
    
    // Generate JWT tokens
    let tokens = service.generate_auth_tokens(&user)?;
    
    Ok((
        StatusCode::CREATED,
        Json(AuthResponse { 
            user, 
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_in: tokens.expires_in,
            token_type: tokens.token_type,
        }),
    ))
}

/// Login with email and password
async fn login(
    State(service): State<Arc<UserService>>,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, UserError> {
    let (user, tokens) = service.authenticate_email_password(
        &req.email,
        &req.password,
    ).await?;
    
    Ok(Json(AuthResponse { 
        user, 
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
        token_type: tokens.token_type,
    }))
}

/// Request a magic link via email
async fn magic_link(
    State(service): State<Arc<UserService>>,
    Json(req): Json<MagicLinkRequest>,
) -> Result<impl IntoResponse, UserError> {
    // Get base URL from request headers or environment
    let base_url = std::env::var("BASE_URL")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());
        
    service.send_magic_link(&req.email, &base_url).await?;
    
    Ok(StatusCode::OK)
}

/// Verify a magic link token
async fn verify_magic_link(
    State(service): State<Arc<UserService>>,
    Json(req): Json<VerifyMagicLinkRequest>,
) -> Result<impl IntoResponse, UserError> {
    let (user, tokens) = service.verify_magic_link(&req.token).await?;
    
    Ok(Json(AuthResponse { 
        user, 
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
        token_type: tokens.token_type,
    }))
}

/// Request an SMS verification code
async fn sms_code(
    State(service): State<Arc<UserService>>,
    Json(req): Json<SmsCodeRequest>,
) -> Result<impl IntoResponse, UserError> {
    service.send_sms_code(&req.phone).await?;
    
    Ok(StatusCode::OK)
}

/// Verify an SMS code
async fn verify_sms_code(
    State(service): State<Arc<UserService>>,
    Json(req): Json<VerifySmsCodeRequest>,
) -> Result<impl IntoResponse, UserError> {
    let (user, tokens) = service.verify_sms_code(&req.code).await?;
    
    Ok(Json(AuthResponse { 
        user, 
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
        token_type: tokens.token_type,
    }))
}

/// Get an OAuth authorization URL
async fn oauth_authorize(
    State(service): State<Arc<UserService>>,
    Path(provider): Path<String>,
) -> Result<impl IntoResponse, UserError> {
    tracing::info!("OAuth authorization requested for provider: {}", provider);
    
    // Parse provider
    let provider = match provider.to_lowercase().as_str() {
        "github" => {
            tracing::info!("GitHub OAuth provider selected");
            OAuthProvider::Github
        },
        "google" => {
            tracing::info!("Google OAuth provider selected");
            OAuthProvider::Google
        },
        "keycloak" => {
            tracing::info!("Keycloak OAuth provider selected");
            OAuthProvider::Keycloak
        },
        _ => {
            tracing::error!("Invalid OAuth provider requested: {}", provider);
            return Err(UserError::InvalidInput(format!("Invalid provider: {}", provider)))
        },
    };
    
    // Get the authorization URL
    tracing::debug!("Getting authorization URL for provider: {:?}", provider);
    let url = match service.get_oauth_authorization_url(provider).await {
        Ok(url) => {
            tracing::info!("Successfully generated OAuth URL: {}", url);
            url
        },
        Err(err) => {
            tracing::error!("Failed to generate OAuth URL: {:?}", err);
            return Err(err);
        }
    };
    
    // Redirect to the authorization URL
    tracing::info!("Redirecting user to OAuth provider URL");
    Ok(Redirect::to(url.as_str()))
}

/// Handle OAuth callback - used within user routes
async fn oauth_callback(
    State(service): State<Arc<UserService>>,
    Path(provider): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, UserError> {
    tracing::info!("OAuth callback received for provider: {}", provider);
    tracing::debug!("Callback query parameters: {:?}", params);
    
    // Check for error response from provider
    if let Some(error) = params.get("error") {
        let error_description = params.get("error_description")
            .map(|s| s.as_str())
            .unwrap_or("No description provided");
            
        tracing::error!("OAuth provider returned error: {} - {}", error, error_description);
        return Err(UserError::ProviderError(format!("Provider error: {} - {}", error, error_description)));
    }
    
    // Parse provider
    let provider = match provider.to_lowercase().as_str() {
        "github" => {
            tracing::info!("GitHub OAuth callback");
            OAuthProvider::Github
        },
        "google" => {
            tracing::info!("Google OAuth callback");
            OAuthProvider::Google
        },
        "keycloak" => {
            tracing::info!("Keycloak OAuth callback");
            OAuthProvider::Keycloak
        },
        _ => {
            tracing::error!("Invalid OAuth provider in callback: {}", provider);
            return Err(UserError::InvalidInput(format!("Invalid provider: {}", provider)))
        },
    };
    
    // Get the code from the query parameters
    let code = match params.get("code") {
        Some(code) => {
            tracing::info!("OAuth code received");
            code
        },
        None => {
            tracing::error!("No OAuth code provided in callback");
            return Err(UserError::InvalidInput("No code provided".to_string()));
        }
    };
        
    // Handle the OAuth callback
    tracing::info!("Processing OAuth callback");
    let result = match service.handle_oauth_callback(provider, code).await {
        Ok(result) => {
            let (user, tokens, new_user, account_linked) = &result;
            let status = if *new_user { "new" } else { "existing" };
            let link_status = if *account_linked { " (account linked)" } else { "" };
            tracing::info!("OAuth authentication successful for {}{} user: {}", status, link_status, user.id);
            result
        },
        Err(err) => {
            tracing::error!("OAuth callback processing failed: {:?}", err);
            return Err(err);
        }
    };
    
    let (user, tokens, _is_new_user, _is_account_linked) = result;
    
    // Redirect to Angular route that will handle token storage
    tracing::info!("Redirecting to frontend auth-callback route to handle token storage");
    
    // Get frontend URL from environment variables or use default
    let frontend_url = std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:4200".to_string());
    
    // Create auth-callback route URL with tokens as parameters
    let auth_callback_url = format!(
        "{}/auth-callback?access_token={}&refresh_token={}&user_id={}&email={}&username={}",
        frontend_url,
        tokens.access_token,
        tokens.refresh_token,
        user.id,
        user.email.as_deref().unwrap_or(""),
        user.username
    );
    
    tracing::info!("Redirecting to frontend auth-callback route");
    
    // Redirect to the auth-callback URL in the Angular app
    Ok(Redirect::to(&auth_callback_url))
}

/// Public OAuth callback handler for routes outside user APIs
pub async fn oauth_callback_handler(
    Query(params): Query<std::collections::HashMap<String, String>>,
    Path(provider): Path<String>,
) -> impl IntoResponse {
    tracing::info!("Public OAuth callback received for provider: {}", provider);
    tracing::debug!("Callback query parameters: {:?}", params);
    
    // Get user service
    let pool = match get_db_pool().await {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!("Failed to get DB pool: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR, 
                Json(serde_json::json!({
                    "error": "Internal server error",
                    "message": "Failed to connect to database"
                }))
            ).into_response();
        }
    };
    
    let service = UserService::new(pool);
    
    // Parse provider
    let oauth_provider = match provider.to_lowercase().as_str() {
        "github" => OAuthProvider::Github,
        "google" => OAuthProvider::Google,
        "keycloak" => OAuthProvider::Keycloak,
        _ => {
            tracing::error!("Invalid OAuth provider in callback: {}", provider);
            return (
                StatusCode::BAD_REQUEST, 
                Json(serde_json::json!({
                    "error": "Invalid provider",
                    "message": format!("Provider {} is not supported", provider)
                }))
            ).into_response();
        }
    };
    
    // Get code from query parameters
    let code = match params.get("code") {
        Some(code) => code,
        None => {
            tracing::error!("No OAuth code provided in callback");
            return (
                StatusCode::BAD_REQUEST, 
                Json(serde_json::json!({
                    "error": "No code provided",
                    "message": "No code was provided in the callback"
                }))
            ).into_response();
        }
    };
    
    // Handle the OAuth callback
    tracing::info!("Processing OAuth callback in public handler");
    match service.handle_oauth_callback(oauth_provider, code).await {
        Ok((user, tokens, is_new_user, is_account_linked)) => {
            let status = if is_new_user { "new" } else { "existing" };
            let link_status = if is_account_linked { " (account linked)" } else { "" };
            tracing::info!("OAuth authentication successful for {}{} user: {}", status, link_status, user.id);
            
            // Get frontend URL from environment variables or use default
            let frontend_url = std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:4200".to_string());
            
            // Create auth-callback route URL with tokens as parameters
            let auth_callback_url = format!(
                "{}/auth-callback?access_token={}&refresh_token={}&user_id={}&email={}&username={}",
                frontend_url,
                tokens.access_token,
                tokens.refresh_token,
                user.id,
                user.email.as_deref().unwrap_or(""),
                user.username
            );
            
            tracing::info!("Redirecting to frontend auth-callback route");
            
            // Redirect to the auth-callback URL in the Angular app
            Redirect::to(&auth_callback_url).into_response()
        },
        Err(err) => {
            tracing::error!("OAuth callback processing failed: {:?}", err);
            let (status, message) = match &err {
                UserError::NotFound => (StatusCode::NOT_FOUND, "User not found"),
                UserError::AuthFailed => (StatusCode::UNAUTHORIZED, "Authentication failed"),
                UserError::InvalidInput(_) => (StatusCode::BAD_REQUEST, "Invalid input"),
                UserError::DatabaseError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
                UserError::ProviderError(_) => (StatusCode::BAD_REQUEST, "Provider error"),
                UserError::AuthError(_) => (StatusCode::UNAUTHORIZED, "Authentication error"),
            };
            
            (
                status,
                Json(serde_json::json!({
                    "error": message,
                    "message": format!("{}", err)
                }))
            ).into_response()
        }
    }
}

/// Helper function to get DB pool
async fn get_db_pool() -> Result<PgPool, String> {
    // Get database URL from environment variables
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://eldrin:eldrin_password@localhost:5432/eldrin_dev".to_string());
    
    // Connect to the database
    PgPool::connect(&database_url)
        .await
        .map_err(|e| format!("Failed to connect to database: {}", e))
}

/// Connect a provider to an existing user account
async fn connect_provider(
    State(service): State<Arc<UserService>>,
    Path(user_id): Path<Uuid>,
    Json(req): Json<ConnectProviderRequest>,
) -> Result<impl IntoResponse, UserError> {
    // Parse provider
    let provider = match req.provider.to_lowercase().as_str() {
        "github" => OAuthProvider::Github,
        "google" => OAuthProvider::Google,
        "keycloak" => OAuthProvider::Keycloak,
        _ => return Err(UserError::InvalidInput(format!("Invalid provider: {}", req.provider))),
    };
    
    // Connect the provider
    service.connect_provider(user_id, provider, &req.code).await?;
    
    Ok(StatusCode::OK)
}

/// Refresh an access token
async fn refresh_token(
    State(service): State<Arc<UserService>>,
    Json(req): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, UserError> {
    let tokens = service.refresh_token(&req.refresh_token).await?;
    
    Ok(Json(TokenResponse { 
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
        token_type: tokens.token_type,
    }))
}

/// Get a user's profile
async fn get_profile(
    State(service): State<Arc<UserService>>,
    Path(user_id): Path<Uuid>,
) -> Result<impl IntoResponse, UserError> {
    let profile = service.get_profile(user_id).await?;
    
    Ok(Json(profile))
}

/// Update a user's profile
async fn update_profile(
    State(service): State<Arc<UserService>>,
    Path(user_id): Path<Uuid>,
    Json(req): Json<ProfileUpdateRequest>,
) -> Result<impl IntoResponse, UserError> {
    let profile = UserProfile {
        user_id,
        display_name: req.display_name,
        avatar_url: req.avatar_url,
        locale: req.locale,
        timezone: req.timezone,
        metadata: req.metadata.map(|m| {
            let mut map = std::collections::HashMap::new();
            if let serde_json::Value::Object(obj) = m {
                for (k, v) in obj {
                    map.insert(k, v);
                }
            }
            map
        }),
    };
    
    let updated_profile = service.update_profile(profile).await?;
    
    Ok(Json(updated_profile))
}