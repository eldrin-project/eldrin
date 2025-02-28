use crate::modules::user::models::{User, UserProfile, AuthMethod};
use crate::modules::user::service::{UserService, UserError, AuthTokens};
use crate::modules::user::auth::OAuthProvider;
use axum::{
    extract::{Json, State, Path, Query, Form},
    http::{StatusCode, HeaderMap, HeaderValue, HeaderName},
    response::{IntoResponse, Response, Redirect},
    routing::{post, get, put},
    Router,
};
use axum_extra::extract::{cookie::{Cookie, SameSite}, CookieJar};
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
    // Parse provider
    let provider = match provider.to_lowercase().as_str() {
        "github" => OAuthProvider::Github,
        "google" => OAuthProvider::Google,
        "keycloak" => OAuthProvider::Keycloak,
        _ => return Err(UserError::InvalidInput(format!("Invalid provider: {}", provider))),
    };
    
    // Get the authorization URL
    let url = service.get_oauth_authorization_url(provider).await?;
    
    // Redirect to the authorization URL
    Ok(Redirect::to(url.as_str()))
}

/// Handle OAuth callback
async fn oauth_callback(
    State(service): State<Arc<UserService>>,
    Path(provider): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, UserError> {
    // Parse provider
    let provider = match provider.to_lowercase().as_str() {
        "github" => OAuthProvider::Github,
        "google" => OAuthProvider::Google,
        "keycloak" => OAuthProvider::Keycloak,
        _ => return Err(UserError::InvalidInput(format!("Invalid provider: {}", provider))),
    };
    
    // Get the code from the query parameters
    let code = params.get("code")
        .ok_or_else(|| UserError::InvalidInput("No code provided".to_string()))?;
        
    // Handle the OAuth callback
    let (user, tokens, is_new_user) = service.handle_oauth_callback(provider, code).await?;
    
    // In a real implementation, you might want to redirect to a frontend page
    // and pass the tokens as query parameters or cookies
    
    // For now, we'll just return the tokens
    Ok(Json(AuthResponse { 
        user, 
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
        token_type: tokens.token_type,
    }))
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