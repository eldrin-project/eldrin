use crate::modules::user::models::{User, UserProfile, UserRole, ExternalAuth};
use sqlx::{PgPool, Error};
use sqlx::postgres::PgQueryResult;
use sqlx::types::Uuid;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use serde_json::Value;

/// Repository for user-related database operations
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    /// Create a new user repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    
    /// Create a new user
    pub async fn create_user(&self, user: &User) -> Result<User, sqlx::Error> {
        let role = format!("{:?}", user.role);
        
        sqlx::query!(
            r#"
            INSERT INTO users (id, email, phone, username, created_at, updated_at, last_login, active, email_verified, phone_verified, role)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
            user.id,
            user.email,
            user.phone,
            user.username,
            user.created_at,
            user.updated_at,
            user.last_login,
            user.active,
            user.email_verified,
            user.phone_verified,
            role,
        )
        .execute(&self.pool)
        .await?;
        
        Ok(user.clone())
    }
    
    /// Create a provisional user with email
    pub async fn create_provisional_user(&self, email: &str, username: &str) -> Result<User, sqlx::Error> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        
        let user = User {
            id,
            email: Some(email.to_string()),
            phone: None,
            username: username.to_string(),
            created_at: now,
            updated_at: now,
            last_login: None,
            active: true,
            email_verified: false,
            phone_verified: false,
            role: UserRole::User,
            roles: None,
            permissions: None,
        };
        
        self.create_user(&user).await?;
        
        Ok(user)
    }
    
    /// Create a provisional user with phone
    pub async fn create_provisional_user_with_phone(&self, phone: &str, username: &str) -> Result<User, sqlx::Error> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        
        let user = User {
            id,
            email: None,
            phone: Some(phone.to_string()),
            username: username.to_string(),
            created_at: now,
            updated_at: now,
            last_login: None,
            active: true,
            email_verified: false,
            phone_verified: false,
            role: UserRole::User,
            roles: None,
            permissions: None,
        };
        
        self.create_user(&user).await?;
        
        Ok(user)
    }
    
    /// Create a user from OAuth
    pub async fn create_oauth_user(
        &self,
        email: Option<&str>,
        username: &str,
        display_name: &str,
        avatar_url: Option<&str>,
    ) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        
        // Create the user
        let email_verified = email.is_some();
        
        sqlx::query!(
            r#"
            INSERT INTO users (id, email, username, created_at, updated_at, active, email_verified, phone_verified, role)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            id,
            email,
            username,
            now,
            now,
            true,
            email_verified,
            false,
            "User", // Role as string
        )
        .execute(&self.pool)
        .await?;
        
        // Create the profile
        sqlx::query!(
            r#"
            INSERT INTO user_profiles (user_id, display_name, avatar_url, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            id,
            display_name,
            avatar_url,
            now,
            now,
        )
        .execute(&self.pool)
        .await?;
        
        Ok(id)
    }
    
    /// Store a password hash for a user
    pub async fn store_password_hash(&self, user_id: Uuid, hash: &str) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE users
            SET password_hash = $1, updated_at = $2
            WHERE id = $3
            "#,
            hash,
            Utc::now(),
            user_id,
        )
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    /// Find a user by ID
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, sqlx::Error> {
        let record = sqlx::query!(
            r#"
            SELECT id, email, phone, username, password_hash, created_at, updated_at, last_login, active, email_verified, phone_verified, role
            FROM users
            WHERE id = $1
            "#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(record.map(|r| User {
            id: r.id,
            email: r.email,
            phone: r.phone,
            username: r.username,
            created_at: r.created_at,
            updated_at: r.updated_at,
            last_login: r.last_login,
            active: r.active,
            email_verified: r.email_verified,
            phone_verified: r.phone_verified,
            role: match r.role.as_str() {
                "Admin" => UserRole::Admin,
                "Guest" => UserRole::Guest,
                _ => UserRole::User,
            },
            roles: None,
            permissions: None,
        }))
    }
    
    /// Find a user by email
    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>, sqlx::Error> {
        let record = sqlx::query!(
            r#"
            SELECT id, email, phone, username, password_hash, created_at, updated_at, last_login, active, email_verified, phone_verified, role
            FROM users
            WHERE email = $1
            "#,
            email,
        )
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(record.map(|r| User {
            id: r.id,
            email: r.email,
            phone: r.phone,
            username: r.username,
            created_at: r.created_at,
            updated_at: r.updated_at,
            last_login: r.last_login,
            active: r.active,
            email_verified: r.email_verified,
            phone_verified: r.phone_verified,
            role: match r.role.as_str() {
                "Admin" => UserRole::Admin,
                "Guest" => UserRole::Guest,
                _ => UserRole::User,
            },
            roles: None,
            permissions: None,
        }))
    }
    
    /// Find a user by phone
    pub async fn find_by_phone(&self, phone: &str) -> Result<Option<User>, sqlx::Error> {
        let record = sqlx::query!(
            r#"
            SELECT id, email, phone, username, password_hash, created_at, updated_at, last_login, active, email_verified, phone_verified, role
            FROM users
            WHERE phone = $1
            "#,
            phone,
        )
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(record.map(|r| User {
            id: r.id,
            email: r.email,
            phone: r.phone,
            username: r.username,
            created_at: r.created_at,
            updated_at: r.updated_at,
            last_login: r.last_login,
            active: r.active,
            email_verified: r.email_verified,
            phone_verified: r.phone_verified,
            role: match r.role.as_str() {
                "Admin" => UserRole::Admin,
                "Guest" => UserRole::Guest,
                _ => UserRole::User,
            },
            roles: None,
            permissions: None,
        }))
    }
    
    /// Find a user by username
    pub async fn find_by_username(&self, username: &str) -> Result<Option<User>, sqlx::Error> {
        let record = sqlx::query!(
            r#"
            SELECT id, email, phone, username, password_hash, created_at, updated_at, last_login, active, email_verified, phone_verified, role
            FROM users
            WHERE username = $1
            "#,
            username,
        )
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(record.map(|r| User {
            id: r.id,
            email: r.email,
            phone: r.phone,
            username: r.username,
            created_at: r.created_at,
            updated_at: r.updated_at,
            last_login: r.last_login,
            active: r.active,
            email_verified: r.email_verified,
            phone_verified: r.phone_verified,
            role: match r.role.as_str() {
                "Admin" => UserRole::Admin,
                "Guest" => UserRole::Guest,
                _ => UserRole::User,
            },
            roles: None,
            permissions: None,
        }))
    }
    
    /// Find a user by external auth provider
    pub async fn find_by_external_auth(&self, provider: &str, provider_user_id: &str) -> Result<Option<(Uuid, Uuid)>, sqlx::Error> {
        let record = sqlx::query!(
            r#"
            SELECT id, user_id
            FROM user_external_auths
            WHERE provider = $1 AND provider_user_id = $2
            "#,
            provider,
            provider_user_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(record.map(|r| (r.user_id, r.id)))
    }
    
    /// Update a user
    pub async fn update_user(&self, user: &User) -> Result<User, sqlx::Error> {
        let role = format!("{:?}", user.role);
        
        sqlx::query!(
            r#"
            UPDATE users
            SET email = $1, phone = $2, username = $3, updated_at = $4, 
                active = $5, email_verified = $6, phone_verified = $7, role = $8
            WHERE id = $9
            "#,
            user.email,
            user.phone,
            user.username,
            Utc::now(),
            user.active,
            user.email_verified,
            user.phone_verified,
            role,
            user.id,
        )
        .execute(&self.pool)
        .await?;
        
        Ok(user.clone())
    }
    
    /// Update a user's last login time
    pub async fn update_last_login(&self, user_id: Uuid) -> Result<(), sqlx::Error> {
        let now = Utc::now();
        
        sqlx::query!(
            r#"
            UPDATE users
            SET last_login = $1, updated_at = $2
            WHERE id = $3
            "#,
            now,
            now,
            user_id,
        )
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    /// Get user profile
    pub async fn get_profile(&self, user_id: Uuid) -> Result<Option<UserProfile>, sqlx::Error> {
        let record = sqlx::query!(
            r#"
            SELECT user_id, display_name, avatar_url, locale, timezone, metadata
            FROM user_profiles
            WHERE user_id = $1
            "#,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(record.map(|r| {
            let metadata: Option<HashMap<String, serde_json::Value>> = r.metadata
                .map(|json| {
                    let mut map = HashMap::new();
                    if let Some(obj) = json.as_object() {
                        for (k, v) in obj {
                            map.insert(k.clone(), v.clone());
                        }
                    }
                    map
                });
                
            UserProfile {
                user_id: r.user_id,
                display_name: r.display_name,
                avatar_url: r.avatar_url,
                locale: r.locale,
                timezone: r.timezone,
                metadata,
            }
        }))
    }
    
    /// Update user profile
    pub async fn update_profile(&self, profile: &UserProfile) -> Result<UserProfile, sqlx::Error> {
        let metadata: Option<serde_json::Value> = profile.metadata.as_ref()
            .map(|m| serde_json::to_value(m).unwrap_or(serde_json::Value::Null));
            
        // Check if profile exists
        let exists = sqlx::query!(
            r#"
            SELECT 1 as "exists" FROM user_profiles WHERE user_id = $1
            "#,
            profile.user_id,
        )
        .fetch_optional(&self.pool)
        .await?
        .is_some();
        
        if exists {
            sqlx::query!(
                r#"
                UPDATE user_profiles
                SET display_name = $1, avatar_url = $2, locale = $3, timezone = $4, metadata = $5, updated_at = $6
                WHERE user_id = $7
                "#,
                profile.display_name,
                profile.avatar_url,
                profile.locale,
                profile.timezone,
                metadata,
                Utc::now(),
                profile.user_id,
            )
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query!(
                r#"
                INSERT INTO user_profiles (user_id, display_name, avatar_url, locale, timezone, metadata, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                "#,
                profile.user_id,
                profile.display_name,
                profile.avatar_url,
                profile.locale,
                profile.timezone,
                metadata,
                Utc::now(),
                Utc::now(),
            )
            .execute(&self.pool)
            .await?;
        }
        
        Ok(profile.clone())
    }
    
    /// Get external auth providers for a user
    pub async fn get_external_auth(&self, user_id: Uuid) -> Result<Vec<ExternalAuth>, sqlx::Error> {
        let records = sqlx::query!(
            r#"
            SELECT id, user_id, provider, provider_user_id, access_token, refresh_token, expires_at, provider_data
            FROM user_external_auths
            WHERE user_id = $1
            "#,
            user_id,
        )
        .fetch_all(&self.pool)
        .await?;
        
        Ok(records.into_iter().map(|r| {
            ExternalAuth {
                user_id: r.user_id,
                provider: r.provider,
                provider_user_id: r.provider_user_id,
                access_token: r.access_token,
                refresh_token: r.refresh_token,
                expires_at: r.expires_at,
                provider_data: r.provider_data,
            }
        }).collect())
    }
    
    /// Add an external auth provider for a user
    pub async fn add_external_auth(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_user_id: &str,
        access_token: &str,
        refresh_token: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
        provider_data: Option<&Value>,
    ) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        
        sqlx::query!(
            r#"
            INSERT INTO user_external_auths (id, user_id, provider, provider_user_id, access_token, refresh_token, expires_at, provider_data, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
            id,
            user_id,
            provider,
            provider_user_id,
            access_token,
            refresh_token,
            expires_at,
            provider_data,
            now,
            now,
        )
        .execute(&self.pool)
        .await?;
        
        Ok(id)
    }
    
    /// Update an external auth provider for a user
    pub async fn update_external_auth(
        &self,
        user_id: Uuid,
        provider: &str,
        access_token: &str,
        refresh_token: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
        provider_data: Option<&Value>,
    ) -> Result<(), sqlx::Error> {
        let now = Utc::now();
        
        sqlx::query!(
            r#"
            UPDATE user_external_auths
            SET access_token = $1, refresh_token = $2, expires_at = $3, provider_data = $4, updated_at = $5
            WHERE user_id = $6 AND provider = $7
            "#,
            access_token,
            refresh_token,
            expires_at,
            provider_data,
            now,
            user_id,
            provider,
        )
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    /// Check for any admin users
    pub async fn has_admin_users(&self) -> Result<bool, sqlx::Error> {
        let count = sqlx::query!(
            r#"
            SELECT COUNT(*) as count
            FROM users
            WHERE role = 'Admin'
            "#,
        )
        .fetch_one(&self.pool)
        .await?
        .count
        .unwrap_or(0);
        
        Ok(count > 0)
    }
}