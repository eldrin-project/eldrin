use crate::modules::user::models::{Role, Permission, RolePermission, UserRoleMapping};
use sqlx::{PgPool, Error};
use sqlx::types::Uuid;
use chrono::Utc;
use std::collections::HashSet;

/// Repository for role-related database operations
pub struct RoleRepository {
    pool: PgPool,
}

impl RoleRepository {
    /// Create a new role repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    
    /// Create a new role
    pub async fn create_role(&self, name: &str, description: Option<&str>) -> Result<Role, Error> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        
        sqlx::query!(
            r#"
            INSERT INTO roles (id, name, description, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            id,
            name,
            description,
            now,
            now,
        )
        .execute(&self.pool)
        .await?;
        
        Ok(Role {
            id,
            name: name.to_string(),
            description: description.map(ToString::to_string),
            created_at: now,
            updated_at: now,
            permissions: None,
        })
    }
    
    /// Get a role by ID
    pub async fn get_role_by_id(&self, id: Uuid) -> Result<Option<Role>, Error> {
        let record = sqlx::query!(
            r#"
            SELECT id, name, description, created_at, updated_at
            FROM roles
            WHERE id = $1
            "#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(record.map(|r| Role {
            id: r.id,
            name: r.name,
            description: r.description,
            created_at: r.created_at,
            updated_at: r.updated_at,
            permissions: None,
        }))
    }
    
    /// Get a role by name
    pub async fn get_role_by_name(&self, name: &str) -> Result<Option<Role>, Error> {
        let record = sqlx::query!(
            r#"
            SELECT id, name, description, created_at, updated_at
            FROM roles
            WHERE name = $1
            "#,
            name,
        )
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(record.map(|r| Role {
            id: r.id,
            name: r.name,
            description: r.description,
            created_at: r.created_at,
            updated_at: r.updated_at,
            permissions: None,
        }))
    }
    
    /// Get all roles
    pub async fn get_all_roles(&self) -> Result<Vec<Role>, Error> {
        let records = sqlx::query!(
            r#"
            SELECT id, name, description, created_at, updated_at
            FROM roles
            ORDER BY name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        
        Ok(records.into_iter().map(|r| Role {
            id: r.id,
            name: r.name,
            description: r.description,
            created_at: r.created_at,
            updated_at: r.updated_at,
            permissions: None,
        }).collect())
    }
    
    /// Update a role
    pub async fn update_role(&self, id: Uuid, name: &str, description: Option<&str>) -> Result<Role, Error> {
        let now = Utc::now();
        
        sqlx::query!(
            r#"
            UPDATE roles
            SET name = $1, description = $2, updated_at = $3
            WHERE id = $4
            "#,
            name,
            description,
            now,
            id,
        )
        .execute(&self.pool)
        .await?;
        
        Ok(Role {
            id,
            name: name.to_string(),
            description: description.map(ToString::to_string),
            created_at: now, // We don't know the original creation time here
            updated_at: now,
            permissions: None,
        })
    }
    
    /// Delete a role
    pub async fn delete_role(&self, id: Uuid) -> Result<(), Error> {
        sqlx::query!(
            r#"
            DELETE FROM roles
            WHERE id = $1
            "#,
            id,
        )
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    /// Assign a role to a user
    pub async fn assign_role_to_user(&self, user_id: Uuid, role_id: Uuid) -> Result<(), Error> {
        let now = Utc::now();
        
        // Check if mapping already exists
        let exists = sqlx::query!(
            r#"
            SELECT 1 as "exists"
            FROM user_roles
            WHERE user_id = $1 AND role_id = $2
            "#,
            user_id,
            role_id,
        )
        .fetch_optional(&self.pool)
        .await?
        .is_some();
        
        if !exists {
            sqlx::query!(
                r#"
                INSERT INTO user_roles (user_id, role_id, created_at)
                VALUES ($1, $2, $3)
                "#,
                user_id,
                role_id,
                now,
            )
            .execute(&self.pool)
            .await?;
        }
        
        Ok(())
    }
    
    /// Remove a role from a user
    pub async fn remove_role_from_user(&self, user_id: Uuid, role_id: Uuid) -> Result<(), Error> {
        sqlx::query!(
            r#"
            DELETE FROM user_roles
            WHERE user_id = $1 AND role_id = $2
            "#,
            user_id,
            role_id,
        )
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    /// Get all roles for a user
    pub async fn get_user_roles(&self, user_id: Uuid) -> Result<Vec<Role>, Error> {
        let records = sqlx::query!(
            r#"
            SELECT r.id, r.name, r.description, r.created_at, r.updated_at
            FROM roles r
            JOIN user_roles ur ON r.id = ur.role_id
            WHERE ur.user_id = $1
            ORDER BY r.name
            "#,
            user_id,
        )
        .fetch_all(&self.pool)
        .await?;
        
        Ok(records.into_iter().map(|r| Role {
            id: r.id,
            name: r.name,
            description: r.description,
            created_at: r.created_at,
            updated_at: r.updated_at,
            permissions: None,
        }).collect())
    }
    
    /// Get all users with a specific role
    pub async fn get_users_with_role(&self, role_id: Uuid) -> Result<Vec<Uuid>, Error> {
        let records = sqlx::query!(
            r#"
            SELECT user_id
            FROM user_roles
            WHERE role_id = $1
            "#,
            role_id,
        )
        .fetch_all(&self.pool)
        .await?;
        
        Ok(records.into_iter().map(|r| r.user_id).collect())
    }
    
    /// Check if a user has a specific role
    pub async fn user_has_role(&self, user_id: Uuid, role_id: Uuid) -> Result<bool, Error> {
        let record = sqlx::query!(
            r#"
            SELECT 1 as "exists"
            FROM user_roles
            WHERE user_id = $1 AND role_id = $2
            "#,
            user_id,
            role_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(record.is_some())
    }
    
    /// Check if a user has a role by name
    pub async fn user_has_role_by_name(&self, user_id: Uuid, role_name: &str) -> Result<bool, Error> {
        let record = sqlx::query!(
            r#"
            SELECT 1 as "exists"
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            WHERE ur.user_id = $1 AND r.name = $2
            "#,
            user_id,
            role_name,
        )
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(record.is_some())
    }
    
    /// Get all permissions for a role
    pub async fn get_role_permissions(&self, role_id: Uuid) -> Result<Vec<Permission>, Error> {
        let records = sqlx::query!(
            r#"
            SELECT p.id, p.name, p.description, p.resource, p.action, p.created_at, p.updated_at
            FROM permissions p
            JOIN role_permissions rp ON p.id = rp.permission_id
            WHERE rp.role_id = $1
            ORDER BY p.resource, p.action
            "#,
            role_id,
        )
        .fetch_all(&self.pool)
        .await?;
        
        Ok(records.into_iter().map(|r| Permission {
            id: r.id,
            name: r.name,
            description: r.description,
            resource: r.resource,
            action: r.action,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }).collect())
    }
    
    /// Assign a permission to a role
    pub async fn assign_permission_to_role(&self, role_id: Uuid, permission_id: Uuid) -> Result<(), Error> {
        let now = Utc::now();
        
        // Check if mapping already exists
        let exists = sqlx::query!(
            r#"
            SELECT 1 as "exists"
            FROM role_permissions
            WHERE role_id = $1 AND permission_id = $2
            "#,
            role_id,
            permission_id,
        )
        .fetch_optional(&self.pool)
        .await?
        .is_some();
        
        if !exists {
            sqlx::query!(
                r#"
                INSERT INTO role_permissions (role_id, permission_id, created_at)
                VALUES ($1, $2, $3)
                "#,
                role_id,
                permission_id,
                now,
            )
            .execute(&self.pool)
            .await?;
        }
        
        Ok(())
    }
    
    /// Remove a permission from a role
    pub async fn remove_permission_from_role(&self, role_id: Uuid, permission_id: Uuid) -> Result<(), Error> {
        sqlx::query!(
            r#"
            DELETE FROM role_permissions
            WHERE role_id = $1 AND permission_id = $2
            "#,
            role_id,
            permission_id,
        )
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    /// Get all permissions for a user (through their roles)
    pub async fn get_user_permissions(&self, user_id: Uuid) -> Result<HashSet<Permission>, Error> {
        let records = sqlx::query!(
            r#"
            SELECT DISTINCT p.id, p.name, p.description, p.resource, p.action, p.created_at, p.updated_at
            FROM permissions p
            JOIN role_permissions rp ON p.id = rp.permission_id
            JOIN user_roles ur ON rp.role_id = ur.role_id
            WHERE ur.user_id = $1
            ORDER BY p.resource, p.action
            "#,
            user_id,
        )
        .fetch_all(&self.pool)
        .await?;
        
        let permissions = records.into_iter().map(|r| Permission {
            id: r.id,
            name: r.name,
            description: r.description,
            resource: r.resource,
            action: r.action,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }).collect();
        
        Ok(permissions)
    }
    
    /// Check if a user has a specific permission (through their roles)
    pub async fn user_has_permission(&self, user_id: Uuid, permission_id: Uuid) -> Result<bool, Error> {
        let record = sqlx::query!(
            r#"
            SELECT 1 as "exists"
            FROM user_roles ur
            JOIN role_permissions rp ON ur.role_id = rp.role_id
            WHERE ur.user_id = $1 AND rp.permission_id = $2
            "#,
            user_id,
            permission_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(record.is_some())
    }
    
    /// Check if a user has permission for a specific resource and action
    pub async fn user_has_permission_for(&self, user_id: Uuid, resource: &str, action: &str) -> Result<bool, Error> {
        let record = sqlx::query!(
            r#"
            SELECT 1 as "exists"
            FROM user_roles ur
            JOIN role_permissions rp ON ur.role_id = rp.role_id
            JOIN permissions p ON rp.permission_id = p.id
            WHERE ur.user_id = $1 AND p.resource = $2 AND p.action = $3
            "#,
            user_id,
            resource,
            action,
        )
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(record.is_some())
    }
}