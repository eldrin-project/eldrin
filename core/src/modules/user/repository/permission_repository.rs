use crate::modules::user::models::Permission;
use sqlx::{PgPool, Error};
use sqlx::types::Uuid;
use chrono::Utc;

/// Repository for permission-related database operations
pub struct PermissionRepository {
    pool: PgPool,
}

impl PermissionRepository {
    /// Create a new permission repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    
    /// Create a new permission
    pub async fn create_permission(
        &self, 
        name: &str, 
        resource: &str, 
        action: &str, 
        description: Option<&str>
    ) -> Result<Permission, Error> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        
        sqlx::query!(
            r#"
            INSERT INTO permissions (id, name, description, resource, action, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            id,
            name,
            description,
            resource,
            action,
            now,
            now,
        )
        .execute(&self.pool)
        .await?;
        
        Ok(Permission {
            id,
            name: name.to_string(),
            description: description.map(ToString::to_string),
            resource: resource.to_string(),
            action: action.to_string(),
            created_at: now,
            updated_at: now,
        })
    }
    
    /// Get a permission by ID
    pub async fn get_permission_by_id(&self, id: Uuid) -> Result<Option<Permission>, Error> {
        let record = sqlx::query!(
            r#"
            SELECT id, name, description, resource, action, created_at, updated_at
            FROM permissions
            WHERE id = $1
            "#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(record.map(|r| Permission {
            id: r.id,
            name: r.name,
            description: r.description,
            resource: r.resource,
            action: r.action,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }
    
    /// Get a permission by name
    pub async fn get_permission_by_name(&self, name: &str) -> Result<Option<Permission>, Error> {
        let record = sqlx::query!(
            r#"
            SELECT id, name, description, resource, action, created_at, updated_at
            FROM permissions
            WHERE name = $1
            "#,
            name,
        )
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(record.map(|r| Permission {
            id: r.id,
            name: r.name,
            description: r.description,
            resource: r.resource,
            action: r.action,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }
    
    /// Get a permission by resource and action
    pub async fn get_permission_by_resource_action(&self, resource: &str, action: &str) -> Result<Option<Permission>, Error> {
        let record = sqlx::query!(
            r#"
            SELECT id, name, description, resource, action, created_at, updated_at
            FROM permissions
            WHERE resource = $1 AND action = $2
            "#,
            resource,
            action,
        )
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(record.map(|r| Permission {
            id: r.id,
            name: r.name,
            description: r.description,
            resource: r.resource,
            action: r.action,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }
    
    /// Get all permissions
    pub async fn get_all_permissions(&self) -> Result<Vec<Permission>, Error> {
        let records = sqlx::query!(
            r#"
            SELECT id, name, description, resource, action, created_at, updated_at
            FROM permissions
            ORDER BY resource, action
            "#,
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
    
    /// Get all permissions for a resource
    pub async fn get_permissions_by_resource(&self, resource: &str) -> Result<Vec<Permission>, Error> {
        let records = sqlx::query!(
            r#"
            SELECT id, name, description, resource, action, created_at, updated_at
            FROM permissions
            WHERE resource = $1
            ORDER BY action
            "#,
            resource,
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
    
    /// Update a permission
    pub async fn update_permission(
        &self, 
        id: Uuid, 
        name: &str, 
        description: Option<&str>, 
        resource: &str, 
        action: &str
    ) -> Result<Permission, Error> {
        let now = Utc::now();
        
        sqlx::query!(
            r#"
            UPDATE permissions
            SET name = $1, description = $2, resource = $3, action = $4, updated_at = $5
            WHERE id = $6
            "#,
            name,
            description,
            resource,
            action,
            now,
            id,
        )
        .execute(&self.pool)
        .await?;
        
        Ok(Permission {
            id,
            name: name.to_string(),
            description: description.map(ToString::to_string),
            resource: resource.to_string(),
            action: action.to_string(),
            created_at: now, // We don't know the original creation time here
            updated_at: now,
        })
    }
    
    /// Delete a permission
    pub async fn delete_permission(&self, id: Uuid) -> Result<(), Error> {
        sqlx::query!(
            r#"
            DELETE FROM permissions
            WHERE id = $1
            "#,
            id,
        )
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
}