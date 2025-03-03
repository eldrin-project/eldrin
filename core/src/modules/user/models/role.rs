use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Uuid;

use super::Permission;

/// Represents a role in the system
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct Role {
    /// Unique role identifier
    pub id: Uuid,
    
    /// Role name
    pub name: String,
    
    /// Role description
    pub description: Option<String>,
    
    /// When the role was created
    pub created_at: DateTime<Utc>,
    
    /// When the role was last updated
    pub updated_at: DateTime<Utc>,
    
    /// The permissions associated with this role (populated when loaded with permissions)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<Permission>>,
}

/// Mapping between a role and a permission
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RolePermission {
    /// Reference to the role
    pub role_id: Uuid,
    
    /// Reference to the permission
    pub permission_id: Uuid,
    
    /// When the mapping was created
    pub created_at: DateTime<Utc>,
}