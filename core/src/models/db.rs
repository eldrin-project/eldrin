use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Represents a module in the database
#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct DbModule {
    /// Unique ID in the database
    pub id: i32,
    
    /// Name of the module
    pub name: String,
    
    /// Version of the module
    pub version: String,
    
    /// Description of the module
    pub description: Option<String>,
    
    /// Author information
    pub author: Option<String>,
    
    /// Whether this is a core module
    pub is_core: bool,
    
    /// Whether the module is active
    pub active: bool,
    
    /// Module path on disk
    pub path: String,
    
    /// JSON representation of module dependencies
    pub dependencies: Option<serde_json::Value>,
    
    /// Git repository URL
    pub repository: Option<String>,
    
    /// Module configuration as JSON
    pub config: Option<serde_json::Value>,
    
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}