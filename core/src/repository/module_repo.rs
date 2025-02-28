use sqlx::{Pool, Postgres};
use tracing::{error, info};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use crate::models::db::DbModule;
use crate::modules::{Module, ModuleManifest, ModuleDependency};

#[derive(Debug, thiserror::Error)]
pub enum ModuleRepoError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone)]
pub struct ModuleRepository {
    pool: Arc<Pool<Postgres>>,
}

impl ModuleRepository {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { 
            pool: Arc::new(pool)
        }
    }
    
    /// Save a module to the database
    pub async fn save_module(&self, module: &Module) -> Result<DbModule, ModuleRepoError> {
        // Convert dependencies to JSON if they exist
        let dependencies = if let Some(deps) = &module.manifest.dependencies {
            Some(json!(deps))
        } else {
            None
        };
        
        // Convert config to JSON if it exists
        let config = if let Some(cfg) = &module.manifest.config {
            Some(json!(cfg))
        } else {
            None
        };
        
        let db_module = sqlx::query_as!(DbModule,
            r#"
            INSERT INTO modules (
                name, version, description, author, is_core, active, path, 
                dependencies, repository, config
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (name) 
            DO UPDATE SET
                version = EXCLUDED.version,
                description = EXCLUDED.description,
                author = EXCLUDED.author,
                is_core = EXCLUDED.is_core,
                active = EXCLUDED.active,
                path = EXCLUDED.path,
                dependencies = EXCLUDED.dependencies,
                repository = EXCLUDED.repository,
                config = EXCLUDED.config,
                updated_at = NOW()
            RETURNING 
                id, name, version, description, author, is_core, active, path,
                dependencies as "dependencies: serde_json::Value", repository, 
                config as "config: serde_json::Value", created_at, updated_at
            "#,
            module.manifest.name,
            module.manifest.version,
            module.manifest.description,
            module.manifest.author,
            module.is_core,
            module.active,
            module.path,
            dependencies as Option<serde_json::Value>,
            module.manifest.repository,
            config as Option<serde_json::Value>
        )
        .fetch_one(&*self.pool)
        .await?;
        
        info!("Saved module {} to database", module.manifest.name);
        Ok(db_module)
    }
    
    /// Get a module by name
    pub async fn get_module_by_name(&self, name: &str) -> Result<Option<DbModule>, ModuleRepoError> {
        let result = sqlx::query_as!(DbModule,
            r#"
            SELECT 
                id, name, version, description, author, is_core, active, path,
                dependencies as "dependencies: serde_json::Value", repository, 
                config as "config: serde_json::Value", created_at, updated_at
            FROM modules
            WHERE name = $1
            "#,
            name
        )
        .fetch_optional(&*self.pool)
        .await?;
        
        Ok(result)
    }
    
    /// Get all modules
    pub async fn get_all_modules(&self) -> Result<Vec<DbModule>, ModuleRepoError> {
        let modules = sqlx::query_as!(DbModule,
            r#"
            SELECT 
                id, name, version, description, author, is_core, active, path,
                dependencies as "dependencies: serde_json::Value", repository, 
                config as "config: serde_json::Value", created_at, updated_at
            FROM modules
            ORDER BY name
            "#
        )
        .fetch_all(&*self.pool)
        .await?;
        
        Ok(modules)
    }
    
    /// Get all active modules
    pub async fn get_active_modules(&self) -> Result<Vec<DbModule>, ModuleRepoError> {
        let modules = sqlx::query_as!(DbModule,
            r#"
            SELECT 
                id, name, version, description, author, is_core, active, path,
                dependencies as "dependencies: serde_json::Value", repository, 
                config as "config: serde_json::Value", created_at, updated_at
            FROM modules
            WHERE active = true
            ORDER BY name
            "#
        )
        .fetch_all(&*self.pool)
        .await?;
        
        Ok(modules)
    }
    
    /// Update module active status
    pub async fn update_module_active_status(&self, name: &str, active: bool) -> Result<(), ModuleRepoError> {
        sqlx::query!(
            r#"
            UPDATE modules
            SET active = $1, updated_at = NOW()
            WHERE name = $2
            "#,
            active,
            name
        )
        .execute(&*self.pool)
        .await?;
        
        info!("Updated active status of module {} to {}", name, active);
        Ok(())
    }
    
    /// Delete a module
    pub async fn delete_module(&self, name: &str) -> Result<(), ModuleRepoError> {
        sqlx::query!(
            r#"
            DELETE FROM modules
            WHERE name = $1
            "#,
            name
        )
        .execute(&*self.pool)
        .await?;
        
        info!("Deleted module {}", name);
        Ok(())
    }
    
    /// Convert a database module to a Module struct
    pub fn to_module(&self, db_module: DbModule) -> Result<Module, ModuleRepoError> {
        // Convert dependencies from JSON if they exist
        let dependencies = if let Some(deps_json) = db_module.dependencies {
            let deps: Vec<ModuleDependency> = serde_json::from_value(deps_json)?;
            Some(deps)
        } else {
            None
        };
        
        // Convert config from JSON if it exists
        let config = if let Some(cfg_json) = db_module.config {
            let cfg: HashMap<String, serde_json::Value> = serde_json::from_value(cfg_json)?;
            Some(cfg)
        } else {
            None
        };
        
        let manifest = ModuleManifest {
            name: db_module.name,
            version: db_module.version,
            description: db_module.description,
            author: db_module.author,
            dependencies,
            repository: db_module.repository,
            config,
        };
        
        let module = Module {
            manifest,
            path: db_module.path,
            is_core: db_module.is_core,
            active: db_module.active,
        };
        
        Ok(module)
    }
}