use crate::modules::user::models::{User, Role, Permission};
use crate::modules::user::repository::{RoleRepository, PermissionRepository, UserRepository};
use sqlx::{PgPool, Error};
use sqlx::types::Uuid;
use std::collections::HashSet;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthorizationError {
    #[error("Permission denied")]
    PermissionDenied,

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// Service for authorization-related operations
pub struct AuthorizationService {
    role_repo: RoleRepository,
    permission_repo: PermissionRepository,
    user_repo: UserRepository,
}

impl AuthorizationService {
    /// Create a new authorization service
    pub fn new(pool: PgPool) -> Self {
        Self {
            role_repo: RoleRepository::new(pool.clone()),
            permission_repo: PermissionRepository::new(pool.clone()),
            user_repo: UserRepository::new(pool),
        }
    }
    
    /// Create a new role
    pub async fn create_role(&self, name: &str, description: Option<&str>) -> Result<Role, AuthorizationError> {
        // Validate input
        if name.is_empty() {
            return Err(AuthorizationError::InvalidInput("Role name cannot be empty".to_string()));
        }
        
        // Check if role already exists
        if let Some(_) = self.role_repo.get_role_by_name(name).await? {
            return Err(AuthorizationError::InvalidInput(format!("Role '{}' already exists", name)));
        }
        
        let role = self.role_repo.create_role(name, description).await?;
        Ok(role)
    }
    
    /// Get a role by ID
    pub async fn get_role(&self, id: Uuid) -> Result<Option<Role>, AuthorizationError> {
        let role = self.role_repo.get_role_by_id(id).await?;
        
        // Get permissions for this role if it exists
        if let Some(mut role) = role {
            let permissions = self.role_repo.get_role_permissions(role.id).await?;
            role.permissions = Some(permissions);
            Ok(Some(role))
        } else {
            Ok(None)
        }
    }
    
    /// Get a role by name
    pub async fn get_role_by_name(&self, name: &str) -> Result<Option<Role>, AuthorizationError> {
        let role = self.role_repo.get_role_by_name(name).await?;
        
        // Get permissions for this role if it exists
        if let Some(mut role) = role {
            let permissions = self.role_repo.get_role_permissions(role.id).await?;
            role.permissions = Some(permissions);
            Ok(Some(role))
        } else {
            Ok(None)
        }
    }
    
    /// Get all roles
    pub async fn get_all_roles(&self) -> Result<Vec<Role>, AuthorizationError> {
        let roles = self.role_repo.get_all_roles().await?;
        Ok(roles)
    }
    
    /// Update a role
    pub async fn update_role(&self, id: Uuid, name: &str, description: Option<&str>) -> Result<Role, AuthorizationError> {
        // Validate input
        if name.is_empty() {
            return Err(AuthorizationError::InvalidInput("Role name cannot be empty".to_string()));
        }
        
        // Check if role exists
        if self.role_repo.get_role_by_id(id).await?.is_none() {
            return Err(AuthorizationError::InvalidInput(format!("Role with ID {} does not exist", id)));
        }
        
        // Check if the new name conflicts with another role
        if let Some(existing_role) = self.role_repo.get_role_by_name(name).await? {
            if existing_role.id != id {
                return Err(AuthorizationError::InvalidInput(format!("Role name '{}' is already in use", name)));
            }
        }
        
        let role = self.role_repo.update_role(id, name, description).await?;
        Ok(role)
    }
    
    /// Delete a role
    pub async fn delete_role(&self, id: Uuid) -> Result<(), AuthorizationError> {
        // Check if role exists
        if self.role_repo.get_role_by_id(id).await?.is_none() {
            return Err(AuthorizationError::InvalidInput(format!("Role with ID {} does not exist", id)));
        }
        
        self.role_repo.delete_role(id).await?;
        Ok(())
    }
    
    /// Create a new permission
    pub async fn create_permission(
        &self, 
        name: &str, 
        resource: &str, 
        action: &str, 
        description: Option<&str>
    ) -> Result<Permission, AuthorizationError> {
        // Validate input
        if name.is_empty() {
            return Err(AuthorizationError::InvalidInput("Permission name cannot be empty".to_string()));
        }
        
        if resource.is_empty() {
            return Err(AuthorizationError::InvalidInput("Resource cannot be empty".to_string()));
        }
        
        if action.is_empty() {
            return Err(AuthorizationError::InvalidInput("Action cannot be empty".to_string()));
        }
        
        // Check if permission already exists
        if let Some(_) = self.permission_repo.get_permission_by_name(name).await? {
            return Err(AuthorizationError::InvalidInput(format!("Permission '{}' already exists", name)));
        }
        
        // Check if resource+action already exists
        if let Some(_) = self.permission_repo.get_permission_by_resource_action(resource, action).await? {
            return Err(AuthorizationError::InvalidInput(
                format!("Permission for resource '{}' and action '{}' already exists", resource, action)
            ));
        }
        
        let permission = self.permission_repo.create_permission(name, resource, action, description).await?;
        Ok(permission)
    }
    
    /// Get a permission by ID
    pub async fn get_permission(&self, id: Uuid) -> Result<Option<Permission>, AuthorizationError> {
        let permission = self.permission_repo.get_permission_by_id(id).await?;
        Ok(permission)
    }
    
    /// Get a permission by name
    pub async fn get_permission_by_name(&self, name: &str) -> Result<Option<Permission>, AuthorizationError> {
        let permission = self.permission_repo.get_permission_by_name(name).await?;
        Ok(permission)
    }
    
    /// Get a permission by resource and action
    pub async fn get_permission_by_resource_action(&self, resource: &str, action: &str) -> Result<Option<Permission>, AuthorizationError> {
        let permission = self.permission_repo.get_permission_by_resource_action(resource, action).await?;
        Ok(permission)
    }
    
    /// Get all permissions
    pub async fn get_all_permissions(&self) -> Result<Vec<Permission>, AuthorizationError> {
        let permissions = self.permission_repo.get_all_permissions().await?;
        Ok(permissions)
    }
    
    /// Update a permission
    pub async fn update_permission(
        &self, 
        id: Uuid, 
        name: &str, 
        description: Option<&str>, 
        resource: &str, 
        action: &str
    ) -> Result<Permission, AuthorizationError> {
        // Validate input
        if name.is_empty() {
            return Err(AuthorizationError::InvalidInput("Permission name cannot be empty".to_string()));
        }
        
        if resource.is_empty() {
            return Err(AuthorizationError::InvalidInput("Resource cannot be empty".to_string()));
        }
        
        if action.is_empty() {
            return Err(AuthorizationError::InvalidInput("Action cannot be empty".to_string()));
        }
        
        // Check if permission exists
        if self.permission_repo.get_permission_by_id(id).await?.is_none() {
            return Err(AuthorizationError::InvalidInput(format!("Permission with ID {} does not exist", id)));
        }
        
        // Check if the new name conflicts with another permission
        if let Some(existing_permission) = self.permission_repo.get_permission_by_name(name).await? {
            if existing_permission.id != id {
                return Err(AuthorizationError::InvalidInput(format!("Permission name '{}' is already in use", name)));
            }
        }
        
        // Check if the new resource+action conflicts with another permission
        if let Some(existing_permission) = self.permission_repo.get_permission_by_resource_action(resource, action).await? {
            if existing_permission.id != id {
                return Err(AuthorizationError::InvalidInput(
                    format!("Permission for resource '{}' and action '{}' already exists", resource, action)
                ));
            }
        }
        
        let permission = self.permission_repo.update_permission(id, name, description, resource, action).await?;
        Ok(permission)
    }
    
    /// Delete a permission
    pub async fn delete_permission(&self, id: Uuid) -> Result<(), AuthorizationError> {
        // Check if permission exists
        if self.permission_repo.get_permission_by_id(id).await?.is_none() {
            return Err(AuthorizationError::InvalidInput(format!("Permission with ID {} does not exist", id)));
        }
        
        self.permission_repo.delete_permission(id).await?;
        Ok(())
    }
    
    /// Assign a role to a user
    pub async fn assign_role_to_user(&self, user_id: Uuid, role_id: Uuid) -> Result<(), AuthorizationError> {
        // Check if user exists
        if self.user_repo.find_by_id(user_id).await?.is_none() {
            return Err(AuthorizationError::InvalidInput(format!("User with ID {} does not exist", user_id)));
        }
        
        // Check if role exists
        if self.role_repo.get_role_by_id(role_id).await?.is_none() {
            return Err(AuthorizationError::InvalidInput(format!("Role with ID {} does not exist", role_id)));
        }
        
        self.role_repo.assign_role_to_user(user_id, role_id).await?;
        Ok(())
    }
    
    /// Remove a role from a user
    pub async fn remove_role_from_user(&self, user_id: Uuid, role_id: Uuid) -> Result<(), AuthorizationError> {
        // We don't need to check if user or role exists since we're just removing a mapping
        
        self.role_repo.remove_role_from_user(user_id, role_id).await?;
        Ok(())
    }
    
    /// Get all roles for a user
    pub async fn get_user_roles(&self, user_id: Uuid) -> Result<Vec<Role>, AuthorizationError> {
        // Check if user exists
        if self.user_repo.find_by_id(user_id).await?.is_none() {
            return Err(AuthorizationError::InvalidInput(format!("User with ID {} does not exist", user_id)));
        }
        
        let roles = self.role_repo.get_user_roles(user_id).await?;
        Ok(roles)
    }
    
    /// Check if a user has a specific role
    pub async fn user_has_role(&self, user_id: Uuid, role_id: Uuid) -> Result<bool, AuthorizationError> {
        let has_role = self.role_repo.user_has_role(user_id, role_id).await?;
        Ok(has_role)
    }
    
    /// Check if a user has a role by name
    pub async fn user_has_role_by_name(&self, user_id: Uuid, role_name: &str) -> Result<bool, AuthorizationError> {
        let has_role = self.role_repo.user_has_role_by_name(user_id, role_name).await?;
        Ok(has_role)
    }
    
    /// Assign a permission to a role
    pub async fn assign_permission_to_role(&self, role_id: Uuid, permission_id: Uuid) -> Result<(), AuthorizationError> {
        // Check if role exists
        if self.role_repo.get_role_by_id(role_id).await?.is_none() {
            return Err(AuthorizationError::InvalidInput(format!("Role with ID {} does not exist", role_id)));
        }
        
        // Check if permission exists
        if self.permission_repo.get_permission_by_id(permission_id).await?.is_none() {
            return Err(AuthorizationError::InvalidInput(format!("Permission with ID {} does not exist", permission_id)));
        }
        
        self.role_repo.assign_permission_to_role(role_id, permission_id).await?;
        Ok(())
    }
    
    /// Remove a permission from a role
    pub async fn remove_permission_from_role(&self, role_id: Uuid, permission_id: Uuid) -> Result<(), AuthorizationError> {
        // We don't need to check if role or permission exists since we're just removing a mapping
        
        self.role_repo.remove_permission_from_role(role_id, permission_id).await?;
        Ok(())
    }
    
    /// Get all permissions for a role
    pub async fn get_role_permissions(&self, role_id: Uuid) -> Result<Vec<Permission>, AuthorizationError> {
        // Check if role exists
        if self.role_repo.get_role_by_id(role_id).await?.is_none() {
            return Err(AuthorizationError::InvalidInput(format!("Role with ID {} does not exist", role_id)));
        }
        
        let permissions = self.role_repo.get_role_permissions(role_id).await?;
        Ok(permissions)
    }
    
    /// Get all permissions for a user (through their roles)
    pub async fn get_user_permissions(&self, user_id: Uuid) -> Result<HashSet<Permission>, AuthorizationError> {
        // Check if user exists
        if self.user_repo.find_by_id(user_id).await?.is_none() {
            return Err(AuthorizationError::InvalidInput(format!("User with ID {} does not exist", user_id)));
        }
        
        let permissions = self.role_repo.get_user_permissions(user_id).await?;
        Ok(permissions)
    }
    
    /// Check if a user has a specific permission (through their roles)
    pub async fn user_has_permission(&self, user_id: Uuid, permission_id: Uuid) -> Result<bool, AuthorizationError> {
        let has_permission = self.role_repo.user_has_permission(user_id, permission_id).await?;
        Ok(has_permission)
    }
    
    /// Check if a user has permission for a specific resource and action
    pub async fn user_has_permission_for(&self, user_id: Uuid, resource: &str, action: &str) -> Result<bool, AuthorizationError> {
        let has_permission = self.role_repo.user_has_permission_for(user_id, resource, action).await?;
        Ok(has_permission)
    }
    
    /// Get a user with their roles and permissions populated
    pub async fn get_user_with_roles_and_permissions(&self, user_id: Uuid) -> Result<Option<User>, AuthorizationError> {
        // Get the user
        let user = match self.user_repo.find_by_id(user_id).await? {
            Some(user) => user,
            None => return Ok(None),
        };
        
        // Get the user's roles
        let roles = self.role_repo.get_user_roles(user_id).await?;
        
        // Get the user's permissions
        let permissions = self.role_repo.get_user_permissions(user_id).await?;
        
        // Create a new user with roles and permissions
        let user_with_auth = User {
            roles: Some(roles),
            permissions: Some(permissions),
            ..user
        };
        
        Ok(Some(user_with_auth))
    }
    
    /// Authorize a user for a specific resource and action
    pub async fn authorize(&self, user_id: Uuid, resource: &str, action: &str) -> Result<bool, AuthorizationError> {
        // Check if user has the permission
        let has_permission = self.user_has_permission_for(user_id, resource, action).await?;
        
        if !has_permission {
            return Err(AuthorizationError::PermissionDenied);
        }
        
        Ok(true)
    }
}