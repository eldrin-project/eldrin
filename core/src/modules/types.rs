use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a module manifest file that describes a module's metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleManifest {
    /// Name of the module
    pub name: String,
    
    /// Version of the module
    pub version: String,
    
    /// Description of what the module does
    pub description: Option<String>,
    
    /// Author information
    pub author: Option<String>,
    
    /// Module dependencies
    pub dependencies: Option<Vec<ModuleDependency>>,
    
    /// Optional Git repository URL for module source
    pub repository: Option<String>,
    
    /// Custom configuration options for the module
    pub config: Option<HashMap<String, serde_json::Value>>,
}

/// Represents a dependency on another module
#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleDependency {
    /// Name of the required module
    pub name: String,
    
    /// Version requirement
    pub version: String,
}

/// Represents a loaded module in the application
#[derive(Debug)]
pub struct Module {
    /// Module manifest information
    pub manifest: ModuleManifest,
    
    /// Path to the module on disk
    pub path: String,
    
    /// Whether the module is a core module or custom module
    pub is_core: bool,
    
    /// Whether the module is currently active
    pub active: bool,
}