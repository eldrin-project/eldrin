use std::collections::{HashMap, HashSet};
use std::error::Error;
use tracing::{info, error, warn};

use crate::modules::types::{Module, ModuleManifest};
use crate::modules::loader::ModuleLoader;

/// Errors that can occur during module operations
#[derive(Debug, thiserror::Error)]
pub enum ModuleError {
    #[error("Module not found: {0}")]
    NotFound(String),
    
    #[error("Module dependency not satisfied: {module} requires {dependency}")]
    DependencyNotSatisfied { module: String, dependency: String },
    
    #[error("Circular dependency detected: {0}")]
    CircularDependency(String),
    
    #[error("Invalid module: {0}")]
    InvalidModule(String),
}

/// Manages module lifecycle (loading, activation, deactivation)
pub struct ModuleManager {
    /// All available modules indexed by name
    modules: HashMap<String, Module>,
    
    /// Module loader for discovering modules
    loader: ModuleLoader,
}

impl ModuleManager {
    /// Create a new module manager with default paths
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
            loader: ModuleLoader::with_default_paths(),
        }
    }
    
    /// Initialize the module manager by discovering all available modules
    pub fn initialize(&mut self) -> Result<(), Box<dyn Error>> {
        info!("Initializing module manager");
        let discovered_modules = self.loader.discover_modules();
        
        for module in discovered_modules {
            self.modules.insert(module.manifest.name.clone(), module);
        }
        
        info!("Module manager initialized with {} modules", self.modules.len());
        Ok(())
    }
    
    /// Get a list of all available modules
    pub fn get_all_modules(&self) -> Vec<&Module> {
        self.modules.values().collect()
    }
    
    /// Get a module by name
    pub fn get_module(&self, name: &str) -> Option<&Module> {
        self.modules.get(name)
    }
    
    /// Get a mutable reference to a module by name
    pub fn get_module_mut(&mut self, name: &str) -> Option<&mut Module> {
        self.modules.get_mut(name)
    }
    
    /// Activate a module and its dependencies
    pub fn activate_module(&mut self, name: &str) -> Result<(), ModuleError> {
        info!("Activating module: {}", name);
        
        // Check if module exists
        if !self.modules.contains_key(name) {
            return Err(ModuleError::NotFound(name.to_string()));
        }
        
        // Track visited modules to detect circular dependencies
        let mut visited = HashSet::new();
        let mut activation_stack = Vec::new();
        
        // Perform DFS to resolve dependencies
        self.resolve_dependencies(name, &mut visited, &mut activation_stack)?;
        
        // Activate modules in the correct order (dependencies first)
        for module_name in activation_stack {
            if let Some(module) = self.modules.get_mut(&module_name) {
                info!("Activating module: {}", module_name);
                module.active = true;
            }
        }
        
        Ok(())
    }
    
    /// Recursive function to resolve module dependencies
    fn resolve_dependencies(
        &self,
        module_name: &str,
        visited: &mut HashSet<String>,
        activation_stack: &mut Vec<String>
    ) -> Result<(), ModuleError> {
        // If we've already processed this module, skip it
        if activation_stack.contains(&module_name.to_string()) {
            return Ok(());
        }
        
        // Check for circular dependencies
        if visited.contains(module_name) {
            return Err(ModuleError::CircularDependency(module_name.to_string()));
        }
        
        visited.insert(module_name.to_string());
        
        let module = self.modules.get(module_name)
            .ok_or_else(|| ModuleError::NotFound(module_name.to_string()))?;
        
        // Process dependencies if any
        if let Some(deps) = &module.manifest.dependencies {
            for dep in deps {
                let dep_name = &dep.name;
                
                // Check if dependency exists
                if !self.modules.contains_key(dep_name) {
                    return Err(ModuleError::DependencyNotSatisfied { 
                        module: module_name.to_string(), 
                        dependency: dep_name.clone(),
                    });
                }
                
                // Recursively resolve this dependency
                self.resolve_dependencies(dep_name, visited, activation_stack)?;
            }
        }
        
        // Add this module to the activation stack after its dependencies
        activation_stack.push(module_name.to_string());
        
        Ok(())
    }
    
    /// Deactivate a module
    pub fn deactivate_module(&mut self, name: &str) -> Result<(), ModuleError> {
        let module = self.modules.get_mut(name)
            .ok_or_else(|| ModuleError::NotFound(name.to_string()))?;
        
        info!("Deactivating module: {}", name);
        module.active = false;
        
        Ok(())
    }
}