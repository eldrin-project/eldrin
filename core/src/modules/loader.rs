use std::path::{Path, PathBuf};
use std::fs;
use std::error::Error;
use tracing::{info, error, warn};

use crate::modules::types::{Module, ModuleManifest};

/// Responsible for discovering and loading modules from the filesystem
pub struct ModuleLoader {
    /// Path to core modules directory
    core_modules_path: PathBuf,
    
    /// Path to custom modules directory
    custom_modules_path: PathBuf,
}

impl ModuleLoader {
    /// Create a new module loader with specified paths
    pub fn new(core_path: impl AsRef<Path>, custom_path: impl AsRef<Path>) -> Self {
        Self {
            core_modules_path: core_path.as_ref().to_path_buf(),
            custom_modules_path: custom_path.as_ref().to_path_buf(),
        }
    }
    
    /// Create a module loader with default paths
    pub fn with_default_paths() -> Self {
        let current_dir = std::env::current_dir().expect("Failed to get current directory");
        Self {
            core_modules_path: current_dir.join("core/src/modules"),
            custom_modules_path: current_dir.join("modules"),
        }
    }
    
    /// Discover all available modules in both core and custom directories
    pub fn discover_modules(&self) -> Vec<Module> {
        let mut modules = Vec::new();
        
        // Discover core modules
        if let Err(err) = self.discover_in_directory(&self.core_modules_path, true, &mut modules) {
            error!("Error discovering core modules: {}", err);
        }
        
        // Discover custom modules
        if let Err(err) = self.discover_in_directory(&self.custom_modules_path, false, &mut modules) {
            error!("Error discovering custom modules: {}", err);
        }
        
        info!("Discovered {} modules ({} core, {} custom)", 
            modules.len(),
            modules.iter().filter(|m| m.is_core).count(),
            modules.iter().filter(|m| !m.is_core).count()
        );
        
        modules
    }
    
    /// Internal method to discover modules in a directory
    fn discover_in_directory(
        &self, 
        dir_path: &Path, 
        is_core: bool, 
        modules: &mut Vec<Module>
    ) -> Result<(), Box<dyn Error>> {
        if !dir_path.exists() {
            warn!("Module directory does not exist: {}", dir_path.display());
            return Ok(());
        }
        
        for entry in fs::read_dir(dir_path)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() {
                // Look for manifest.json in each directory
                let manifest_path = path.join("manifest.json");
                if manifest_path.exists() {
                    match self.load_module_from_manifest(&manifest_path, is_core) {
                        Ok(module) => modules.push(module),
                        Err(err) => error!("Failed to load module from {}: {}", manifest_path.display(), err),
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Load a module from its manifest file
    fn load_module_from_manifest(
        &self, 
        manifest_path: &Path, 
        is_core: bool
    ) -> Result<Module, Box<dyn Error>> {
        let manifest_content = fs::read_to_string(manifest_path)?;
        let manifest: ModuleManifest = serde_json::from_str(&manifest_content)?;
        
        let module = Module {
            manifest,
            path: manifest_path.parent().unwrap().to_string_lossy().to_string(),
            is_core,
            active: false, // Modules start inactive until explicitly activated
        };
        
        Ok(module)
    }
}