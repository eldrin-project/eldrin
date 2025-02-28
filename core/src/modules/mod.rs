// Module management functionality
pub mod types;
pub mod loader;
pub mod manager;

// Re-export key types
pub use types::{Module, ModuleManifest, ModuleDependency};
pub use loader::ModuleLoader;
pub use manager::{ModuleManager, ModuleError};