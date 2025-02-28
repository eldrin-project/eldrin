use axum::{
    routing::{get, post},
    Router,
    extract::{State, Path},
    Json,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::modules::{ModuleError};
use crate::AppState;

#[derive(Serialize)]
pub struct ModuleInfo {
    name: String,
    version: String,
    description: Option<String>,
    author: Option<String>,
    is_core: bool,
    active: bool,
}

#[derive(Deserialize)]
pub struct ActivateModuleRequest {
    name: String,
}

// API router for modules
pub fn module_routes() -> Router<AppState> {
    Router::new()
        .route("/modules", get(list_modules))
        .route("/modules/:name", get(get_module))
        .route("/modules/activate", post(activate_module))
        .route("/modules/deactivate/:name", post(deactivate_module))
}

// List all modules
async fn list_modules(State(state): State<AppState>) -> Json<Vec<ModuleInfo>> {
    let module_manager = state.module_manager.lock().await;
    
    let modules = module_manager.get_all_modules()
        .iter()
        .map(|m| ModuleInfo {
            name: m.manifest.name.clone(),
            version: m.manifest.version.clone(),
            description: m.manifest.description.clone(),
            author: m.manifest.author.clone(),
            is_core: m.is_core,
            active: m.active,
        })
        .collect();
    
    Json(modules)
}

// Get a single module by name
async fn get_module(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<ModuleInfo>, StatusCode> {
    let module_manager = state.module_manager.lock().await;
    
    let module = module_manager.get_module(&name)
        .ok_or(StatusCode::NOT_FOUND)?;
    
    let module_info = ModuleInfo {
        name: module.manifest.name.clone(),
        version: module.manifest.version.clone(),
        description: module.manifest.description.clone(),
        author: module.manifest.author.clone(),
        is_core: module.is_core,
        active: module.active,
    };
    
    Ok(Json(module_info))
}

// Activate a module
async fn activate_module(
    State(state): State<AppState>,
    Json(payload): Json<ActivateModuleRequest>,
) -> Result<StatusCode, StatusCode> {
    let mut module_manager = state.module_manager.lock().await;
    
    match module_manager.activate_module(&payload.name).await {
        Ok(_) => Ok(StatusCode::OK),
        Err(ModuleError::NotFound(_)) => Err(StatusCode::NOT_FOUND),
        Err(ModuleError::DependencyNotSatisfied { .. }) => Err(StatusCode::BAD_REQUEST),
        Err(ModuleError::CircularDependency(_)) => Err(StatusCode::BAD_REQUEST),
        Err(ModuleError::InvalidModule(_)) => Err(StatusCode::BAD_REQUEST),
        Err(ModuleError::Database(_)) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// Deactivate a module
async fn deactivate_module(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let mut module_manager = state.module_manager.lock().await;
    
    match module_manager.deactivate_module(&name).await {
        Ok(_) => Ok(StatusCode::OK),
        Err(ModuleError::NotFound(_)) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}