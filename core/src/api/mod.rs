// API module for handling HTTP routes
pub mod routes;

pub use routes::module_routes;

pub fn routes() -> axum::Router<crate::AppState> {
    axum::Router::new()
        .route("/health", axum::routing::get(health_check))
}

async fn health_check() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}