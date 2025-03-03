# ELDRIN PROJECT GUIDE

## Build/Test Commands
- Build: `SQLX_OFFLINE=true cargo build`
- Run: `cargo run`
- Test all: `SQLX_OFFLINE=true cargo test`
- Test single: `SQLX_OFFLINE=true cargo test test_name`
- Database prepare: `cargo sqlx prepare --workspace`
- Start services: `./start.sh`
- API tests: `./tools/test_api.sh`
- Lint: `cargo clippy`
- Format: `cargo fmt`

## Code Style Guidelines
- **Architecture**: Follow modular design with clear separation between API, service, and repository layers
- **Imports**: Group imports by source (std, external, internal)
- **Naming**: Use snake_case for variables/functions, CamelCase for types/traits
- **Error Handling**: Use thiserror for custom error types with proper error propagation
- **Types**: Prefer strong typing and leverage Rust's type system
- **Documentation**: Document public APIs with rustdoc comments
- **Testing**: Write unit tests for core functionality and integration tests for API endpoints
- **Async**: Use async/await with tokio runtime for asynchronous operations
- **Module Structure**: Place modules in the `modules/` directory with proper manifest files
- **Database**: Use SQLx for database interactions with PostgreSQL

## OAuth Configuration
### Provider Setup
1. Configure OAuth providers in environment variables:
   ```
   OAUTH_CLIENT_ID=your_client_id
   OAUTH_CLIENT_SECRET=your_client_secret
   OAUTH_REDIRECT_URI=http://localhost:3000/auth/callback
   ```