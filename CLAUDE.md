# ELDRIN PROJECT GUIDE

## Build/Test Commands
- Build: `SQLX_OFFLINE=false cargo build`
- Run: `cargo run`
- Test all: `cargo test`
- Test single: `cargo test test_name`
- Lint: `cargo clippy`
- Format: `cargo fmt`

## Code Style Guidelines
- **Architecture**: Follow modular design with clear separation between API, service, and repository layers
- **Imports**: Group imports by source (std, external, internal)
- **Naming**: Use snake_case for variables/functions, CamelCase for types/traits
- **Error Handling**: Use Result<T, E> with proper error propagation
- **Types**: Prefer strong typing and leverage Rust's type system
- **Documentation**: Document public APIs with rustdoc comments
- **Testing**: Write unit tests for core functionality and integration tests for API endpoints
- **Module Structure**: Place modules in the `addons/` directory with proper manifest files
- **Dependencies**: Clearly define module dependencies in manifests
- **Database**: Use Diesel or SQLx for database interactions

## OAuth Configuration
### Google Auth Setup
1. Go to Google Cloud Console and create a project
2. Navigate to "APIs & Services" > "Credentials"
3. Click "Create Credentials" > "OAuth client ID"
4. Set up the consent screen with app name and contact info
5. Create a Web application type OAuth client
6. Add authorized redirect URIs: `http://localhost:3000/auth/google/callback`
7. Copy the Client ID and Client Secret to your .env file:
   ```
   GOOGLE_CLIENT_ID=your_client_id
   GOOGLE_CLIENT_SECRET=your_client_secret
   GOOGLE_REDIRECT_URI=http://localhost:3000/auth/google/callback
   ```