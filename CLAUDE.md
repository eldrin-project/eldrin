# ELDRIN PROJECT GUIDE

## Build/Test Commands
- Build: `cargo build`
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