# eldrin
Rust software development platform

run cargo sqlx prepare --workspace to generate the sqlx cache before pushing the changes
./start.sh & sleep 10 && SQLX_OFFLINE=false cargo sqlx prepare --workspace 
