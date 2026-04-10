#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    mpc_server_demo::run_server().await
}
