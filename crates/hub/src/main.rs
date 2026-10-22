#[tokio::main]
async fn main() -> anyhow::Result<()> {
    hub::run().await
}
