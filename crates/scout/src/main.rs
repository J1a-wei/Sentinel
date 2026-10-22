fn main() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    let result = runtime.block_on(scout::run());
    runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    result
}
