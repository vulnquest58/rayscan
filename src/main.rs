use clap::Parser;

use rayscan::Cli;

fn main() {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("rayscan: cannot start async runtime: {error}");
            std::process::exit(1);
        }
    };

    if let Err(error) = runtime.block_on(rayscan::run(cli)) {
        eprintln!("rayscan: {error}");
        std::process::exit(error.exit_code());
    }
}
