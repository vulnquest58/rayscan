//! Man-page generator — run with `cargo run --bin gen_man` to produce
//! `man/rayscan.1` from the clap command definition.
//!
//! This binary is not shipped in the final package; it is a build-time helper.
//! The generated man page is committed to `man/rayscan.1` and installed via
//! `make install`.

use std::fs;

use clap::CommandFactory;
use clap_mangen::Man;
use rayscan::Cli;

fn main() {
    fs::create_dir_all("man").expect("failed to create man/ directory");

    let cmd = Cli::command();
    let man = Man::new(cmd);

    let mut file = fs::File::create("man/rayscan.1").expect("failed to create man/rayscan.1");
    man.render(&mut file).expect("failed to render man page");

    println!("Generated man/rayscan.1");
}
