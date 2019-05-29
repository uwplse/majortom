#![allow(dead_code)]

extern crate env_logger;

use log::trace;
use std::env::set_current_dir;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use majortom::config;

pub fn setup_logging() {
    let _ = env_logger::builder().is_test(true).try_init();
}

pub fn setup_example(example: &str) -> config::Config {
    setup_logging();
    let mut example_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    example_path.push("examples");
    example_path.push(example);
    if !example_path.is_dir() {
        panic!("No example named {}", example);
    }
    set_current_dir(example_path).expect("Couldn't change directories");
    trace!("Running make");
    let make_status = Command::new("make")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("Couldn't run make");
    if !make_status.success() {
        panic!("Failed to build example {}", example)
    }
    trace!("Make finished");
    let config = config::read(&format!("{}.toml", example)).expect("Failed to read config file");
    config
}

pub fn path_exists(s: &str) -> bool {
    std::path::Path::new(s).exists()
}
