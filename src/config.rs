extern crate serde;
extern crate serde_json;
extern crate toml;

use std::collections::HashMap;
use std::error::Error;
use std::fs;

#[derive(Deserialize, Debug)]
pub struct OddityConfig {
    pub address: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct SystemConfig {
    pub protobufs: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct Config {
    pub oddity: OddityConfig,
    pub system: Option<SystemConfig>,
    pub nodes: HashMap<String, String>,
}

pub fn read(filename: &str) -> Result<Config, Box<dyn Error>> {
    let contents = fs::read_to_string(filename)?;

    let config: Config = toml::from_str(&contents)?;
    Ok(config)
}
