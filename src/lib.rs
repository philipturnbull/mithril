extern crate goblin;

use goblin::Object;
use std::fs::File;
use std::io::{Error, ErrorKind, Read};
use std::process;

fn run<F, C>(func: F, config: &C, filename: &str) -> Result<bool, Error>
    where F: FnOnce(&C, &str, &[u8], &Object) -> Result<bool, Error>
{
    let mut fd = File::open(filename)?;
    let mut buffer = Vec::new();
    fd.read_to_end(&mut buffer)?;
    let bytes = &buffer;

    match Object::parse(bytes) {
        Ok(object) => func(config, filename, bytes, &object),
        Err(err) => Err(Error::new(ErrorKind::Other, err.to_string())),
    }
}

pub fn run_and_exit<F, C>(func: F, config: &C, filename: &str) -> !
    where F: FnOnce(&C, &str, &[u8], &Object) -> Result<bool, Error>
{
    let code = match run(func, config, filename) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(err) => {
            eprintln!("{}: {}", filename, err.to_string());
            1
        }
    };
    process::exit(code)
}
