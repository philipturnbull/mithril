extern crate goblin;

use goblin::Object;
use std::fs::File;
use std::io::{Error, ErrorKind, Read};
use std::path::Path;

pub fn slurp_file(filename: &Path) -> Result<Vec<u8>, Error> {
    let mut fd = File::open(filename)?;
    let mut buffer = Vec::new();
    fd.read_to_end(&mut buffer)?;

    Ok(buffer)
}

pub fn slurp_object(bytes: &[u8]) -> Result<Object, Error> {
    Object::parse(bytes).map_err(|err| Error::new(ErrorKind::Other, err.to_string()))
}
