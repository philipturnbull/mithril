use std::fs::File;
use std::io::{Error, Read};
use std::path::Path;

pub fn read_file(filename: &Path) -> Result<Vec<u8>, Error> {
    let mut fd = File::open(filename)?;
    let mut buffer = Vec::new();
    fd.read_to_end(&mut buffer)?;

    Ok(buffer)
}
