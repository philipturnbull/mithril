extern crate ansi_term;
#[macro_use]
extern crate clap;
extern crate goblin;
extern crate mithril_elf;

use goblin::Object;
use std::fs::File;
use std::io::{Error, ErrorKind, Read};
use std::path::Path;
use std::process::exit;

#[derive(Debug)]
struct Results {
    is_pie: mithril_elf::IsPIE,
    has_stack_protector: mithril_elf::HasStackProtector,
    has_fortify: mithril_elf::HasFortify,
    has_relro: mithril_elf::HasRelRO,
    has_bindnow: mithril_elf::HasBindNow,
    library_search_paths: Vec<mithril_elf::LibrarySearchPath>,
}

fn run_mithril(filename: &str) -> Result<bool, Error> {
    let path = Path::new(filename);
    let mut fd = File::open(path)?;
    let mut buffer = Vec::new();
    fd.read_to_end(&mut buffer)?;

    let elf = match Object::parse(&buffer) {
        Ok(Object::Elf(elf)) => elf,
        Ok(_) => return Err(Error::new(ErrorKind::Other, "not an ELF file")),
        Err(err) => return Err(Error::new(ErrorKind::Other, err.to_string())),
    };
    let elf = &elf;

    let is_pie = mithril_elf::is_pie(elf);
    let (has_stack_protector, has_fortify) = mithril_elf::has_protection(elf);
    let has_relro = mithril_elf::has_relro(elf);
    let has_bindnow = mithril_elf::has_bindnow(elf);
    let library_search_paths = mithril_elf::has_library_search_path(elf);

    println!("{:?}", Results {
        is_pie,
        has_stack_protector,
        has_fortify,
        has_relro,
        has_bindnow,
        library_search_paths,
    });

    Ok(true)
}

fn main() {
    let matches = clap_app!(myapp =>
        (version: "0.1")
        (author: "Phil Turnbull <philip.turnbull@gmail.com>")
        (@arg FILE: +required)
    ).get_matches();

    let filename = matches.value_of("FILE").unwrap();
    let code = match run_mithril(filename) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(e) => {
            eprintln!("{}: {}", filename, e.to_string());
            1
        }
    };
    exit(code)
}
