extern crate ansi_term;
#[macro_use]
extern crate clap;
extern crate goblin;
extern crate mithril;
extern crate mithril_elf;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

use goblin::Object;
use std::io::{Error, ErrorKind};
use std::path::Path;
use std::process::exit;

#[derive(Serialize, Debug)]
struct Results {
    is_pie: mithril_elf::IsPIE,
    has_nx_stack: mithril_elf::HasNXStack,
    has_stack_protector: mithril_elf::HasStackProtector,
    has_fortify: mithril_elf::HasFortify,
    has_relro: mithril_elf::HasRelRO,
    has_bindnow: mithril_elf::HasBindNow,
    library_search_paths: Vec<mithril_elf::LibrarySearchPath>,
}

fn run_mithril(filename: &Path) -> Result<bool, Error> {
    let buffer = mithril::read_file(filename)?;

    let elf = match Object::parse(&buffer) {
        Ok(Object::Elf(elf)) => elf,
        Ok(_) => return Err(Error::new(ErrorKind::Other, "not an ELF file")),
        Err(err) => return Err(Error::new(ErrorKind::Other, err.to_string())),
    };
    let elf = &elf;

    let is_pie = mithril_elf::is_pie(elf);
    let has_nx_stack = mithril_elf::has_nx_stack(elf);
    let (has_stack_protector, has_fortify) = mithril_elf::has_protection(elf);
    let has_relro = mithril_elf::has_relro(elf);
    let has_bindnow = mithril_elf::has_bindnow(elf);
    let library_search_paths = mithril_elf::library_search_paths(elf);

     let results = Results {
        is_pie,
        has_nx_stack,
        has_stack_protector,
        has_fortify,
        has_relro,
        has_bindnow,
        library_search_paths,
    };
    println!("{}", serde_json::to_string(&results).unwrap());

    Ok(true)
}

fn main() {
    let matches = clap_app!(myapp =>
        (version: "0.1")
        (author: "Phil Turnbull <philip.turnbull@gmail.com>")
        (@arg FILE: +required)
    ).get_matches();

    let filename = Path::new(matches.value_of("FILE").unwrap());
    let code = match run_mithril(filename) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(e) => {
            eprintln!("{}: {}", filename.to_str().unwrap_or("<unknown>"), e.to_string());
            1
        }
    };
    exit(code)
}
