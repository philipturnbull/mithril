extern crate ansi_term;
#[macro_use]
extern crate clap;
extern crate goblin;
extern crate kobold;
extern crate mithril;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

use goblin::Object;
use kobold::elf;
use std::io::{Error, ErrorKind};

struct Config {
}

#[derive(Serialize, Debug)]
struct Results {
    is_pie: elf::IsPIE,
    has_nx_stack: elf::HasNXStack,
    has_stack_protector: elf::HasStackProtector,
    has_fortify: elf::HasFortify,
    has_relro: elf::HasRelRO,
    has_bindnow: elf::HasBindNow,
    library_search_paths: Vec<elf::LibrarySearchPath>,
}

fn run(_config: &Config, _filename: &str, _bytes: &[u8], object: &Object) -> Result<bool, Error> {
    let elf = match object {
        Object::Elf(elf) => elf,
        _ => return Err(Error::new(ErrorKind::Other, "not an ELF file")),
    };
    let elf = &elf;

    let is_pie = elf::is_pie(elf);
    let has_nx_stack = elf::has_nx_stack(elf);
    let (has_stack_protector, has_fortify) = elf::has_protection(elf);
    let has_relro = elf::has_relro(elf);
    let has_bindnow = elf::has_bindnow(elf);
    let library_search_paths = elf::library_search_paths(elf);

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

    let filename = matches.value_of("FILE").unwrap();
    let config = Config{};
    mithril::run_and_exit(run, &config, filename);
}
