extern crate ansi_term;
#[macro_use]
extern crate clap;
extern crate goblin;
extern crate mithril_elf;

use ansi_term::Color::{Green, Red, Yellow};
use goblin::Object;
use std::fs::File;
use std::io::{Error, ErrorKind, Read};
use std::path::Path;
use std::process::exit;
use mithril_elf::Fortified;

#[derive(PartialEq)]
enum CheckStatus {
    Good,
    Bad,
    Unknown,
}

struct CheckConfig {
    color: bool,
    skip_pie: bool,
    skip_stackprotector: bool,
    skip_fortify: bool,
    skip_relro: bool,
    skip_bindnow: bool,
}

macro_rules! status {
    ($x:ident, $text:expr, $comment:expr) => {
        (CheckStatus::$x, $text, $comment)
    };
    ($x:ident, $text:expr) => {
        (CheckStatus::$x, $text, "")
    };
}

macro_rules! checked {
    ($name:ident $flag:ident: $title:expr, $($pattern:pat => $result:expr),+,) => {
        struct $name<'a> {
            value: mithril_elf::$name,
            config: &'a CheckConfig,
        }

        impl<'a> $name<'a> {
            #![allow(match_bool)]
            fn status(self: &Self) -> (CheckStatus, &str, &str) {
                match self.value.0 {
                    $(
                        $pattern => $result,
                    )*
                }
            }

            fn failed(self: &Self) -> bool {
                return !self.config.$flag && self.status().0 == CheckStatus::Bad
            }

            fn print(self: &Self) {
                let (status, text, comment) = self.status();

                let ignored = if self.config.$flag && status == CheckStatus::Bad {
                    " (ignored)"
                } else {
                    ""
                };

                let text = if self.config.color {
                    (match status {
                        CheckStatus::Good => Green,
                        CheckStatus::Unknown => Yellow,
                        CheckStatus::Bad => Red,
                    }).paint(text).to_string()
                } else {
                    text.to_string()
                };

                println!(" {}: {}{}{}", $title, text, comment, ignored);
            }
        }
    }
}

checked! {
    HasPIE skip_pie: "Position Independent Executable",
    true => status!(Good, "yes"),
    false => status!(Bad, "no, normal executable!"),
}

checked! {
    HasStackProtector skip_stackprotector: "Stack protected",
    true => status!(Good, "yes"),
    false => status!(Bad, "no, not found!"),
}

checked! {
    HasFortify skip_fortify: "Fortify Source functions",
    Fortified::All => status!(Good, "yes"),
    Fortified::Some => status!(Good, "yes", " (some protected functions found)"),
    Fortified::Unknown => status!(Unknown, "unknown, no protectable libc functions used"),
    Fortified::OnlyUnprotected => status!(Bad, "no, only unprotected functions found!"),
}

checked! {
    HasRelRO skip_relro: "Read-only relocations",
    true => status!(Good, "yes"),
    false => status!(Bad, "no, not found!"),
}

checked! {
    HasBindNow skip_bindnow: "Immediate binding",
    true => status!(Good, "yes"),
    false => status!(Bad, "no, not found!"),
}

fn run_hardening_check(filename: &str, config: &CheckConfig) -> Result<bool, Error> {
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

    let has_pie = HasPIE { value: mithril_elf::has_pie(elf), config };
    let (has_stackprotector, has_fortify) = mithril_elf::has_protection(elf);
    let has_stackprotector = HasStackProtector { value: has_stackprotector, config };
    let has_fortify = HasFortify { value: has_fortify, config };
    let has_relro = HasRelRO { value: mithril_elf::has_relro(elf), config };
    let has_bindnow = HasBindNow { value: mithril_elf::has_bindnow(elf), config };

    println!("{}:", filename);
    has_pie.print();
    has_stackprotector.print();
    has_fortify.print();
    has_relro.print();
    has_bindnow.print();

    Ok(has_pie.failed() ||
       has_stackprotector.failed() ||
       has_fortify.failed() ||
       has_relro.failed() ||
       has_bindnow.failed()
    )
}

fn main() {
    let matches = clap_app!(myapp =>
        (version: "0.1")
        (author: "Phil Turnbull <philip.turnbull@gmail.com>")
        (@arg color: -c --color)
        (@arg skip_pie: -p --nopie)
        (@arg skip_stackprotector: -s --nostackprotector)
        (@arg skip_fortify: -f --nofortify)
        (@arg skip_relro: -r --norelro)
        (@arg skip_bindnow: -b --nobindnow)
        (@arg FILE: +required)
    ).get_matches();

    let filename = matches.value_of("FILE").unwrap();
    let config = &CheckConfig {
        color: matches.is_present("color"),
        skip_pie: matches.is_present("skip_pie"),
        skip_stackprotector: matches.is_present("skip_stackprotector"),
        skip_fortify: matches.is_present("skip_fortify"),
        skip_relro: matches.is_present("skip_relro"),
        skip_bindnow: matches.is_present("skip_bindnow"),
    };

    let code = match run_hardening_check(filename, config) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => {
            eprintln!("{}: {}", filename, e.to_string());
            1
        }
    };
    exit(code)
}
