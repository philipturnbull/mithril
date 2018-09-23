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

struct CheckResult {
    status: CheckStatus,
    text: &'static str,
    comment: &'static str,
}

fn good(text: &'static str) -> CheckResult {
    CheckResult { status: CheckStatus::Good, text, comment: "" }
}

fn good_comment(text: &'static str, comment: &'static str) -> CheckResult {
    CheckResult { status: CheckStatus::Good, text, comment }
}

fn bad(text: &'static str) -> CheckResult {
    CheckResult { status: CheckStatus::Bad, text, comment: "" }
}

fn unknown(text: &'static str) -> CheckResult {
    CheckResult { status: CheckStatus::Unknown, text, comment: "" }
}

struct CheckConfig {
    color: bool,
    skip_pie: bool,
    skip_stack_protector: bool,
    skip_fortify: bool,
    skip_relro: bool,
    skip_bindnow: bool,
}

trait Check {
    fn meta(self: &Self, config: &CheckConfig) -> (&'static str, bool);
    fn result(self: &Self) -> CheckResult;
}

macro_rules! checked {
    ($type:ident $flag:ident $title:expr, $($pattern:pat => $result:expr),+,) => {
        impl Check for mithril_elf::$type {
            fn meta(self: &Self, config: &CheckConfig) -> (&'static str, bool) {
                ($title, config.$flag)
            }

            fn result(self: &Self) -> CheckResult {
                #![allow(match_bool)]
                match self.0 {
                    $(
                        $pattern => $result,
                    )*
                }
            }
        }
    }
}

checked! {
    HasPIE skip_pie "Position Independent Executable",
    true => good("yes"),
    false => bad("no, normal executable!"),
}

checked! {
    HasStackProtector skip_stack_protector "Stack protected",
    true => good("yes"),
    false => bad("no, not found!"),
}

checked! {
    HasFortify skip_fortify "Fortify Source functions",
    Fortified::All => good("yes"),
    Fortified::Some => good_comment("yes", " (some protected functions found)"),
    Fortified::Unknown => unknown("unknown, no protectable libc functions used"),
    Fortified::OnlyUnprotected => bad("no, only unprotected functions found!"),
}

checked! {
    HasRelRO skip_relro "Read-only relocations",
    true => good("yes"),
    false => bad("no, not found!"),
}

checked! {
    HasBindNow skip_bindnow "Immediate binding",
    true => good("yes"),
    false => bad("no, not found!"),
}


fn print_check<C: Check>(config: &CheckConfig, check: &C) -> bool {
    let (title, should_ignore) = check.meta(config);
    let result = check.result();

    let ignored = if should_ignore && result.status == CheckStatus::Bad {
        " (ignored)"
    } else {
        ""
    };

    let text = if config.color {
        (match result.status {
            CheckStatus::Good => Green,
            CheckStatus::Unknown => Yellow,
            CheckStatus::Bad => Red,
        }).paint(result.text).to_string()
    } else {
        result.text.to_string()
    };

    println!(" {}: {}{}{}", title, text, result.comment, ignored);

    !should_ignore && result.status == CheckStatus::Bad
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

    let has_pie = mithril_elf::has_pie(elf);
    let (has_stack_protector, has_fortify) = mithril_elf::has_protection(elf);
    let has_relro = mithril_elf::has_relro(elf);
    let has_bindnow = mithril_elf::has_bindnow(elf);

    println!("{}:", filename);
    let mut failed = false;
    failed |= print_check(config, &has_pie);
    failed |= print_check(config, &has_stack_protector);
    failed |= print_check(config, &has_fortify);
    failed |= print_check(config, &has_relro);
    failed |= print_check(config, &has_bindnow);

    Ok(!failed)
}

fn main() {
    let matches = clap_app!(myapp =>
        (version: "0.1")
        (author: "Phil Turnbull <philip.turnbull@gmail.com>")
        (@arg color: -c --color)
        (@arg skip_pie: -p --nopie)
        (@arg skip_stack_protector: -s --nostackprotector)
        (@arg skip_fortify: -f --nofortify)
        (@arg skip_relro: -r --norelro)
        (@arg skip_bindnow: -b --nobindnow)
        (@arg FILE: +required)
    ).get_matches();

    let filename = matches.value_of("FILE").unwrap();
    let config = &CheckConfig {
        color: matches.is_present("color"),
        skip_pie: matches.is_present("skip_pie"),
        skip_stack_protector: matches.is_present("skip_stack_protector"),
        skip_fortify: matches.is_present("skip_fortify"),
        skip_relro: matches.is_present("skip_relro"),
        skip_bindnow: matches.is_present("skip_bindnow"),
    };

    let code = match run_hardening_check(filename, config) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(e) => {
            eprintln!("{}: {}", filename, e.to_string());
            1
        }
    };
    exit(code)
}
