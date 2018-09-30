extern crate ansi_term;
#[macro_use]
extern crate clap;
extern crate goblin;
extern crate mithril;
extern crate mithril_elf;

use ansi_term::Color::{Green, Red, Yellow};
use goblin::Object;
use std::io::{Error, ErrorKind};
use std::path::Path;
use std::process::exit;

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
    ignore_pie: bool,
    ignore_stack_protector: bool,
    ignore_fortify: bool,
    ignore_relro: bool,
    ignore_bindnow: bool,
}

trait Check {
    fn meta(self: &Self, config: &CheckConfig) -> (&'static str, bool);
    fn result(self: &Self) -> CheckResult;
}

macro_rules! checked {
    ($type:ident $flag:ident $title:expr, $($pattern:ident => $result:expr),+,) => {
        impl Check for mithril_elf::$type {
            fn meta(self: &Self, config: &CheckConfig) -> (&'static str, bool) {
                ($title, config.$flag)
            }

            fn result(self: &Self) -> CheckResult {
                match self {
                    $(
                        mithril_elf::$type::$pattern => $result,
                    )*
                }
            }
        }
    }
}

checked! {
    IsPIE ignore_pie "Position Independent Executable",
    Yes => good("yes"),
    No => bad("no, normal executable!"),
    SharedLibrary => good("no, regular shared library (ignored)"),
}

checked! {
    HasStackProtector ignore_stack_protector "Stack protected",
    Yes => good("yes"),
    No => bad("no, not found!"),
}

checked! {
    HasFortify ignore_fortify "Fortify Source functions",
    All => good("yes"),
    Some => good_comment("yes", " (some protected functions found)"),
    Unknown => unknown("unknown, no protectable libc functions used"),
    OnlyUnprotected => bad("no, only unprotected functions found!"),
}

checked! {
    HasRelRO ignore_relro "Read-only relocations",
    Yes => good("yes"),
    No => bad("no, not found!"),
}

checked! {
    HasBindNow ignore_bindnow "Immediate binding",
    Yes => good("yes"),
    No => bad("no, not found!"),
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

fn run_hardening_check(filename: &Path, config: &CheckConfig) -> Result<bool, Error> {
    let file = mithril::slurp_file(filename)?;
    let object = mithril::slurp_object(&file)?;

    let elf = match object {
        Object::Elf(elf) => elf,
        _ => return Err(Error::new(ErrorKind::Other, "not an ELF file")),
    };
    let elf = &elf;

    let is_pie = mithril_elf::is_pie(elf);
    let (has_stack_protector, has_fortify) = mithril_elf::has_protection(elf);
    let has_relro = mithril_elf::has_relro(elf);
    let has_bindnow = mithril_elf::has_bindnow(elf);

    println!("{}:", filename.to_str().unwrap_or("<unknown>"));
    let mut failed = false;
    failed |= print_check(config, &is_pie);
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
        (@arg ignore_pie: -p --nopie)
        (@arg ignore_stack_protector: -s --nostackprotector)
        (@arg ignore_fortify: -f --nofortify)
        (@arg ignore_relro: -r --norelro)
        (@arg ignore_bindnow: -b --nobindnow)
        (@arg FILE: +required)
    ).get_matches();

    let filename = Path::new(matches.value_of("FILE").unwrap());
    let config = &CheckConfig {
        color: matches.is_present("color"),
        ignore_pie: matches.is_present("ignore_pie"),
        ignore_stack_protector: matches.is_present("ignore_stack_protector"),
        ignore_fortify: matches.is_present("ignore_fortify"),
        ignore_relro: matches.is_present("ignore_relro"),
        ignore_bindnow: matches.is_present("ignore_bindnow"),
    };

    let code = match run_hardening_check(filename, config) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(e) => {
            eprintln!("{}: {}", filename.to_str().unwrap_or("<unknown>"), e.to_string());
            1
        }
    };
    exit(code)
}
