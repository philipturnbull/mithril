extern crate ansi_term;
#[macro_use]
extern crate clap;
extern crate goblin;
#[macro_use]
extern crate lazy_static;

use ansi_term::Color::{Green, Red, Yellow};
use goblin::elf::dyn::DT_BIND_NOW;
use goblin::elf::header::ET_DYN;
use goblin::elf::Elf;
use goblin::elf32::program_header::{PT_GNU_RELRO, PT_PHDR};
use goblin::Object;
use std::collections::HashSet;
use std::fs::File;
use std::io::{Error, ErrorKind, Read};
use std::iter::FromIterator;
use std::path::Path;
use std::process::exit;

macro_rules! chk {
    ($($x:expr),+,) => {
        (
            &[
                $(
                    stringify!($x),
                )*
            ],
            &[
                $(
                    concat!("__", stringify!($x), "_chk"),
                )*
            ]
        )
    }
}

const LIBC_FUNCTIONS: (&[&str], &[&str]) = chk!(
    asprintf,
    confstr,
    dprintf,
    fgets,
    fgets_unlocked,
    fgetws,
    fgetws_unlocked,
    fprintf,
    fread,
    fread_unlocked,
    fwprintf,
    getcwd,
    getdomainname,
    getgroups,
    gethostname,
    getlogin_r,
    gets,
    getwd,
    longjmp,
    mbsnrtowcs,
    mbsrtowcs,
    mbstowcs,
    memcpy,
    memmove,
    mempcpy,
    memset,
    obstack_printf,
    obstack_vprintf,
    pread64,
    pread,
    printf,
    ptsname_r,
    read,
    readlink,
    readlinkat,
    realpath,
    recv,
    recvfrom,
    snprintf,
    sprintf,
    stpcpy,
    stpncpy,
    strcat,
    strcpy,
    strncat,
    strncpy,
    swprintf,
    syslog,
    ttyname_r,
    vasprintf,
    vdprintf,
    vfprintf,
    vfwprintf,
    vprintf,
    vsnprintf,
    vsprintf,
    vswprintf,
    vsyslog,
    vwprintf,
    wcpcpy,
    wcpncpy,
    wcrtomb,
    wcscat,
    wcscpy,
    wcsncat,
    wcsncpy,
    wcsnrtombs,
    wcsrtombs,
    wcstombs,
    wctomb,
    wmemcpy,
    wmemmove,
    wmempcpy,
    wmemset,
    wprintf,
);

lazy_static! {
    static ref UNPROTECTED_FUNCTIONS: HashSet<&'static &'static str> =
        HashSet::from_iter(LIBC_FUNCTIONS.0.iter());
    static ref PROTECTED_FUNCTIONS: HashSet<&'static &'static str> =
        HashSet::from_iter(LIBC_FUNCTIONS.1.iter());
}

#[derive(PartialEq)]
enum Fortified {
    All,
    Some,
    Unknown,
    OnlyUnprotected,
}

#[derive(PartialEq)]
enum CheckStatus {
    Good,
    Bad,
    Unknown,
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
    ($type:ident $name:ident: $title:expr, $($pattern:pat => $result:expr),+,) => {
        struct $name($type);
        impl $name {
            fn print(self: &Self, color:bool, ignore: bool) {
                let (status, text, comment) = match self.0 {
                    $(
                        $pattern => $result,
                    )*
                };

                let ignored = if ignore && status == CheckStatus::Bad {
                    " (ignored)"
                } else {
                    ""
                };

                let text = if color {
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
    bool HasPIE: "Position Independent Executable",
    true => status!(Good, "yes"),
    false => status!(Bad, "no, normal executable!"),
}

checked! {
    bool HasStackProtector: "Stack protected",
    true => status!(Good, "yes"),
    false => status!(Bad, "no, not found!"),
}

checked! {
    Fortified HasFortify: "Fortify Source functions",
    Fortified::All => status!(Good, "yes"),
    Fortified::Some => status!(Good, "yes", " (some protected functions found)"),
    Fortified::Unknown => status!(Unknown, "unknown, no protectable libc functions used"),
    Fortified::OnlyUnprotected => status!(Bad, "no, only unprotected functions found!"),
}

checked! {
    bool HasRelRO: "Read-only relocations",
    true => status!(Good, "yes"),
    false => status!(Bad, "no, not found!"),
}

checked! {
    bool HasBindNow: "Immediate binding",
    true => status!(Good, "yes"),
    false => status!(Bad, "no, not found!"),
}

struct CheckConfig {
    color: bool,
    skip_pie: bool,
    skip_stackprotector: bool,
    skip_fortify: bool,
    skip_relro: bool,
    skip_bindnow: bool,
}

fn elf_has_pie(elf: &Elf) -> HasPIE {
    if elf.header.e_type == ET_DYN && elf.program_headers.iter().any(|hdr| hdr.p_type == PT_PHDR) {
        return HasPIE(true);
    }

    HasPIE(false)
}

fn elf_has_relro(elf: &Elf) -> HasRelRO {
    HasRelRO(
        elf.program_headers
            .iter()
            .any(|hdr| hdr.p_type == PT_GNU_RELRO),
    )
}

fn elf_has_bindnow(elf: &Elf) -> HasBindNow {
    if let Some(ref dynamic) = elf.dynamic {
        if dynamic.dyns.iter().any(|dyn| dyn.d_tag == DT_BIND_NOW) {
            return HasBindNow(true);
        }
    }

    HasBindNow(false)
}

fn elf_has_protection(elf: &Elf) -> (HasStackProtector, HasFortify) {
    let mut has_stackprotector = HasStackProtector(false);
    let mut num_protected = 0;
    let mut num_unprotected = 0;
    for sym in elf.dynsyms.iter() {
        if let Some(Ok(name)) = elf.dynstrtab.get(sym.st_name) {
            if name == "__stack_chk_fail" {
                has_stackprotector = HasStackProtector(true);
            }

            if PROTECTED_FUNCTIONS.contains(&name) {
                num_protected += 1;
            } else if UNPROTECTED_FUNCTIONS.contains(&name) {
                num_unprotected += 1;
            }
        }
    }

    let has_fortify = HasFortify(if num_protected > 0 && num_unprotected == 0 {
        Fortified::All
    } else if num_protected > 0 && num_unprotected > 0 {
        Fortified::Some
    } else if num_protected == 0 && num_unprotected == 0 {
        Fortified::Unknown
    } else {
        Fortified::OnlyUnprotected
    });

    (has_stackprotector, has_fortify)
}

fn run_hardening_check(filename: &str, config: &CheckConfig) -> Result<i32, Error> {
    let path = Path::new(filename);
    let mut fd = File::open(path)?;
    let mut buffer = Vec::new();
    fd.read_to_end(&mut buffer)?;

    let elf = match Object::parse(&buffer) {
        Ok(Object::Elf(elf)) => elf,
        Ok(_) => return Err(Error::new(ErrorKind::Other, "only ELF files are supported")),
        Err(err) => return Err(Error::new(ErrorKind::Other, err.to_string())),
    };
    let elf = &elf;

    println!("{}:", filename);
    let has_pie = elf_has_pie(elf);
    let has_relro = elf_has_relro(elf);
    let has_bindnow = elf_has_bindnow(elf);
    let (has_stackprotector, has_fortify) = elf_has_protection(elf);

    has_pie.print(config.color, config.skip_pie);
    has_stackprotector.print(config.color, config.skip_stackprotector);
    has_fortify.print(config.color, config.skip_fortify);
    has_relro.print(config.color, config.skip_relro);
    has_bindnow.print(config.color, config.skip_bindnow);

    Ok(0)
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
        Ok(code) => code,
        Err(e) => {
            println!("err = {:#?}", e);
            1
        }
    };
    exit(code)
}
