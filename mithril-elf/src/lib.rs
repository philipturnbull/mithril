extern crate goblin;
#[macro_use]
extern crate lazy_static;

use goblin::elf::dyn::DT_BIND_NOW;
use goblin::elf::header::ET_DYN;
use goblin::elf::Elf;
use goblin::elf32::program_header::{PT_GNU_RELRO, PT_PHDR};
use std::collections::HashSet;
use std::iter::FromIterator;

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
pub enum Fortified {
    All,
    Some,
    Unknown,
    OnlyUnprotected,
}

pub struct HasPIE(pub bool);
pub struct HasStackProtector(pub bool);
pub struct HasFortify(pub Fortified);
pub struct HasRelRO(pub bool);
pub struct HasBindNow(pub bool);

pub fn has_pie(elf: &Elf) -> HasPIE {
    if elf.header.e_type == ET_DYN && elf.program_headers.iter().any(|hdr| hdr.p_type == PT_PHDR) {
        return HasPIE(true);
    }

    HasPIE(false)
}

pub fn has_relro(elf: &Elf) -> HasRelRO {
    HasRelRO(
        elf.program_headers
            .iter()
            .any(|hdr| hdr.p_type == PT_GNU_RELRO),
    )
}

pub fn has_bindnow(elf: &Elf) -> HasBindNow {
    if let Some(ref dynamic) = elf.dynamic {
        if dynamic.dyns.iter().any(|dyn| dyn.d_tag == DT_BIND_NOW) {
            return HasBindNow(true);
        }
    }

    HasBindNow(false)
}

pub fn has_protection(elf: &Elf) -> (HasStackProtector, HasFortify) {
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