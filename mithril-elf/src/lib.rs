extern crate goblin;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_derive;

use goblin::elf::dyn::{DT_BIND_NOW, DT_RPATH, DT_RUNPATH};
use goblin::elf::header::ET_DYN;
use goblin::elf::Elf;
use goblin::elf::program_header::ProgramHeader;
use goblin::elf32::program_header::{PT_GNU_RELRO, PT_GNU_STACK, PT_PHDR};
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

#[derive(PartialEq, Debug, Serialize)]
pub enum HasNXStack {
    Yes,
    No,
}

#[derive(PartialEq, Debug, Serialize)]
pub enum IsPIE {
    Yes,
    No,
    SharedLibrary,
}

#[derive(PartialEq, Debug, Serialize)]
pub enum HasStackProtector {
    Yes,
    No,
}

#[derive(PartialEq, Debug, Serialize)]
pub enum HasFortify {
    All,
    Some,
    Unknown,
    OnlyUnprotected,
}

#[derive(PartialEq, Debug, Serialize)]
pub enum HasRelRO {
    Yes,
    No,
}

#[derive(PartialEq, Debug, Serialize)]
pub enum HasBindNow {
    Yes,
    No,
}

#[derive(PartialEq, Debug, Serialize)]
pub enum LibrarySearchPath {
    RPATHUnknown,
    RPATH(String),
    RUNPATHUnknown,
    RUNPATH(String),
}

fn has_program_header(elf: &Elf, header: u32) -> bool {
    elf.program_headers.iter().any(|hdr| hdr.p_type == header)
}

fn get_program_header<'a>(elf: &'a Elf, header: u32) -> Option<&'a ProgramHeader> {
    elf.program_headers.iter().filter(|hdr| hdr.p_type == header).nth(0)
}

fn has_dynamic_entry(elf: &Elf, tag: u64) -> bool {
    if let Some(ref dynamic) = elf.dynamic {
        return dynamic.dyns.iter().any(|dyn| dyn.d_tag == tag)
    }

    false
}

pub fn is_pie(elf: &Elf) -> IsPIE {
    if elf.header.e_type == ET_DYN {
        return if has_program_header(elf, PT_PHDR) {
            IsPIE::Yes
        } else {
            IsPIE::SharedLibrary
        }
    }

    IsPIE::No
}

pub fn has_nx_stack(elf: &Elf) -> HasNXStack {
    if let Some(hdr) = get_program_header(elf, PT_GNU_STACK) {
        if hdr.p_flags & 1 == 1 {
            return HasNXStack::No
        }
    }

    HasNXStack::Yes
}

pub fn has_relro(elf: &Elf) -> HasRelRO {
    if has_program_header(elf, PT_GNU_RELRO) {
        HasRelRO::Yes
    } else {
        HasRelRO::No
    }
}

pub fn has_bindnow(elf: &Elf) -> HasBindNow {
    if has_dynamic_entry(elf, DT_BIND_NOW) {
        HasBindNow::Yes
    } else {
        HasBindNow::No
    }
}

fn dyn_sym_names<'a>(elf: &'a Elf) -> impl std::iter::Iterator<Item=&'a str> {
    elf.dynsyms.iter().filter_map(move |sym| elf.dynstrtab.get(sym.st_name).and_then(|x| x.ok()))
}

pub fn has_protection(elf: &Elf) -> (HasStackProtector, HasFortify) {
    let mut has_stack_protector = HasStackProtector::No;
    let mut has_protected = false;
    let mut has_unprotected = false;

    for name in dyn_sym_names(elf) {
        if has_stack_protector == HasStackProtector::No && name == "__stack_chk_fail" {
            has_stack_protector = HasStackProtector::Yes;
        }

        if !has_protected && PROTECTED_FUNCTIONS.contains(&name) {
            has_protected = true;
        } else if !has_unprotected && UNPROTECTED_FUNCTIONS.contains(&name) {
            has_unprotected = true;
        }

        if has_stack_protector == HasStackProtector::Yes && has_protected && has_unprotected {
            break
        }
    }

    let has_fortify = match (has_protected, has_unprotected) {
        (true, true) => HasFortify::Some,
        (true, false) => HasFortify::All,
        (false, true) => HasFortify::OnlyUnprotected,
        (false, false) => HasFortify::Unknown,
    };

    (has_stack_protector, has_fortify)
}

pub fn library_search_paths(elf: &Elf) -> Vec<LibrarySearchPath> {
    let mut paths = Vec::new();

    if let Some(ref dynamic) = elf.dynamic {
        for dyn in &dynamic.dyns {
            if dyn.d_tag == DT_RPATH {
                match elf.dynstrtab.get(dyn.d_val as usize) {
                    Some(Ok(path)) => paths.push(LibrarySearchPath::RPATH(path.into())),
                    _ => paths.push(LibrarySearchPath::RPATHUnknown),
                }
            } else if dyn.d_tag == DT_RUNPATH {
                match elf.dynstrtab.get(dyn.d_val as usize) {
                    Some(Ok(path)) => paths.push(LibrarySearchPath::RUNPATH(path.into())),
                    _ => paths.push(LibrarySearchPath::RUNPATHUnknown),
                }
            }
        }
    }

    paths
}
