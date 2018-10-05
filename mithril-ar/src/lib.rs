extern crate goblin;
extern crate mithril_elf;

use goblin::archive::Archive;
use goblin::elf::Elf;
use mithril_elf::{HasStackProtector, HasFortify};
use std::io::{Error, ErrorKind};

fn sym_names<'a>(elf: &'a Elf) -> impl std::iter::Iterator<Item=&'a str> {
    elf.syms.iter().filter_map(move |sym| elf.strtab.get(sym.st_name).and_then(|x| x.ok()))
}

// This is an unlinked object, so we can't use mithril_elf::has_protection
fn object_has_protection(elf: &Elf) -> (HasStackProtector, HasFortify) {
    let mut has_stack_protector = HasStackProtector::No;
    let mut has_protected = false;
    let mut has_unprotected = false;

    for name in sym_names(elf) {
        // TODO: should this check Ndx == UND for each symbol?
        if has_stack_protector == HasStackProtector::No && name == "__stack_chk_fail" {
            has_stack_protector = HasStackProtector::Yes;
        }

        if !has_protected && mithril_elf::protected_function(name) {
            has_protected = true;
        } else if !has_unprotected && mithril_elf::unprotected_function(name) {
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

pub fn has_protection(bytes: &[u8], archive: &Archive) -> Result<(HasStackProtector, HasFortify), Error> {
    let mut has_stack_protector = HasStackProtector::No;
    let mut has_fortify = HasFortify::Unknown;

    for member in &archive.members() {
        match archive.extract(member, bytes) {
            Ok(member_bytes) => {
                let elf = match Elf::parse(member_bytes) {
                    Ok(elf) => elf,
                    Err(err) => return Err(Error::new(ErrorKind::Other, err.to_string())),
                };
                let (member_has_stack_protector, member_has_fortify) = object_has_protection(&elf);
                has_stack_protector = has_stack_protector.union(&member_has_stack_protector);
                has_fortify = has_fortify.union(&member_has_fortify);
            },
            Err(err) => return Err(Error::new(ErrorKind::Other, err.to_string())),
        }
    }

    Ok((has_stack_protector, has_fortify))
}
