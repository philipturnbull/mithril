mithril
=======

`mithril` is a re-implementation of [`hardening-check`](https://wiki.debian.org/Hardening#Validation) in Rust. It uses the excellent [`goblin`](https://crates.io/crates/goblin) library for ELF parsing.

[![Build Status](https://travis-ci.org/philipturnbull/mithril.svg?branch=master)](https://travis-ci.org/philipturnbull/mithril)

```
$ mithril a.out | cowsay -f stegosaurus -n
 __________________________________________________________
/ a.out:                                                   \
|  Position Independent Executable: no, normal executable! |
|  Stack protected: yes                                    |
|  Fortify Source functions: yes                           |
|  Read-only relocations: yes                              |
\  Immediate binding: no, not found!                       /
 ----------------------------------------------------------
\                             .       .
 \                           / `.   .' "
  \                  .---.  <    > <    >  .---.
   \                 |    \  \ - ~ ~ - /  /    |
         _____          ..-~             ~-..-~
        |     |   \~~~\.'                    `./~~~/
       ---------   \__/                        \__/
      .'  O    \     /               /       \  "
     (_____,    `._.'               |         }  \/~~~/
      `----.          /       }     |        /    \__/
            `-.      |       /      |       /      `. ,~~|
                ~-.__|      /_ - ~ ^|      /- _      `..-'
                     |     /        |     /     ~-.     `-. _  _  _
                     |_____|        |_____|         ~ - . _ _ _ _ _>
```
