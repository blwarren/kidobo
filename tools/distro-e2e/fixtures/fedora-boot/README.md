# Fedora boot fixtures

These files come from `run-1793157406-1204107` and its archived
`fedora-44/prepared-diagnostics/prepared/boot-config-before.txt`:

- `full-efi.cfg` retains the complete image-generated EFI GRUB configuration,
  including environment loading, the initial numeric default, fallback counting,
  and BLS loading.
- `old.conf` and `new.conf` retain the image and newly installed kernel entries.
  Both use `/boot/` paths because this image shares its root and boot filesystem.

Filesystem UUIDs are fictional, metadata lines have been removed, and trailing
whitespace has been normalized. The Rust harness assigns fictional entry filenames,
adapts filesystem paths for the separate-boot case, and adds arguments that exercise
preservation. Its fake `grub2-mkconfig` uses this full configuration with the normal
default changed to `${saved_entry}`. Bootloader commands remain inert.

The fixtures establish parser and preparation regressions; they do not establish
that a real firmware boot or Fedora application lifecycle passed.
