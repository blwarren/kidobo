//! Fedora's image boot layout is exercised without host bootloader commands.
use crate::{read_text, tests::TestDir};
use std::fs;
use std::process::{Command, Output};

const KERNEL: &str = "7.2.13-200.fc44.x86_64";
const ROOT_UUID: &str = "00000000-0000-4000-8000-000000000001";
const BOOT_UUID: &str = "10000000-0000-0000-0000-000000000001";
const FULL_EFI: &str = include_str!("../fixtures/fedora-boot/full-efi.cfg");
const NEW_ENTRY: &str = include_str!("../fixtures/fedora-boot/new.conf");
const OLD_ENTRY: &str = include_str!("../fixtures/fedora-boot/old.conf");

fn canonical() -> String {
    FULL_EFI.replace("set default=\"0\"", "set default=\"${saved_entry}\"")
}

struct Fixture {
    temp: TestDir,
}

impl Fixture {
    fn new(separate_boot: bool, stub: bool) -> Self {
        let fixture = Self {
            temp: TestDir::new(),
        };
        for directory in [
            "boot/efi/EFI/fedora",
            "boot/grub2",
            "boot/loader/entries",
            "etc/kernel",
            "etc/default",
            "proc",
            "prepared",
        ] {
            fs::create_dir_all(fixture.temp.path().join(directory)).expect("fixture directory");
        }
        fixture.write("root-uuid", ROOT_UUID);
        fixture.write(
            "boot-uuid",
            if separate_boot { BOOT_UUID } else { ROOT_UUID },
        );
        fixture.write(
            "grub-path",
            if separate_boot {
                "/grub2"
            } else {
                "/boot/grub2"
            },
        );
        fixture.write("scenario", "normal");
        fixture.write("os-release", "ID=fedora\nPRETTY_NAME=Fedora\n");
        fixture.write("generated-config", &canonical());
        fixture.write("kernel-uuid", &fixture.read("boot-uuid"));
        fixture.write("initramfs-uuid", &fixture.read("boot-uuid"));
        let prefix = if separate_boot { "" } else { "/boot" };
        fixture.write("kernel-path", &format!("{prefix}/vmlinuz-{KERNEL}"));
        fixture.write(
            "initramfs-path",
            &format!("{prefix}/initramfs-{KERNEL}.img"),
        );
        let efi_config = if stub {
            fixture.stub()
        } else {
            FULL_EFI.to_owned()
        };
        fixture.write("boot/efi/EFI/fedora/grub.cfg", &efi_config);
        fixture.write(
            "boot/grub2/grubenv",
            "saved_entry=machine-old\nnext_entry=machine-old\nprev_saved_entry=machine-old\nboot_counter=0\n",
        );
        fixture.write(
            "boot/loader/entries/machine-old.conf",
            &OLD_ENTRY.replace("/boot/", &format!("{prefix}/")),
        );
        fixture.write(
            "boot/loader/entries/machine-new.conf",
            &NEW_ENTRY.replace("/boot/", &format!("{prefix}/")).replace(
                "options root=/dev/loop0p2 ro",
                "options root=/dev/loop0p2 ro selinux=0 rootflags=subvol=root",
            ),
        );
        fixture.write(
            "proc/cmdline",
            &format!("BOOT_IMAGE=/vmlinuz-old root=UUID={ROOT_UUID} ro console=ttyS0 selinux=0\n"),
        );
        fixture.write(
            "etc/kernel/cmdline",
            "root=/dev/loop0p2 ro console=ttyS0 selinux=0 rootflags=subvol=root\n",
        );
        fixture.write(
            "etc/default/grub",
            "GRUB_CMDLINE_LINUX=\"root=/dev/loop0p2 console=ttyS0 selinux=0\"\nGRUB_DEFAULT=0\n",
        );
        fixture
    }

    fn write(&self, path: &str, content: &str) {
        fs::write(self.temp.path().join(path), content).expect("write fixture");
    }

    fn read(&self, path: &str) -> String {
        read_text(&self.temp.path().join(path)).expect("read fixture")
    }

    fn stub(&self) -> String {
        format!(
            "# Existing Fedora stub must survive unchanged\nsearch --no-floppy --fs-uuid --set=dev {}\nset prefix=($dev){}\nexport $prefix\nconfigfile $prefix/grub.cfg\n",
            self.read("boot-uuid"),
            self.read("grub-path")
        )
    }

    fn run(&self) -> Output {
        self.run_script(&format!(
            "prepare_fedora_boot {KERNEL}\nprintf 'selected\\n' > \"$PREPARED/selection-succeeded\""
        ))
    }

    fn run_script(&self, script: &str) -> Output {
        let source = include_str!("../../../scripts/e2e/provision.sh");
        let first = source
            .find("\nfedora_boot_configuration() {")
            .expect("configuration helper")
            + 1;
        let last = source
            .find("\nselect_boot_kernel() {")
            .expect("selection helper");
        // Redirect only filesystem constructors in embedded Python. Logical GRUB
        // paths stay unchanged, and every bootloader command is an inert shell fake.
        let helpers = source[first..last]
            .replace("Path('/", &format!("Path('{}/", self.temp.path().display()));
        let main = source[source.find("\nprovision_main() {").expect("entrypoint")
            ..source.rfind("\nif [[").expect("entrypoint guard")]
            .replace(
                "/etc/os-release",
                &self.temp.path().join("os-release").to_string_lossy(),
            );
        let body = format!(
            r#"
set -euo pipefail
PREPARED=$FIXTURE_ROOT/prepared
BASE=$FIXTURE_ROOT
fail() {{ printf '%s\n' "$*" >&2; exit 1; }}
capture_boot_configuration() {{
  cat "$FIXTURE_ROOT/boot/efi/EFI/fedora/grub.cfg" "$FIXTURE_ROOT/etc/kernel/cmdline" "$FIXTURE_ROOT"/boot/loader/entries/*.conf > "$PREPARED/boot-config-$1.txt"
}}
findmnt() {{ [[ "$*" == '--noheadings --output UUID --target /' ]]; cat "$FIXTURE_ROOT/root-uuid"; }}
grub2-probe() {{
  [[ "$1" == --target=fs_uuid ]]
  case "$2" in
    /boot/grub2) cat "$FIXTURE_ROOT/boot-uuid" ;;
    /boot/vmlinuz-{KERNEL}) cat "$FIXTURE_ROOT/kernel-uuid" ;;
    /boot/initramfs-{KERNEL}.img) cat "$FIXTURE_ROOT/initramfs-uuid" ;;
    *) exit 96 ;;
  esac
}}
grub2-mkrelpath() {{
  case "$1" in
    /boot/grub2) cat "$FIXTURE_ROOT/grub-path" ;;
    /boot/vmlinuz-{KERNEL}) cat "$FIXTURE_ROOT/kernel-path" ;;
    /boot/initramfs-{KERNEL}.img) cat "$FIXTURE_ROOT/initramfs-path" ;;
    *) exit 95 ;;
  esac
}}
grub2-mkconfig() {{
  [[ "$*" == '-o /boot/grub2/grub.cfg' ]]
  cp "$FIXTURE_ROOT/generated-config" "$FIXTURE_ROOT/boot/grub2/grub.cfg"
}}
grubby() {{
  # Reproduce the misleading success in the real failure: grubby always agrees.
  case "$1" in
    --set-default)
      [[ "$2" == '/boot/vmlinuz-{KERNEL}' ]]
      if [[ "$(cat "$FIXTURE_ROOT/scenario")" == corrupt-root ]]; then
        sed -i 's@root=UUID=[^ ]*@root=/dev/loop0p2@' "$FIXTURE_ROOT/boot/loader/entries/machine-new.conf"
      fi ;;
    --default-kernel) printf '/boot/vmlinuz-{KERNEL}\n' ;;
    *) exit 98 ;;
  esac
}}
grub2-editenv() {{
  [[ "$1" == /boot/grub2/grubenv ]]
  case "$2" in
    set)
      if [[ "$(cat "$FIXTURE_ROOT/scenario")" != wrong-environment ]]; then
        sed -i '/^saved_entry=/d' "$FIXTURE_ROOT/boot/grub2/grubenv"
        printf '%s\n' "$3" >> "$FIXTURE_ROOT/boot/grub2/grubenv"
      fi ;;
    unset)
      [[ "$*" == '/boot/grub2/grubenv unset next_entry prev_saved_entry boot_counter' ]]
      if [[ "$(cat "$FIXTURE_ROOT/scenario")" != stale-override ]]; then
        sed -i -e '/^next_entry=/d' -e '/^prev_saved_entry=/d' -e '/^boot_counter=/d' "$FIXTURE_ROOT/boot/grub2/grubenv"
      fi ;;
    list) cat "$FIXTURE_ROOT/boot/grub2/grubenv" ;;
    *) exit 97 ;;
  esac
}}
{helpers}
{main}
{script}
"#
        );
        Command::new("bash")
            .args(["-c", &body])
            .env("FIXTURE_ROOT", self.temp.path())
            .output()
            .expect("isolated Fedora boot preparation")
    }
}

#[test]
fn fedora_shared_boot_accepts_captured_kernel_paths() {
    let fixture = Fixture::new(false, false);
    let output = fixture.run();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(fixture.read("prepared/selected-bls-entry"), "machine-new\n");
}

#[test]
fn fedora_accepts_stock_grub_fallback_selection() {
    let fixture = Fixture::new(true, false);
    let output = fixture.run();
    assert!(output.status.success(), "{output:?}");
    assert!(
        fixture
            .read("boot/grub2/grub.cfg")
            .contains("set default=1")
    );
    assert_eq!(
        fixture.read("boot/grub2/grubenv"),
        "saved_entry=machine-new\n"
    );
}

#[test]
fn fedora_rechecks_boot_selection_after_selinux_preparation() {
    for scenario in ["corrupt-root", "changed-selection", "normal"] {
        let fixture = Fixture::new(false, false);
        let script = format!(
            r#"
require_guest() {{ :; }}
e2e_check_start() {{ :; }}
e2e_check_pass() {{ :; }}
e2e_report_exit() {{ :; }}
wait_for_network() {{ :; }}
install_dependencies() {{ :; }}
record_packages() {{ printf 'fixture\n' > "$2"; }}
upgrade_operating_system() {{ :; }}
installed_kernel() {{ printf '%s\n' '{KERNEL}'; }}
select_boot_kernel() {{ prepare_fedora_boot "$2"; }}
prepare_selinux() {{
  sed -i 's/selinux=0/selinux=1 enforcing=0/g' "$FIXTURE_ROOT"/boot/loader/entries/*.conf
  case '{scenario}' in
    corrupt-root) sed -i 's@root=UUID=[^ ]*@root=/dev/loop0p2@' "$FIXTURE_ROOT/boot/loader/entries/machine-new.conf" ;;
    changed-selection) printf 'saved_entry=machine-old\n' > "$FIXTURE_ROOT/boot/grub2/grubenv" ;;
  esac
  printf '1\n' > "$PREPARED/relabel-scheduled"
}}
provision_main --prepare dnf enforcing fixture
printf 'accepted\n' > "$PREPARED/preparation-completed"
"#
        );
        let output = fixture.run_script(&script);
        let completed = fixture.temp.path().join("prepared/preparation-completed");
        if scenario == "normal" {
            assert!(output.status.success(), "{output:?}");
            assert_eq!(fixture.read("prepared/preparation-completed"), "accepted\n");
            assert!(
                fixture
                    .read("prepared/boot-config-final.txt")
                    .contains("selinux=1 enforcing=0")
            );
        } else {
            assert_eq!(output.status.code(), Some(1), "{scenario}: {output:?}");
            let expected = if scenario == "corrupt-root" {
                "root identity is not explicit"
            } else {
                "does not select the intended BLS"
            };
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(expected),
                "{output:?}"
            );
            assert!(!completed.exists());
        }
    }
}

#[test]
fn fedora_repairs_image_builder_roots_and_the_actual_efi_selection_chain() {
    for separate in [false, true] {
        let fixture = Fixture::new(separate, false);
        let output = fixture.run();
        assert!(output.status.success(), "{output:?}");
        let efi = fixture.read("boot/efi/EFI/fedora/grub.cfg");
        assert!(efi.contains(&format!("--set=dev {}", fixture.read("boot-uuid"))));
        assert!(efi.contains(&format!("set prefix=($dev){}", fixture.read("grub-path"))));
        assert!(efi.contains("configfile $prefix/grub.cfg"));
        assert_eq!(
            fixture.read("boot/grub2/grubenv"),
            "saved_entry=machine-new\n"
        );
        assert_eq!(fixture.read("boot/grub2/grub.cfg"), canonical());
        for path in [
            "etc/kernel/cmdline",
            "etc/default/grub",
            "boot/loader/entries/machine-old.conf",
            "boot/loader/entries/machine-new.conf",
        ] {
            let text = fixture.read(path);
            assert!(
                text.contains(&format!("root=UUID={ROOT_UUID}")),
                "{path}: {text}"
            );
            assert!(text.contains("console=ttyS0"), "{path}: {text}");
            assert!(
                text.contains("selinux=0"),
                "selection must preserve security arguments until SELinux preparation: {path}"
            );
            assert!(!text.contains("/dev/loop"), "{path}: {text}");
            assert!(!text.contains("$kernelopts"), "{path}: {text}");
        }
        assert!(
            fixture
                .read("etc/kernel/cmdline")
                .contains("rootflags=subvol=root")
        );
        assert!(
            fixture
                .read("boot/loader/entries/machine-new.conf")
                .contains("rootflags=subvol=root")
        );
        assert!(
            fixture
                .read("prepared/boot-config-before.txt")
                .contains("/dev/loop0p2")
        );
        assert!(
            !fixture
                .read("prepared/boot-config-after.txt")
                .contains("/dev/loop0p2")
        );
        assert_eq!(fixture.read("prepared/selection-succeeded"), "selected\n");
    }
}

#[test]
fn fedora_preserves_a_correct_existing_efi_forwarding_stub() {
    let fixture = Fixture::new(true, true);
    let before = fixture.read("boot/efi/EFI/fedora/grub.cfg");
    let output = fixture.run();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(fixture.read("boot/efi/EFI/fedora/grub.cfg"), before);
}

#[test]
fn fedora_root_repair_preserves_quoted_and_nested_non_root_arguments() {
    let fixture = Fixture::new(false, false);
    fixture.write(
        "etc/default/grub",
        "GRUB_CMDLINE_LINUX=\"root=/dev/loop0p2 console=ttyS0 custom=root=/dev/keep quoted='root=/dev/keep with spaces'\"\n",
    );
    let output = fixture.run();
    assert!(output.status.success(), "{output:?}");
    let defaults = fixture.read("etc/default/grub");
    assert!(defaults.contains("custom=root=/dev/keep"));
    assert!(defaults.contains("quoted='root=/dev/keep with spaces'"));
    assert!(defaults.contains(&format!("root=UUID={ROOT_UUID}")));
    assert!(!defaults.contains("root=/dev/loop0p2"));
}

#[test]
fn fedora_rejects_unknown_layouts_and_missing_root_identity_before_boot_writes() {
    for (scenario, message) in [
        ("unknown", "unrecognized EFI"),
        ("ambiguous", "ambiguous EFI"),
        ("missing-root", "root UUID"),
    ] {
        let fixture = Fixture::new(false, false);
        match scenario {
            "unknown" => fixture.write(
                "boot/efi/EFI/fedora/grub.cfg",
                "configfile /somewhere/else\n",
            ),
            "ambiguous" => fixture.write("boot/efi/EFI/grub.cfg", FULL_EFI),
            "missing-root" => fixture.write("root-uuid", ""),
            _ => unreachable!(),
        }
        let before = fixture.read("boot/efi/EFI/fedora/grub.cfg");
        let options = fixture.read("etc/kernel/cmdline");
        let output = fixture.run();
        assert!(!output.status.success(), "{scenario}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "{scenario}: {output:?}"
        );
        assert_eq!(fixture.read("boot/efi/EFI/fedora/grub.cfg"), before);
        assert_eq!(fixture.read("etc/kernel/cmdline"), options);
        assert!(
            !fixture
                .temp
                .path()
                .join("prepared/selection-succeeded")
                .exists()
        );
        assert!(
            fixture
                .temp
                .path()
                .join("prepared/boot-config-after.txt")
                .exists()
        );
    }
}

#[test]
fn fedora_rejects_bad_canonical_selection_even_when_grubby_reports_success() {
    for (scenario, message) in [
        ("wrong-environment", "does not select the intended BLS"),
        ("bad-config", "lacks environment-based BLS"),
        ("deceptive-config", "lacks environment-based BLS"),
        ("stale-override", "still overrides the next boot"),
        ("corrupt-root", "root identity is not explicit"),
    ] {
        let fixture = Fixture::new(false, false);
        fixture.write("scenario", scenario);
        if scenario == "bad-config" {
            fixture.write("generated-config", "set default=old\nmenuentry old {{}}\n");
        }
        if scenario == "deceptive-config" {
            fixture.write(
                "generated-config",
                "load_env\n# ${saved_entry}\nset default=0\nblscfg\n",
            );
        }
        let output = fixture.run();
        assert!(!output.status.success(), "{scenario}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "{scenario}: {output:?}"
        );
        assert!(
            !fixture
                .temp
                .path()
                .join("prepared/selection-succeeded")
                .exists()
        );
        assert!(
            fixture
                .temp
                .path()
                .join("prepared/boot-config-after.txt")
                .exists()
        );
    }
}

#[test]
fn fedora_rejects_missing_duplicate_or_inconsistent_boot_artifacts() {
    for (scenario, expected) in [
        ("missing", "matched 0"),
        ("duplicate", "matched 2"),
        ("wrong-path", "matched 0"),
        ("multiple-linux", "exactly one kernel path"),
        ("wrong-initrd", "does not reference intended initramfs"),
        ("kernel-filesystem", "different GRUB filesystem"),
        ("initramfs-filesystem", "different GRUB filesystem"),
    ] {
        let fixture = Fixture::new(false, false);
        let entry = fixture.read("boot/loader/entries/machine-new.conf");
        match scenario {
            "missing" => fs::remove_file(
                fixture
                    .temp
                    .path()
                    .join("boot/loader/entries/machine-new.conf"),
            )
            .expect("remove intended entry"),
            "duplicate" => fixture.write("boot/loader/entries/duplicate.conf", &entry),
            "wrong-path" => fixture.write(
                "boot/loader/entries/machine-new.conf",
                &entry.replace("linux /boot/", "linux /"),
            ),
            "multiple-linux" => fixture.write(
                "boot/loader/entries/machine-new.conf",
                &format!("{entry}linux /vmlinuz-other\n"),
            ),
            "wrong-initrd" => fixture.write(
                "boot/loader/entries/machine-new.conf",
                &entry.replace("initrd /boot/", "initrd /"),
            ),
            "kernel-filesystem" => fixture.write("kernel-uuid", BOOT_UUID),
            "initramfs-filesystem" => fixture.write("initramfs-uuid", BOOT_UUID),
            _ => unreachable!(),
        }
        let options = fixture.read("etc/kernel/cmdline");
        let output = fixture.run();
        assert_eq!(output.status.code(), Some(1), "{scenario}: {output:?}");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains(expected), "{scenario}: {output:?}");
        if expected.starts_with("matched") {
            assert!(
                error.contains(&format!("/boot/vmlinuz-{KERNEL}")),
                "{error}"
            );
            assert!(error.contains("machine-old.conf"), "{error}");
        }
        assert_eq!(fixture.read("etc/kernel/cmdline"), options);
        assert_eq!(fixture.read("boot/efi/EFI/fedora/grub.cfg"), FULL_EFI);
        assert!(
            !fixture
                .temp
                .path()
                .join("prepared/selection-succeeded")
                .exists()
        );
    }
}

#[test]
fn fedora_rejects_modified_grub_guards_and_unexpected_overrides() {
    for (before, after, expected) in [
        (
            "if [ \"${next_entry}\" ]",
            "if [ \"different\" ]",
            "lacks environment-based BLS",
        ),
        (
            "if [ -n \"${boot_counter}\"",
            "if [ -z \"${boot_counter}\"",
            "unrecognized fallback guard",
        ),
        (
            "set boot_counter=-1",
            "set boot_counter=0",
            "unrecognized fallback guard",
        ),
        ("blscfg\n", "# blscfg\n", "lacks environment-based BLS"),
        (
            "set pager=1",
            "set pager=1; set default=1",
            "unexpected boot override",
        ),
        (
            "set pager=1",
            "set pager=1\nset default=\"${saved_entry}\"",
            "unexpected boot override",
        ),
        (
            "set pager=1",
            "set prefix=/other",
            "unexpected boot override",
        ),
        (
            "set pager=1",
            "configfile /other",
            "redirects boot selection",
        ),
        (
            "set pager=1",
            "load_env -f /other",
            "redirects boot selection",
        ),
    ] {
        let fixture = Fixture::new(false, false);
        fixture.write("generated-config", &canonical().replace(before, after));
        let output = fixture.run();
        assert_eq!(output.status.code(), Some(1), "{after}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{after}: {output:?}"
        );
        assert!(
            !fixture
                .temp
                .path()
                .join("prepared/selection-succeeded")
                .exists()
        );
    }
}

#[test]
fn fedora_accepts_grub_whitespace_and_comments_and_repeated_preparation() {
    let fixture = Fixture::new(false, false);
    let formatted = canonical()
        .lines()
        .map(|line| {
            if line.starts_with("###") {
                line.to_owned()
            } else {
                format!("\t  {line}  # fixture annotation")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fixture.write("generated-config", &formatted);
    let first = fixture.run();
    assert!(first.status.success(), "{first:?}");
    let paths = [
        "boot/efi/EFI/fedora/grub.cfg",
        "boot/grub2/grub.cfg",
        "boot/grub2/grubenv",
        "etc/kernel/cmdline",
        "etc/default/grub",
        "boot/loader/entries/machine-new.conf",
    ];
    let before: Vec<_> = paths.iter().map(|path| fixture.read(path)).collect();
    let second = fixture.run();
    assert!(second.status.success(), "{second:?}");
    for (path, expected) in paths.iter().zip(before) {
        assert_eq!(fixture.read(path), expected, "{path}");
    }
}
