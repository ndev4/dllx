//! dllx: list the DLLs a Windows executable or DLL depends on, in the same
//! format as `ldd`. The file being inspected is only read and parsed, never
//! loaded or run, so it is safe to use on untrusted binaries. (The optional
//! --load-addr flag maps trusted system DLLs to read their live load address
//! without running any of their code; the inspected file is still never loaded.)

mod apiset;
mod knowndlls;
mod loadaddr;
mod pe;
mod search;

use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use apiset::ApiSet;
use search::Resolver;

const MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;
/// Stops the walk on dependency graphs no real program has.
const MAX_MODULES: usize = 4096;

/// Every Win32 process gets these from the loader, whether the exe imports them or not.
/// DLLs are listed with their real imports only.
const IMPLICIT_WIN32: &[&str] = &["ntdll.dll", "KERNEL32.DLL", "KERNELBASE.dll"];
const IMPLICIT_NATIVE: &[&str] = &["ntdll.dll"];

const USAGE: &str = "\
Usage: dllx [OPTION]... FILE...
Print the DLLs each FILE depends on, without loading or running it.
Each FILE is preceded by a header naming its architecture and type.

      --posix-paths    print paths as /c/... instead of C:\\...
      --delay          also list delay-loaded DLLs, marked [delay]
  -p, --pretty         line up the => arrows
  -l, --load-addr      show the live per-boot load address of system DLLs,
                       like ldd; others keep their header base, marked
                       [image base]. The inspected FILE is never loaded.
  -h, --help           show this help and exit
  -V, --version        show the version and exit

By default, addresses are the preferred image base from each DLL's header.
With --load-addr, system DLLs instead show where they are actually mapped this
boot, read by mapping the trusted system image without running any of its code.
";

struct Options {
    posix_paths: bool,
    delay: bool,
    pretty: bool,
    load_addr: bool,
}

struct Entry {
    name: String,
    found: Option<(PathBuf, u64)>,
    delay: bool,
}

fn main() -> ExitCode {
    let mut options = Options { posix_paths: false, delay: false, pretty: false, load_addr: false };
    let mut files = Vec::new();
    let mut only_files = false;
    for arg in std::env::args_os().skip(1) {
        match arg.to_str() {
            _ if only_files => files.push(PathBuf::from(arg)),
            Some("--") => only_files = true,
            Some("--posix-paths") => options.posix_paths = true,
            Some("--delay") => options.delay = true,
            Some("-p" | "--pretty") => options.pretty = true,
            Some("-l" | "--load-addr") => options.load_addr = true,
            Some("-h" | "--help") => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            Some("-V" | "--version") => {
                println!("dllx {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            Some(s) if s.starts_with('-') && s.len() > 1 => {
                eprintln!("dllx: unknown option '{s}'\nTry 'dllx --help' for more information.");
                return ExitCode::from(2);
            }
            _ => files.push(PathBuf::from(arg)),
        }
    }
    if files.is_empty() {
        eprintln!("dllx: missing file arguments\nTry 'dllx --help' for more information.");
        return ExitCode::from(2);
    }

    let mut out = io::stdout().lock();
    let mut status = ExitCode::SUCCESS;
    for file in &files {
        let shown = sanitize(&file.to_string_lossy());
        if let Err(message) = list(file, &options, &mut out) {
            let _ = out.flush();
            eprintln!("dllx: {shown}: {message}");
            status = ExitCode::FAILURE;
        }
    }
    status
}

fn list(file: &Path, options: &Options, out: &mut impl Write) -> Result<(), String> {
    let data = read_file(file).map_err(|e| e.to_string())?;
    let root = pe::parse(&data).map_err(str::to_string)?;
    drop(data);
    writeln!(out, "{}: {}", sanitize(&file.to_string_lossy()), describe(&root)).map_err(|e| e.to_string())?;
    if root.damaged {
        eprintln!("dllx: warning: {}: damaged import table, list may be incomplete", sanitize(&file.to_string_lossy()));
    }

    let path = search::canonical(file);
    let app_dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let resolver = Resolver::new(app_dir, root.machine);

    let own_name = path.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase());
    let entries = walk(&root, own_name, &resolver, options);
    // Names are plain ASCII (validated or escaped), so byte length is display width.
    let width = if options.pretty { entries.iter().map(|e| e.name.len()).max().unwrap_or(0) } else { 0 };
    for entry in entries {
        let mut line = format!("\t{:width$} => ", entry.name);
        match &entry.found {
            Some((path, image_base)) => {
                line += &display_path(path, options.posix_paths);
                // --load-addr shows the live base for system DLLs (mapped
                // without running their code); private DLLs have no fixed
                // runtime base, so they keep the header value, marked.
                let live = (options.load_addr && resolver.is_system(path))
                    .then(|| loadaddr::base_of(path))
                    .flatten();
                match live {
                    Some(addr) => line += &format!(" (0x{addr:x})"),
                    None if options.load_addr => line += &format!(" (0x{image_base:x} [image base])"),
                    None => line += &format!(" (0x{image_base:x})"),
                }
            }
            None => line += "not found",
        }
        if entry.delay {
            line += " [delay]";
        }
        writeln!(out, "{line}").map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Depth-first walk in import order, so the list reads roughly in the order
/// the loader would map the DLLs. Everything reachable through normal imports
/// is listed before anything reachable only through delay-loaded ones.
fn walk(root: &pe::Module, own_name: Option<String>, resolver: &Resolver, options: &Options) -> Vec<Entry> {
    let mut entries = Vec::new();
    // A DLL never lists itself, even when its imports lead back to it.
    let mut seen: HashSet<String> = own_name.into_iter().collect();
    let mut stack: Vec<(Vec<u8>, bool)> = Vec::new();
    let mut delayed: VecDeque<Vec<u8>> = VecDeque::new();

    stack.extend(root.imports.iter().rev().map(|n| (n.clone(), false)));
    let implicit = match (root.is_dll, root.native) {
        (true, _) => &[][..],
        (false, true) => IMPLICIT_NATIVE,
        (false, false) => IMPLICIT_WIN32,
    };
    stack.extend(implicit.iter().rev().map(|n| (n.as_bytes().to_vec(), false)));
    if options.delay {
        delayed.extend(root.delay_imports.iter().cloned());
    }

    while let Some((raw, delay)) = stack.pop().or_else(|| delayed.pop_front().map(|n| (n, true))) {
        if seen.len() >= MAX_MODULES {
            eprintln!("dllx: warning: more than {MAX_MODULES} DLLs, list truncated");
            break;
        }
        let Some(imported) = valid_dll_name(&raw) else {
            let name = escape(&raw);
            if seen.insert(name.clone()) {
                entries.push(Entry { name, found: None, delay });
            }
            continue;
        };
        let name = match resolver.api_set(imported) {
            ApiSet::Plain => imported,
            ApiSet::Host(host) => host,
            ApiSet::Missing => {
                if seen.insert(imported.to_ascii_lowercase()) {
                    entries.push(Entry { name: imported.to_string(), found: None, delay });
                }
                continue;
            }
        };
        if !seen.insert(name.to_ascii_lowercase()) {
            continue;
        }

        let Some((path, module)) = resolver.find(name) else {
            entries.push(Entry { name: name.to_string(), found: None, delay });
            continue;
        };
        if module.damaged {
            eprintln!("dllx: warning: {}: damaged import table, list may be incomplete", sanitize(&path.to_string_lossy()));
        }
        stack.extend(module.imports.iter().rev().map(|n| (n.clone(), delay)));
        // System DLLs delay-load dozens of optional components; only follow
        // delay imports of the program's own DLLs.
        if options.delay && !resolver.is_system(&path) {
            delayed.extend(module.delay_imports.iter().cloned());
        }
        entries.push(Entry { name: name.to_string(), found: Some((path, module.image_base)), delay });
    }
    entries
}

/// Reads a regular file, refusing devices, pipes and anything over the size limit.
pub fn read_file(path: &Path) -> io::Result<Vec<u8>> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    let mut data = Vec::new();
    file.take(MAX_FILE_SIZE + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_FILE_SIZE {
        return Err(io::Error::other("file too large"));
    }
    Ok(data)
}

/// Accepts only plain file names the loader could look up. Rejects path
/// separators, control characters and device names like CON or COM1, which
/// would open a device instead of a file.
fn valid_dll_name(raw: &[u8]) -> Option<&str> {
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$", "COM0", "COM1", "COM2", "COM3",
        "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4",
        "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let name = std::str::from_utf8(raw).ok()?;
    let ok = !name.is_empty()
        && name.len() <= 255
        && name.bytes().all(|b| (0x20..0x7f).contains(&b) && !br#"\/:*?"<>|"#.contains(&b))
        && !name.ends_with(['.', ' '])
        && name != "."
        && name != "..";
    let stem = name.split('.').next().unwrap_or("").trim_end();
    (ok && !RESERVED.iter().any(|r| stem.eq_ignore_ascii_case(r))).then_some(name)
}

/// Shows an untrusted byte string with anything non-printable as \xNN.
fn escape(raw: &[u8]) -> String {
    raw.iter()
        .map(|&b| match b {
            0x20..=0x7e if b != b'\\' => (b as char).to_string(),
            _ => format!("\\x{b:02x}"),
        })
        .collect()
}

/// Replaces control characters so a file name cannot inject terminal escapes.
fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { '?' } else { c }).collect()
}

/// One-line summary of the image for the file header: architecture, whether it
/// is an executable or a DLL, its address width, and whether it is a native
/// (kernel/subsystem) image.
fn describe(root: &pe::Module) -> String {
    let kind = if root.is_dll { "library" } else { "executable" };
    let native = if root.native { " (native)" } else { "" };
    let (arch, bits) = match root.machine {
        0x014c => ("i386", "32-bit"),
        0x8664 => ("x86-64", "64-bit"),
        0x01c4 => ("ARM Thumb-2", "32-bit"),
        0xaa64 => ("ARM64", "64-bit"),
        0x0200 => ("IA-64", "64-bit"),
        other => return format!("machine 0x{other:04x} {kind}, unknown width{native}"),
    };
    format!("{arch} {kind}, {bits}{native}")
}

fn display_path(path: &Path, posix: bool) -> String {
    let s = path.to_string_lossy();
    let s = if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else {
        s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
    };
    let s = sanitize(&s);
    if !posix {
        return s;
    }
    let b = s.as_bytes();
    let s = if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        format!("/{}{}", (b[0] as char).to_ascii_lowercase(), &s[2..])
    } else {
        s
    };
    s.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dll_names() {
        assert_eq!(valid_dll_name(b"KERNEL32.dll"), Some("KERNEL32.dll"));
        assert_eq!(valid_dll_name(b"msvcp140_1.dll"), Some("msvcp140_1.dll"));
        assert_eq!(valid_dll_name(b"..\\evil.dll"), None);
        assert_eq!(valid_dll_name(b"C:evil.dll"), None);
        assert_eq!(valid_dll_name(b"CON"), None);
        assert_eq!(valid_dll_name(b"com1.dll"), None);
        assert_eq!(valid_dll_name(b"nul .dll"), None);
        assert_eq!(valid_dll_name(b"a\x1b[31m.dll"), None);
        assert_eq!(valid_dll_name(b""), None);
        assert_eq!(valid_dll_name(b"foo."), None);
    }

    #[test]
    fn escaping() {
        assert_eq!(escape(b"a\x1bb\\"), "a\\x1bb\\x5c");
    }

    #[test]
    fn paths() {
        let p = Path::new(r"\\?\C:\Windows\System32\ntdll.dll");
        assert_eq!(display_path(p, true), "/c/Windows/System32/ntdll.dll");
        assert_eq!(display_path(p, false), r"C:\Windows\System32\ntdll.dll");
        let unc = Path::new(r"\\?\UNC\server\share\a.dll");
        assert_eq!(display_path(unc, true), "//server/share/a.dll");
    }
}
