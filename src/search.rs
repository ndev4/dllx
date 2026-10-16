//! Finds the file a DLL name refers to, following the loader's standard search
//! order with SafeDllSearchMode on (the Windows default):
//!   KnownDLLs, application directory, system directory, Windows directory,
//!   current directory, then each PATH directory.
//! A candidate is accepted only if it parses as a PE for the target's machine.
//! WinSxS side-by-side manifests and SetDllDirectory/AddDllDirectory are not
//! emulated; those DLLs resolve to the copy the plain search finds, if any.

use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};

use crate::apiset::{ApiSet, ApiSetSchema};
use crate::pe::{self, Module};
use crate::{knowndlls, read_file};

const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;

pub struct Resolver {
    machine: u16,
    app_dir: PathBuf,
    system_dir: PathBuf,
    windows_dir: PathBuf,
    current_dir: Option<PathBuf>,
    path_dirs: Vec<PathBuf>,
    known_dlls: HashSet<String>,
    apisets: Option<ApiSetSchema>,
}

impl Resolver {
    pub fn new(app_dir: PathBuf, machine: u16) -> Self {
        let windows_dir = env::var_os("SystemRoot")
            .or_else(|| env::var_os("windir"))
            .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
        let windows_dir = canonical(&windows_dir);

        // 32-bit images on 64-bit Windows get their system DLLs from the WOW64 directory.
        let wow_dir = match machine {
            IMAGE_FILE_MACHINE_I386 => Some(windows_dir.join("SysWOW64")),
            IMAGE_FILE_MACHINE_ARMNT => Some(windows_dir.join("SysArm32")),
            _ => None,
        };
        let system_dir = wow_dir
            .filter(|d| d.is_dir())
            .unwrap_or_else(|| windows_dir.join("System32"));

        let path_dirs = env::var_os("PATH")
            .map(|p| env::split_paths(&p).filter(|d| !d.as_os_str().is_empty()).collect())
            .unwrap_or_default();

        // The schema is read by the kernel from System32 for every process.
        let apisets = ApiSetSchema::load(&windows_dir.join("System32").join("apisetschema.dll"));

        Self {
            machine,
            app_dir,
            system_dir,
            windows_dir,
            current_dir: env::current_dir().ok(),
            path_dirs,
            known_dlls: knowndlls::load(),
            apisets,
        }
    }

    pub fn api_set<'a>(&'a self, name: &'a str) -> ApiSet<'a> {
        match &self.apisets {
            Some(schema) => schema.resolve(name),
            None if crate::apiset::is_api_set_name(&name.to_ascii_lowercase()) => ApiSet::Missing,
            None => ApiSet::Plain,
        }
    }

    /// Returns the canonical path and parsed contents of the first matching file.
    pub fn find(&self, name: &str) -> Option<(PathBuf, Module)> {
        self.search_dirs(name).into_iter().find_map(|dir| {
            let path = dir.join(name);
            let data = read_file(&path).ok()?;
            let module = pe::parse(&data).ok()?;
            (module.machine == self.machine).then(|| (canonical(&path), module))
        })
    }

    pub fn is_system(&self, path: &Path) -> bool {
        let path = path.to_string_lossy().to_ascii_lowercase();
        let windows = self.windows_dir.to_string_lossy().to_ascii_lowercase();
        path.starts_with(&windows)
    }

    fn search_dirs(&self, name: &str) -> Vec<&Path> {
        if self.known_dlls.contains(&name.to_ascii_lowercase()) {
            return vec![&self.system_dir];
        }
        let mut dirs = vec![
            self.app_dir.as_path(),
            &self.system_dir,
            &self.windows_dir,
        ];
        dirs.extend(self.current_dir.as_deref());
        dirs.extend(self.path_dirs.iter().map(PathBuf::as_path));
        dirs
    }
}

pub fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}
