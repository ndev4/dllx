//! API sets: names like `api-ms-win-core-file-l1-2-4.dll` are not real files.
//! The loader maps them to a host DLL (here `kernelbase.dll`) using the
//! schema stored in the `.apiset` section of `apisetschema.dll`.
//! Only schema version 6 (Windows 10 and later) is understood.

use std::collections::HashMap;
use std::path::Path;

const SCHEMA_VERSION: u32 = 6;
const NAMESPACE_ENTRY_SIZE: usize = 24;
const VALUE_ENTRY_SIZE: usize = 20;
const MAX_ENTRIES: usize = 100_000;
const MAX_VALUES: usize = 64;
const MAX_NAME_BYTES: usize = 1024;

pub enum ApiSet<'a> {
    /// An ordinary DLL name.
    Plain,
    Host(&'a str),
    /// A known contract with no implementation on this system, or a name
    /// that looks like an API set but is not in the schema.
    Missing,
}

pub struct ApiSetSchema {
    /// Contract name without its last `-N` version part, lowercased, to host DLL.
    hosts: HashMap<String, Option<String>>,
}

impl ApiSetSchema {
    pub fn load(path: &Path) -> Option<Self> {
        let data = crate::read_file(path).ok()?;
        Self::parse(crate::pe::section_data(&data, b".apiset")?)
    }

    fn parse(ns: &[u8]) -> Option<Self> {
        if u32_at(ns, 0)? != SCHEMA_VERSION {
            return None;
        }
        let count = u32_at(ns, 12)? as usize;
        let entries = u32_at(ns, 16)? as usize;
        if count > MAX_ENTRIES {
            return None;
        }

        let mut hosts = HashMap::with_capacity(count);
        for i in 0..count {
            let entry = entries + i * NAMESPACE_ENTRY_SIZE;
            let name_offset = u32_at(ns, entry + 4)?;
            let hashed_length = u32_at(ns, entry + 12)?;
            let values = u32_at(ns, entry + 16)? as usize;
            let value_count = u32_at(ns, entry + 20)? as usize;
            let Some(name) = utf16_at(ns, name_offset, hashed_length) else {
                continue;
            };

            // The value with an empty name is the default host; the others
            // are exceptions that apply only when a specific DLL imports it.
            let mut default = None;
            let mut first = None;
            for j in 0..value_count.min(MAX_VALUES) {
                let value = values + j * VALUE_ENTRY_SIZE;
                let importer_length = u32_at(ns, value + 8)?;
                let host = utf16_at(ns, u32_at(ns, value + 12)?, u32_at(ns, value + 16)?)
                    .filter(|h| !h.is_empty());
                if host.is_none() {
                    continue;
                }
                if importer_length == 0 {
                    default = host;
                    break;
                }
                if first.is_none() {
                    first = host;
                }
            }
            hosts.insert(name.to_ascii_lowercase(), default.or(first));
        }
        Some(Self { hosts })
    }

    pub fn resolve(&self, name: &str) -> ApiSet<'_> {
        let lower = name.to_ascii_lowercase();
        if !is_api_set_name(&lower) {
            return ApiSet::Plain;
        }
        let stem = lower.strip_suffix(".dll").unwrap_or(&lower);
        let key = stem.rfind('-').map_or(stem, |i| &stem[..i]);
        match self.hosts.get(key) {
            Some(Some(host)) => ApiSet::Host(host),
            _ => ApiSet::Missing,
        }
    }
}

pub fn is_api_set_name(lower: &str) -> bool {
    lower.starts_with("api-") || lower.starts_with("ext-")
}

fn u32_at(buf: &[u8], offset: usize) -> Option<u32> {
    let bytes = buf.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn utf16_at(buf: &[u8], offset: u32, length: u32) -> Option<String> {
    let (offset, length) = (offset as usize, length as usize);
    if length % 2 != 0 || length > MAX_NAME_BYTES {
        return None;
    }
    let bytes = buf.get(offset..offset.checked_add(length)?)?;
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|&c| u16::from_le_bytes(c)).collect();
    String::from_utf16(&units).ok()
}
