//! Static PE reading. Nothing here loads or executes the image: the file is
//! only parsed as bytes, and every table read is bounds-checked by `object`.

use object::pe;
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile};
use object::{FileKind, LittleEndian as LE};

/// Upper bound on descriptors read from one import table, so a crafted file
/// cannot make us loop over millions of entries.
const MAX_IMPORTS: usize = 4096;
/// DLL names longer than this are treated as damaged.
const MAX_NAME: usize = 256;

const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
const IMAGE_FILE_DLL: u16 = 0x2000;
const DLRVA_ATTRIBUTE: u32 = 1;

pub struct Module {
    pub machine: u16,
    pub is_dll: bool,
    pub native: bool,
    /// Preferred load address from the optional header. The real address is
    /// only known once the loader maps the image, which we never do.
    pub image_base: u64,
    pub imports: Vec<Vec<u8>>,
    pub delay_imports: Vec<Vec<u8>>,
    /// Set when an import table could not be read completely.
    pub damaged: bool,
}

pub fn parse(data: &[u8]) -> Result<Module, &'static str> {
    match FileKind::parse(data) {
        Ok(FileKind::Pe32) => parse_as::<pe::ImageNtHeaders32>(data),
        Ok(FileKind::Pe64) => parse_as::<pe::ImageNtHeaders64>(data),
        _ => Err("not a PE file"),
    }
}

fn parse_as<Pe: ImageNtHeaders>(data: &[u8]) -> Result<Module, &'static str> {
    let file = PeFile::<Pe>::parse(data).map_err(|_| "malformed PE headers")?;
    let nt = file.nt_headers();
    let opt = nt.optional_header();
    let sections = file.section_table();
    let image_base = opt.image_base();

    let read_name = |rva: u32| -> Option<Vec<u8>> {
        let bytes = sections.pe_data_at(data, rva)?;
        let len = bytes.iter().take(MAX_NAME).position(|&b| b == 0)?;
        Some(bytes[..len].to_vec())
    };

    let mut module = Module {
        machine: nt.file_header().machine.get(LE).0,
        is_dll: nt.file_header().characteristics.get(LE).0 & IMAGE_FILE_DLL != 0,
        native: opt.subsystem().0 == IMAGE_SUBSYSTEM_NATIVE,
        image_base,
        imports: Vec::new(),
        delay_imports: Vec::new(),
        damaged: false,
    };

    match file.import_table() {
        Ok(Some(table)) => match table.descriptors() {
            Ok(descriptors) => {
                for descriptor in descriptors.take(MAX_IMPORTS) {
                    let name = descriptor.ok().and_then(|d| read_name(d.name.get(LE)));
                    match name {
                        Some(name) => module.imports.push(name),
                        None => {
                            module.damaged = true;
                            break;
                        }
                    }
                }
            }
            Err(_) => module.damaged = true,
        },
        Ok(None) => {}
        Err(_) => module.damaged = true,
    }

    match file.delay_load_import_table() {
        Ok(Some(table)) => match table.descriptors() {
            Ok(descriptors) => {
                for descriptor in descriptors.take(MAX_IMPORTS) {
                    let name = descriptor.ok().and_then(|d| {
                        let mut rva = d.dll_name_rva.get(LE);
                        // Very old linkers stored virtual addresses instead of RVAs.
                        if d.attributes.get(LE) & DLRVA_ATTRIBUTE == 0 {
                            rva = u64::from(rva)
                                .checked_sub(image_base)
                                .and_then(|r| u32::try_from(r).ok())?;
                        }
                        read_name(rva)
                    });
                    match name {
                        Some(name) => module.delay_imports.push(name),
                        None => {
                            module.damaged = true;
                            break;
                        }
                    }
                }
            }
            Err(_) => module.damaged = true,
        },
        Ok(None) => {}
        Err(_) => module.damaged = true,
    }

    Ok(module)
}

/// Raw contents of the first section called `name`, if the file is a PE.
pub fn section_data<'a>(data: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    match FileKind::parse(data).ok()? {
        FileKind::Pe32 => section_data_as::<pe::ImageNtHeaders32>(data, name),
        FileKind::Pe64 => section_data_as::<pe::ImageNtHeaders64>(data, name),
        _ => None,
    }
}

fn section_data_as<'a, Pe: ImageNtHeaders>(data: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let file = PeFile::<Pe>::parse(data).ok()?;
    let header = file
        .section_table()
        .iter()
        .find(|s| s.raw_name() == name)?;
    header.pe_data(data).ok()
}
