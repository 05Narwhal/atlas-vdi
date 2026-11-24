// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! VirtualBox disk images (`.vdi`): dynamic and fixed (static) images.
//!
//! # Layout
//!
//! Source: the VirtualBox source, `src/VBox/Storage/VDICore.h` (the
//! `VDIPREHEADER` and `VDIHEADER1PLUS` structures), cross-checked against
//! the libyal libvdi notes "VirtualBox Virtual Disk Image (VDI) format". All
//! integers are little-endian. Offsets are from the start of the file:
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 64 | text `<<< Oracle VM VirtualBox Disk Image >>>`, ignored |
//! | 64 | 4 | signature `0xBEDA107F` |
//! | 68 | 4 | version: minor in the low 16 bits, major in the high |
//! | 72 | 4 | header size (400 for VirtualBox 1.1, 384 as qemu-img writes it; both put the fields below at the same offsets) |
//! | 76 | 4 | image type: 1 dynamic, 2 fixed, 3 undo, 4 differencing |
//! | 340 | 4 | offset of the block map |
//! | 344 | 4 | offset of the first data block |
//! | 368 | 8 | disk size in bytes |
//! | 376 | 4 | block size (1 MiB by default) |
//! | 380 | 4 | extra bytes per block (always 0) |
//! | 384 | 4 | blocks in the image |
//! | 388 | 4 | blocks allocated, informational |
//!
//! The block map holds one `u32` per block: the index of the block among the
//! stored data blocks, `0xFFFFFFFF` when the block was never written, or
//! `0xFFFFFFFE` when it is all zeros without being stored. Block `i` of the
//! disk starts at `offset of data + index * block size`. A fixed image has
//! the same map with every block stored in order.
//!
//! # Choices where the references are silent
//!
//! - Version 1.1 and later minors of major 1 open; version 1.0 (a shorter
//!   header) and other majors are `Unsupported`.
//! - Image types 3 and 4 (a snapshot or differencing image with a parent) are
//!   `Unsupported`; any other type is corrupt.
//! - A nonzero extra size per block is `Unsupported`.
//! - The block size must be a multiple of 512 and at most 256 MiB.
//! - The map must hold at least `ceil(disk size / block size)` entries and
//!   lie inside the file. A map over 64 MiB is `Unsupported`.
//! - A block that starts at or past the end of the file is corrupt; one cut
//!   short by the end of the file reads its missing part as zeros.
//! - The text at the start and the "blocks allocated" count are not checked.
//!
//! ```no_run
//! use std::path::Path;
//!
//! use atlas_fs_core::io::block::BlockSource;
//!
//! # fn main() -> Result<(), atlas_fs_core::error::Error> {
//! let disk = atlas_vdi::open(Path::new("disk.vdi"))?;
//! println!("{} bytes of disk", disk.len());
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
// On-disk bytes are hostile. These lints make the usual ways of trusting
// them (unchecked indexing, arithmetic and casts, panicking shortcuts) fail
// the clippy gate. Unit tests and the test fixtures are exempt.
#![warn(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::unwrap_used
)]
#![cfg_attr(
    test,
    allow(
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used
    )
)]

use std::path::Path;
use std::sync::Arc;

use atlas_fs_core::error::{CorruptKind, Corruption, Error, Location, Result};
use atlas_fs_core::io::block::{BlockSource, check_range};
use atlas_fs_core::io::file::FileSource;

const WHAT: &str = "VDI header";
const MAP: &str = "VDI block map";
/// Bytes read for the header: the pre-header and the 1.1 header.
const HEADER_LEN: usize = 72 + 400;
/// Smallest header size accepted: the 1.1 header without the legacy geometry block (qemu-img).
const MIN_HEADER_SIZE: u32 = 384;
/// `0xBEDA107F`.
const SIGNATURE: u32 = 0xBEDA_107F;
/// Block map entry of a block never written.
const FREE: u32 = 0xFFFF_FFFF;
/// Block map entry of a block that reads as zeros.
const ZERO: u32 = 0xFFFF_FFFE;
/// Bytes per sector, and the unit the block size must be a multiple of.
const SECTOR: u64 = 512;
/// Largest block size read.
const MAX_BLOCK: u64 = 256 << 20;
/// Most block map bytes held in memory.
const MAX_MAP_BYTES: u64 = 64 << 20;

fn corrupt(offset: u64, kind: CorruptKind) -> Error {
    Error::Corrupt(Corruption::new(WHAT, Location::Byte(offset), kind))
}

fn le32(header: &[u8], offset: usize) -> Result<u32> {
    offset
        .checked_add(4)
        .and_then(|end| header.get(offset..end))
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| {
            corrupt(
                offset as u64,
                CorruptKind::Truncated {
                    needed: 4,
                    available: 0,
                },
            )
        })
}

fn le64(header: &[u8], offset: usize) -> Result<u64> {
    offset
        .checked_add(8)
        .and_then(|end| header.get(offset..end))
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| {
            corrupt(
                offset as u64,
                CorruptKind::Truncated {
                    needed: 8,
                    available: 0,
                },
            )
        })
}

/// Opens the image at `path` read-only.
pub fn open(path: &Path) -> Result<Arc<dyn BlockSource>> {
    let file: Arc<dyn BlockSource> = Arc::new(FileSource::open(path)?);
    Ok(Arc::new(VdiSource::new(file)?))
}

/// The disk a VDI image presents.
pub struct VdiSource {
    file: Arc<dyn BlockSource>,
    len: u64,
    block_size: u64,
    /// File offset of data block 0.
    data_offset: u64,
    /// The block map as stored: little-endian `u32` entries, one per block
    /// of the disk.
    map: Vec<u8>,
}

impl VdiSource {
    /// Parses the VDI image stored in `file`.
    ///
    /// Fails with [`Error::Corrupt`] when the header or map is damaged and
    /// with [`Error::Unsupported`] for what the module docs list.
    pub fn new(file: Arc<dyn BlockSource>) -> Result<Self> {
        let file_len = file.len();
        if file_len < HEADER_LEN as u64 {
            return Err(corrupt(
                0,
                CorruptKind::Truncated {
                    needed: HEADER_LEN as u64,
                    available: file_len,
                },
            ));
        }
        let mut header = vec![0u8; HEADER_LEN];
        file.read_at(0, &mut header)?;

        let signature = le32(&header, 64)?;
        if signature != SIGNATURE {
            return Err(corrupt(
                64,
                CorruptKind::BadSignature {
                    expected: u64::from(SIGNATURE),
                    found: u64::from(signature),
                },
            ));
        }
        let version = le32(&header, 68)?;
        if version >> 16 != 1 || version & 0xFFFF < 1 {
            return Err(Error::unsupported(format!(
                "VDI version {}.{}",
                version >> 16,
                version & 0xFFFF
            )));
        }
        let header_size = le32(&header, 72)?;
        if header_size < MIN_HEADER_SIZE {
            return Err(corrupt(
                72,
                CorruptKind::InvalidValue {
                    field: "header size",
                    value: u64::from(header_size),
                },
            ));
        }
        match le32(&header, 76)? {
            1 | 2 => {}
            3 | 4 => {
                return Err(Error::unsupported(
                    "differencing VDI images (snapshots with a parent)",
                ));
            }
            other => {
                return Err(corrupt(
                    76,
                    CorruptKind::InvalidValue {
                        field: "image type",
                        value: u64::from(other),
                    },
                ));
            }
        }
        let map_offset = u64::from(le32(&header, 340)?);
        let data_offset = u64::from(le32(&header, 344)?);
        let len = le64(&header, 368)?;
        let block_size = u64::from(le32(&header, 376)?);
        let extra = le32(&header, 380)?;
        let blocks = u64::from(le32(&header, 384)?);

        if block_size == 0 || block_size % SECTOR != 0 {
            return Err(corrupt(
                376,
                CorruptKind::InvalidValue {
                    field: "block size",
                    value: block_size,
                },
            ));
        }
        if block_size > MAX_BLOCK {
            return Err(Error::unsupported(format!(
                "VDI block size {block_size} (over {MAX_BLOCK})"
            )));
        }
        if extra != 0 {
            return Err(Error::unsupported("VDI blocks with extra data"));
        }
        let needed = len.div_ceil(block_size);
        if needed > blocks {
            return Err(corrupt(
                384,
                CorruptKind::OutOfRange {
                    field: "blocks in the disk",
                    value: needed,
                    limit_name: "block count",
                    limit: blocks,
                },
            ));
        }
        // needed <= u32::MAX, so this cannot overflow.
        let map_bytes = needed.checked_mul(4).ok_or_else(|| {
            corrupt(
                384,
                CorruptKind::Overflow {
                    field: "block map size",
                },
            )
        })?;
        let in_file = map_offset
            .checked_add(map_bytes)
            .is_some_and(|end| end <= file_len);
        if !in_file {
            return Err(corrupt(
                340,
                CorruptKind::OutOfRange {
                    field: "block map offset",
                    value: map_offset,
                    limit_name: "file size",
                    limit: file_len,
                },
            ));
        }
        if map_bytes > MAX_MAP_BYTES {
            return Err(Error::unsupported(format!(
                "VDI block map of {map_bytes} bytes (over {MAX_MAP_BYTES})"
            )));
        }
        let map_len = usize::try_from(map_bytes).map_err(|_| {
            corrupt(
                384,
                CorruptKind::Overflow {
                    field: "block map size",
                },
            )
        })?;
        let mut map = vec![0u8; map_len];
        file.read_at(map_offset, &mut map)?;
        for (i, raw) in map.as_chunks::<4>().0.iter().enumerate() {
            let entry = u32::from_le_bytes(*raw);
            if entry == FREE || entry == ZERO {
                continue;
            }
            let start = u64::from(entry)
                .checked_mul(block_size)
                .and_then(|n| n.checked_add(data_offset))
                .ok_or_else(|| {
                    corrupt(
                        map_offset.saturating_add((i as u64).saturating_mul(4)),
                        CorruptKind::Overflow {
                            field: "block offset",
                        },
                    )
                })?;
            if start >= file_len {
                return Err(Error::Corrupt(Corruption::new(
                    MAP,
                    Location::Byte(map_offset.saturating_add((i as u64).saturating_mul(4))),
                    CorruptKind::OutOfRange {
                        field: "block offset",
                        value: start,
                        limit_name: "file size",
                        limit: file_len,
                    },
                )));
            }
        }
        Ok(Self {
            file,
            len,
            block_size,
            data_offset,
            map,
        })
    }

    fn entry(&self, block: u64) -> Option<u32> {
        let at = usize::try_from(block).ok()?.checked_mul(4)?;
        let end = at.checked_add(4)?;
        let raw = self.map.get(at..end)?;
        <[u8; 4]>::try_from(raw).ok().map(u32::from_le_bytes)
    }

    fn read_with(&self, offset: u64, buf: &mut [u8], bulk: bool) -> Result<()> {
        check_range(offset, buf.len(), self.len)?;
        let file_len = self.file.len();
        let oob = |offset: u64, len: usize| Error::OutOfBounds {
            offset,
            len: u64::try_from(len).unwrap_or(u64::MAX),
            size: file_len,
        };
        let mut pos = offset;
        let mut rest = buf;
        // Each pass takes at least one byte: `within < block_size`.
        while !rest.is_empty() {
            let left = rest.len();
            let block = pos
                .checked_div(self.block_size)
                .ok_or_else(|| oob(pos, left))?;
            let within = pos
                .checked_rem(self.block_size)
                .ok_or_else(|| oob(pos, left))?;
            let in_block = self
                .block_size
                .checked_sub(within)
                .ok_or_else(|| oob(pos, left))?;
            let n = usize::try_from(in_block).map_or(left, |in_block| in_block.min(left));
            let (chunk, tail) = rest.split_at_mut_checked(n).ok_or_else(|| oob(pos, left))?;
            let entry = self.entry(block).ok_or_else(|| {
                Error::Corrupt(Corruption::new(
                    MAP,
                    Location::Byte(block.saturating_mul(4)),
                    CorruptKind::OutOfRange {
                        field: "block index",
                        value: block,
                        limit_name: "map entries",
                        limit: (self.map.len() / 4) as u64,
                    },
                ))
            })?;
            if entry == FREE || entry == ZERO {
                chunk.fill(0);
            } else {
                let start = u64::from(entry)
                    .checked_mul(self.block_size)
                    .and_then(|n| n.checked_add(self.data_offset))
                    .and_then(|n| n.checked_add(within))
                    .ok_or_else(|| oob(pos, n))?;
                // A block cut short by the end of the file reads as zeros.
                let avail = usize::try_from(file_len.saturating_sub(start)).map_or(n, |a| a.min(n));
                let (data, zeros) = chunk
                    .split_at_mut_checked(avail)
                    .ok_or_else(|| oob(start, n))?;
                if !data.is_empty() {
                    if bulk {
                        self.file.read_bulk(start, data)?;
                    } else {
                        self.file.read_at(start, data)?;
                    }
                }
                zeros.fill(0);
            }
            pos = pos
                .checked_add(u64::try_from(n).unwrap_or(u64::MAX))
                .ok_or_else(|| oob(pos, n))?;
            rest = tail;
        }
        Ok(())
    }
}

impl BlockSource for VdiSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        512
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.read_with(offset, buf, false)
    }

    fn read_bulk(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.read_with(offset, buf, true)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use atlas_fs_core::io::block::MemSource;

    /// Block size of the test images.
    const BS: usize = 1024;
    const MAP_AT: usize = 512;

    fn pattern(index: u32, offset: usize) -> u8 {
        (index as usize * 29 + offset * 7 + 3) as u8
    }

    fn set32(buf: &mut [u8], at: usize, v: u32) {
        buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// An image of `size` bytes. `map` is the block map; `stored` blocks
    /// are written in order after it, block `i` filled with `pattern(i)`.
    fn build(image_type: u32, size: u64, map: &[u32], stored: u32) -> Vec<u8> {
        let map_len = (map.len() * 4).div_ceil(512) * 512;
        let data_at = MAP_AT + map_len;
        let mut out = vec![0u8; MAP_AT];
        out[..39].copy_from_slice(b"<<< Oracle VM VirtualBox Disk Image >>>");
        out[39] = b'\n';
        set32(&mut out, 64, SIGNATURE);
        set32(&mut out, 68, 0x0001_0001);
        set32(&mut out, 72, 400);
        set32(&mut out, 76, image_type);
        set32(&mut out, 340, MAP_AT as u32);
        set32(&mut out, 344, data_at as u32);
        out[368..376].copy_from_slice(&size.to_le_bytes());
        set32(&mut out, 376, BS as u32);
        set32(&mut out, 384, map.len() as u32);
        set32(&mut out, 388, stored);
        let mut table = vec![0u8; map_len];
        for (i, e) in map.iter().enumerate() {
            table[i * 4..i * 4 + 4].copy_from_slice(&e.to_le_bytes());
        }
        out.extend(table);
        for i in 0..stored {
            out.extend((0..BS).map(|o| pattern(i, o)));
        }
        out
    }

    fn expected(size: usize, map: &[u32]) -> Vec<u8> {
        let mut disk = vec![0u8; size];
        for (pos, byte) in disk.iter_mut().enumerate() {
            let entry = map.get(pos / BS).copied().unwrap_or(FREE);
            if entry != FREE && entry != ZERO {
                *byte = pattern(entry, pos % BS);
            }
        }
        disk
    }

    fn open_bytes(bytes: Vec<u8>) -> Result<VdiSource> {
        VdiSource::new(Arc::new(MemSource::new(bytes)))
    }

    fn read_all(src: &VdiSource) -> Vec<u8> {
        let mut buf = vec![0u8; src.len() as usize];
        src.read_at(0, &mut buf).unwrap();
        buf
    }

    #[test]
    fn dynamic_image_with_holes_and_out_of_order_blocks() {
        // Block 1 free, block 3 zero-marked, blocks stored out of order.
        let map = [2, FREE, 0, ZERO, 1];
        let size = 5 * BS - 40;
        let src = open_bytes(build(1, size as u64, &map, 3)).unwrap();
        assert_eq!(src.len(), size as u64);
        assert_eq!(src.sector_size(), 512);
        let want = expected(size, &map);
        assert_eq!(read_all(&src), want);
        for (offset, len) in [
            (1000, 100),
            (BS - 1, 2),
            (BS, 3 * BS),
            (3 * BS + 5, BS),
            (0, size),
        ] {
            let mut buf = vec![0u8; len];
            src.read_at(offset as u64, &mut buf).unwrap();
            assert_eq!(buf, want[offset..offset + len], "at {offset} len {len}");
            let mut bulk = vec![0u8; len];
            src.read_bulk(offset as u64, &mut bulk).unwrap();
            assert_eq!(bulk, buf);
        }
        assert!(matches!(
            src.read_at(size as u64 - 1, &mut [0u8; 2]),
            Err(Error::OutOfBounds { .. })
        ));
    }

    #[test]
    fn fixed_image_and_cut_short_block() {
        let map = [0, 1, 2];
        let size = 3 * BS;
        let src = open_bytes(build(2, size as u64, &map, 3)).unwrap();
        assert_eq!(read_all(&src), expected(size, &map));
        // The last block loses its final 200 bytes.
        let mut bytes = build(2, size as u64, &map, 3);
        bytes.truncate(bytes.len() - 200);
        let mut want = expected(size, &map);
        for b in &mut want[size - 200..] {
            *b = 0;
        }
        assert_eq!(read_all(&open_bytes(bytes).unwrap()), want);
    }

    #[test]
    fn qemu_img_header_size_384_opens() {
        let mut bytes = build(1, BS as u64, &[0], 1);
        set32(&mut bytes, 72, 384);
        assert!(open_bytes(bytes.clone()).is_ok());
        set32(&mut bytes, 72, 383);
        assert!(open_bytes(bytes).is_err());
    }

    #[test]
    fn differencing_images_are_unsupported() {
        for image_type in [3, 4] {
            match open_bytes(build(image_type, BS as u64, &[0], 1)) {
                Err(Error::Unsupported(text)) => assert!(text.contains("differencing"), "{text}"),
                other => panic!("expected Unsupported, got {:?}", other.err()),
            }
        }
    }

    #[test]
    fn hostile_headers_fail_without_panicking() {
        let good = build(1, 2 * BS as u64, &[0, FREE], 1);
        assert!(open_bytes(good.clone()).is_ok());
        let is_err = |bytes: Vec<u8>| assert!(open_bytes(bytes).is_err());
        let edit = |f: &dyn Fn(&mut [u8])| {
            let mut bytes = good.clone();
            f(&mut bytes);
            bytes
        };
        // Signature, short files, version, type, header size.
        is_err(edit(&|b| set32(b, 64, 0)));
        is_err(Vec::new());
        is_err(vec![0u8; 100]);
        is_err(good[..HEADER_LEN - 1].to_vec());
        is_err(edit(&|b| set32(b, 68, 0x0002_0001)));
        is_err(edit(&|b| set32(b, 68, 0x0001_0000)));
        is_err(edit(&|b| set32(b, 76, 9)));
        is_err(edit(&|b| set32(b, 72, 0)));
        // Block size 0, not a multiple of 512, huge, and extra data.
        for bad in [0u32, 1000, u32::MAX, 1 << 29] {
            is_err(edit(&|b| set32(b, 376, bad)));
        }
        is_err(edit(&|b| set32(b, 380, 16)));
        // Huge claimed size: fewer blocks than the size needs, or a map that
        // cannot fit in the file.
        is_err(edit(&|b| {
            b[368..376].copy_from_slice(&u64::MAX.to_le_bytes())
        }));
        is_err(edit(&|b| {
            b[368..376].copy_from_slice(&(1u64 << 40).to_le_bytes());
            set32(b, 384, u32::MAX);
        }));
        // Map offset past the end, and a block that starts past the end.
        is_err(edit(&|b| set32(b, 340, u32::MAX)));
        is_err(edit(&|b| set32(b, MAP_AT, 7)));
        is_err(edit(&|b| set32(b, MAP_AT, 0xFFFF_FFF0)));
        // Data offset near u32::MAX with a stored block.
        is_err(edit(&|b| set32(b, 344, u32::MAX)));
        // Truncated inside the map.
        is_err(good[..MAP_AT + 4].to_vec());
    }

    #[test]
    fn open_reads_a_file_from_disk() {
        let map = [1, 0];
        let dir = std::env::temp_dir().join(format!("disk-atlas-vdi-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.vdi");
        std::fs::write(&path, build(1, 2 * BS as u64, &map, 2)).unwrap();
        let src = open(&path).unwrap();
        let mut buf = vec![0u8; 2 * BS];
        src.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, expected(2 * BS, &map));
        drop(src);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
