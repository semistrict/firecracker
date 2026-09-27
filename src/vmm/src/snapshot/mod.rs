// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides serialization and deserialization facilities and implements a persistent storage
//! format for Firecracker state snapshots.
//!
//! The `Snapshot` API manages serialization and deserialization of collections of objects
//! that implement the `serde` `Serialize`, `Deserialize` trait. Currently, we use
//! [`bitcode`](https://docs.rs/bitcode/latest/bitcode/) for performing the serialization.
//!
//! The snapshot format uses the following layout:
//!
//!  |-----------------------------|
//!  |       64 bit magic_id       |
//!  |-----------------------------|
//!  |       version string        |
//!  |-----------------------------|
//!  |            State            |
//!  |-----------------------------|
//!  |        optional CRC64       |
//!  |-----------------------------|
//!
//!
//! The snapshot format uses a version value in the form of `MAJOR.MINOR.PATCH`. The version is
//! provided by the library clients (it is not tied to this crate).
pub mod crc;
mod persist;
use std::fmt::Debug;
use std::io::{Read, Write};

use crc64::crc64;
use semver::Version;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::persist::SNAPSHOT_VERSION;
use crate::snapshot::crc::CRC64Writer;
pub use crate::snapshot::persist::Persist;

#[cfg(target_arch = "x86_64")]
const SNAPSHOT_MAGIC_ID: u64 = 0x0710_1984_8664_0000u64;

#[cfg(target_arch = "aarch64")]
const SNAPSHOT_MAGIC_ID: u64 = 0x0710_1984_AAAA_0000u64;

/// Maximum size in bytes for snapshot deserialization to prevent DOS attacks.
/// Snapshots contain VM state which can be large, but we set a reasonable upper bound.
/// This limit is 10MB which should be sufficient for any legitimate snapshot.
const SNAPSHOT_DESERIALIZATION_BYTES_LIMIT: usize = 10_000_000;

/// Error definitions for the Snapshot API.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SnapshotError {
    /// CRC64 validation failed
    Crc64,
    /// Invalid data version: {0}
    InvalidFormatVersion(Version),
    /// Magic value does not match arch: {0}
    InvalidMagic(u64),
    /// An error occurred during bitcode serialization: {0}
    Bitcode(#[from] bitcode::Error),
    /// IO Error: {0}
    Io(#[from] std::io::Error),
    /// Snapshot size exceeds limit of {0} bytes
    SizeLimitExceeded(usize),
}

fn serialize<S: Serialize, W: Write>(data: &S, write: &mut W) -> Result<(), SnapshotError> {
    let encoded = bitcode::serialize(data)?;
    write.write_all(&encoded).map_err(SnapshotError::Io)
}

/// Firecracker snapshot header
#[derive(Debug, Serialize, Deserialize)]
struct SnapshotHdr {
    /// magic value
    magic: u64,
    /// Snapshot data version
    version: Version,
}

/// Reads a whole snapshot file: the serialized snapshot followed by its 8-byte CRC.
fn read_snapshot_file<R: Read>(reader: &mut R) -> Result<Vec<u8>, SnapshotError> {
    // Check size limit before reading the full file to prevent DOS attacks
    let mut buf = Vec::new();
    let bytes_read = reader
        .take((SNAPSHOT_DESERIALIZATION_BYTES_LIMIT + 1) as u64)
        .read_to_end(&mut buf)?;

    if bytes_read > SNAPSHOT_DESERIALIZATION_BYTES_LIMIT {
        return Err(SnapshotError::SizeLimitExceeded(
            SNAPSHOT_DESERIALIZATION_BYTES_LIMIT,
        ));
    }

    // The last 8 bytes are the CRC, so we need to separate them
    if buf.len() < 8 {
        return Err(SnapshotError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "File too short to contain CRC",
        )));
    }
    Ok(buf)
}

/// Decodes a snapshot whose data is in `Data`'s layout from minor version
/// `since` on, and in `Old`'s layout below it, converting the latter.
///
/// bitcode cannot read the header alone, so this decodes in the current
/// layout and falls back to the old one; a decode counts only when the
/// version it finds belongs to that layout. The header is not validated.
fn decode_or_upgrade<Data, Old>(buf: &[u8], since: u64) -> Result<Snapshot<Data>, SnapshotError>
where
    Data: DeserializeOwned,
    Old: DeserializeOwned + Into<Data>,
{
    let current = bitcode::deserialize::<Snapshot<Data>>(buf);
    if matches!(&current, Ok(snapshot) if snapshot.header.version.minor >= since) {
        return Ok(current?);
    }
    match bitcode::deserialize::<Snapshot<Old>>(buf) {
        Ok(old) if old.header.version.minor < since => Ok(Snapshot {
            header: old.header,
            data: old.data.into(),
        }),
        _ => Ok(current?),
    }
}

/// Assumes the raw bytes stream read from the given [`Read`] instance is a snapshot file,
/// and returns the version of it.
pub fn get_format_version<R: Read>(reader: &mut R) -> Result<Version, SnapshotError> {
    let buf = read_snapshot_file(reader)?;
    let (data_buf, _crc_buf) = buf.split_at(buf.len() - 8);

    // Since bitcode requires exact type matching, we need to try deserializing
    // as the specific snapshot types we know about. In practice, all snapshots
    // in Firecracker use MicrovmState as the data type. If deserialization
    // fails, the snapshot is from an older layout this build cannot read
    // (such as bincode), or it is corrupted.
    use crate::persist::{MICROVM_STATE_SINCE_MINOR, MicrovmState, MicrovmStateV14};

    decode_or_upgrade::<MicrovmState, MicrovmStateV14>(data_buf, MICROVM_STATE_SINCE_MINOR)
        .map(|snapshot| snapshot.header.version)
}

/// Firecracker snapshot type
///
/// A type used to store and load Firecracker snapshots of a particular version
#[derive(Debug, Serialize, Deserialize)]
pub struct Snapshot<Data> {
    header: SnapshotHdr,
    /// The data stored int his [`Snapshot`]
    pub data: Data,
}

impl<Data> Snapshot<Data> {
    /// Constructs a new snapshot with the given `data`.
    pub fn new(data: Data) -> Self {
        Self {
            header: SnapshotHdr {
                magic: SNAPSHOT_MAGIC_ID,
                version: SNAPSHOT_VERSION.clone(),
            },
            data,
        }
    }

    /// Gets the version of this snapshot
    pub fn version(&self) -> &Version {
        &self.header.version
    }

    /// Checks the magic value and that this build reads the version.
    fn validate(self) -> Result<Self, SnapshotError> {
        if self.header.magic != SNAPSHOT_MAGIC_ID {
            return Err(SnapshotError::InvalidMagic(self.header.magic));
        }

        if self.header.version.major != SNAPSHOT_VERSION.major
            || self.header.version.minor > SNAPSHOT_VERSION.minor
        {
            return Err(SnapshotError::InvalidFormatVersion(self.header.version));
        }

        Ok(self)
    }
}

/// Checks the size limit to prevent DOS attacks.
fn check_size(buf: &[u8]) -> Result<(), SnapshotError> {
    if buf.len() > SNAPSHOT_DESERIALIZATION_BYTES_LIMIT {
        return Err(SnapshotError::SizeLimitExceeded(
            SNAPSHOT_DESERIALIZATION_BYTES_LIMIT,
        ));
    }
    Ok(())
}

impl<Data: DeserializeOwned> Snapshot<Data> {
    pub(crate) fn load_without_crc_check(buf: &[u8]) -> Result<Self, SnapshotError> {
        check_size(buf)?;
        bitcode::deserialize::<Self>(buf)?.validate()
    }

    /// As [`Self::load_without_crc_check`], for data whose layout changed at
    /// minor version `since`: an older snapshot is read in `Old`'s layout.
    pub(crate) fn load_without_crc_check_or_upgrade<Old>(
        buf: &[u8],
        since: u64,
    ) -> Result<Self, SnapshotError>
    where
        Old: DeserializeOwned + Into<Data>,
    {
        check_size(buf)?;
        decode_or_upgrade::<Data, Old>(buf, since)?.validate()
    }

    /// Loads a snapshot from the given [`Read`] instance, performing all validations
    /// (CRC, snapshot magic value, snapshot version).
    pub fn load<R: Read>(reader: &mut R) -> Result<Self, SnapshotError> {
        Self::load_with(reader, Self::load_without_crc_check)
    }

    /// As [`Self::load`], for data whose layout changed at minor version
    /// `since`: an older snapshot is read in `Old`'s layout and converted.
    pub fn load_or_upgrade<Old, R>(reader: &mut R, since: u64) -> Result<Self, SnapshotError>
    where
        Old: DeserializeOwned + Into<Data>,
        R: Read,
    {
        Self::load_with(reader, |buf| {
            Self::load_without_crc_check_or_upgrade::<Old>(buf, since)
        })
    }

    fn load_with<R: Read>(
        reader: &mut R,
        decode: impl FnOnce(&[u8]) -> Result<Self, SnapshotError>,
    ) -> Result<Self, SnapshotError> {
        let buf = read_snapshot_file(reader)?;
        let (data_buf, _crc_buf) = buf.split_at(buf.len() - 8);
        let snapshot = decode(data_buf)?;

        let computed_checksum = crc64(0, buf.as_slice());
        // When we read the entire file, we also read the checksum into the buffer. The CRC has the
        // property that crc(0, buf.as_slice()) == 0 iff the last 8 bytes of buf are the checksum
        // of all the preceding bytes, and this is the property we are using here.
        if computed_checksum != 0 {
            return Err(SnapshotError::Crc64);
        }
        Ok(snapshot)
    }
}

impl<Data: Serialize> Snapshot<Data> {
    /// Saves `self` to the given [`Write`] instance, computing the CRC of the written data,
    /// and then writing the CRC into the `Write` instance, too.
    pub fn save<W: Write>(&self, writer: &mut W) -> Result<(), SnapshotError> {
        let mut crc_writer = CRC64Writer::new(writer);
        serialize(self, &mut crc_writer)?;
        // Write the CRC as raw bytes, not bitcode-serialized
        crc_writer
            .writer
            .write_all(&crc_writer.checksum().to_le_bytes())
            .map_err(SnapshotError::Io)
    }
}

#[cfg(test)]
impl<Data> Snapshot<Data> {
    /// Gives this snapshot another version, as an older build would write it.
    pub(crate) fn with_version(mut self, version: Version) -> Self {
        self.header.version = version;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::MicrovmState;

    /// A layout that gained a field at minor version 1.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct New {
        a: u32,
        b: Option<Vec<u8>>,
    }

    /// The layout before it.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Old {
        a: u32,
    }

    impl From<Old> for New {
        fn from(old: Old) -> Self {
            New { a: old.a, b: None }
        }
    }

    fn saved<D: Serialize>(data: D, minor: u64) -> Vec<u8> {
        let version = Version::new(SNAPSHOT_VERSION.major, minor, 0);
        let mut buf = Vec::new();
        Snapshot::new(data)
            .with_version(version)
            .save(&mut buf)
            .unwrap();
        buf
    }

    #[test]
    fn test_load_or_upgrade() {
        // The current layout at the version that introduced it.
        let buf = saved(
            New {
                a: 1,
                b: Some(vec![2; 3]),
            },
            1,
        );
        let snapshot = Snapshot::<New>::load_or_upgrade::<Old, _>(&mut buf.as_slice(), 1).unwrap();
        assert_eq!(
            snapshot.version(),
            &Version::new(SNAPSHOT_VERSION.major, 1, 0)
        );
        assert_eq!(
            snapshot.data,
            New {
                a: 1,
                b: Some(vec![2; 3])
            }
        );

        // The old layout at a version before it is converted.
        let buf = saved(Old { a: 4 }, 0);
        let snapshot = Snapshot::<New>::load_or_upgrade::<Old, _>(&mut buf.as_slice(), 1).unwrap();
        assert_eq!(
            snapshot.version(),
            &Version::new(SNAPSHOT_VERSION.major, 0, 0)
        );
        assert_eq!(snapshot.data, New { a: 4, b: None });

        // The old layout cannot be read without the upgrade.
        assert!(matches!(
            Snapshot::<New>::load(&mut buf.as_slice()),
            Err(SnapshotError::Bitcode(_))
        ));

        // The old layout claiming a version of the new one is not read.
        let buf = saved(Old { a: 5 }, 1);
        assert!(matches!(
            Snapshot::<New>::load_or_upgrade::<Old, _>(&mut buf.as_slice(), 1),
            Err(SnapshotError::Bitcode(_))
        ));

        // The upgrade does not widen the versions this build reads.
        let buf = saved(New { a: 6, b: None }, SNAPSHOT_VERSION.minor + 1);
        assert!(matches!(
            Snapshot::<New>::load_or_upgrade::<Old, _>(&mut buf.as_slice(), 1),
            Err(SnapshotError::InvalidFormatVersion(v)) if v.minor == SNAPSHOT_VERSION.minor + 1
        ));

        // Nor does it skip the CRC.
        let mut buf = saved(Old { a: 7 }, 0);
        let last = buf.len() - 1;
        buf[last] ^= 0xff;
        assert!(matches!(
            Snapshot::<New>::load_or_upgrade::<Old, _>(&mut buf.as_slice(), 1),
            Err(SnapshotError::Crc64)
        ));
    }

    #[test]
    fn test_snapshot_restore() {
        let state = MicrovmState::default();
        let mut buf = Vec::new();

        Snapshot::new(state).save(&mut buf).unwrap();
        Snapshot::<MicrovmState>::load(&mut buf.as_slice()).unwrap();
    }

    #[test]
    fn test_parse_version_from_file() {
        use crate::persist::MicrovmState;
        let snapshot = Snapshot::new(MicrovmState::default());

        // Use a Vec<u8> that can grow as needed
        let mut snapshot_data = Vec::new();
        snapshot.save(&mut snapshot_data).unwrap();

        assert_eq!(
            get_format_version(&mut std::io::Cursor::new(&snapshot_data)).unwrap(),
            SNAPSHOT_VERSION
        );
    }

    #[test]
    fn test_bad_reader() {
        #[derive(Debug)]
        struct BadReader;

        impl Read for BadReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::InvalidInput.into())
            }
        }

        let mut reader = BadReader {};

        assert!(
            matches!(Snapshot::<()>::load(&mut reader), Err(SnapshotError::Io(inner)) if inner.kind() == std::io::ErrorKind::InvalidInput)
        );
    }

    #[test]
    fn test_bad_magic() {
        // Create a snapshot with corrupted magic and serialize it properly
        let mut bad_snapshot = Snapshot::new(());
        bad_snapshot.header.magic = 0xDEADBEEF;

        // Serialize the bad snapshot (without CRC for load_without_crc_check)
        let corrupted_data = bitcode::serialize(&bad_snapshot).unwrap();

        assert!(matches!(
            Snapshot::<()>::load_without_crc_check(&corrupted_data),
            Err(SnapshotError::InvalidMagic(_))
        ));
    }

    #[test]
    fn test_bad_crc() {
        let snapshot = Snapshot::new(());

        // Use a Vec<u8> that can grow as needed
        let mut valid_data = Vec::new();
        snapshot.save(&mut valid_data).unwrap();

        // Corrupt the CRC by changing the last 8 bytes (where CRC is stored)
        if valid_data.len() >= 8 {
            for i in (valid_data.len() - 8)..valid_data.len() {
                valid_data[i] ^= 0xFF; // Corrupt the CRC by flipping bits
            }
        }

        assert!(matches!(
            Snapshot::<()>::load(&mut std::io::Cursor::new(&valid_data)),
            Err(SnapshotError::Crc64)
        ));
    }

    #[test]
    fn test_bad_version() {
        // Different major version: shouldn't work
        let mut bad_snapshot = Snapshot::new(());
        bad_snapshot.header.version.major = SNAPSHOT_VERSION.major + 1;
        let data = bitcode::serialize(&bad_snapshot).unwrap();

        assert!(matches!(
            Snapshot::<()>::load_without_crc_check(&data),
            Err(SnapshotError::InvalidFormatVersion(v)) if v.major == SNAPSHOT_VERSION.major + 1
        ));

        //  minor > SNAPSHOT_VERSION.minor: shouldn't work
        let mut bad_snapshot = Snapshot::new(());
        bad_snapshot.header.version.minor = SNAPSHOT_VERSION.minor + 1;
        let data = bitcode::serialize(&bad_snapshot).unwrap();
        assert!(matches!(
            Snapshot::<()>::load_without_crc_check(&data),
            Err(SnapshotError::InvalidFormatVersion(v)) if v.minor == SNAPSHOT_VERSION.minor + 1
        ));

        // But we can support minor versions smaller or equal to ours. We also support
        // all patch versions within our supported major.minor version.
        let snapshot = Snapshot::new(());
        let data = bitcode::serialize(&snapshot).unwrap();
        Snapshot::<()>::load_without_crc_check(&data).unwrap();

        if SNAPSHOT_VERSION.minor != 0 {
            let mut snapshot = Snapshot::new(());
            snapshot.header.version.minor = SNAPSHOT_VERSION.minor - 1;
            let data = bitcode::serialize(&snapshot).unwrap();
            Snapshot::<()>::load_without_crc_check(&data).unwrap();
        }

        let mut snapshot = Snapshot::new(());
        snapshot.header.version.patch = 0;
        let data = bitcode::serialize(&snapshot).unwrap();
        Snapshot::<()>::load_without_crc_check(&data).unwrap();

        let mut snapshot = Snapshot::new(());
        snapshot.header.version.patch = SNAPSHOT_VERSION.patch + 1;
        let data = bitcode::serialize(&snapshot).unwrap();
        Snapshot::<()>::load_without_crc_check(&data).unwrap();

        let mut snapshot = Snapshot::new(());
        snapshot.header.version.patch = 1024;
        let data = bitcode::serialize(&snapshot).unwrap();
        Snapshot::<()>::load_without_crc_check(&data).unwrap();
    }
}
