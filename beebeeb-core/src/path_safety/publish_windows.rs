//! The Windows trusted publisher: [`TrustedDirectory`] and [`PendingPublish`]
//! with the guarantees of the Unix one in `path_safety.rs`, on handles.
//!
//! - The directory is opened once, as a handle (`FILE_FLAG_BACKUP_SEMANTICS`),
//!   without following a reparse point (`FILE_FLAG_OPEN_REPARSE_POINT`). Unless
//!   that handle is a plain directory it is refused: a junction, a symbolic
//!   link or any other reparse point in its place, as `O_NOFOLLOW |
//!   O_DIRECTORY` refuses a symlink on Unix. Ancestors are resolved as usual,
//!   as on Unix.
//! - The temporary sibling is created relative to that handle (`NtCreateFile`
//!   with `RootDirectory`), with `FILE_CREATE`: like `O_EXCL`, an existing
//!   name, a link included, is never opened or followed.
//! - Commit flushes the data, then renames the file through its own handle to
//!   the final name under the directory handle (`NtSetInformationFile`,
//!   `FileRenameInformationEx` with `RootDirectory`), replacing an existing
//!   file as `renameat` does: POSIX semantics first, so a reader holding the
//!   old file open does not block it; the plain class where the volume
//!   refuses that one.
//! - A publication dropped before commit is deleted through its own handle
//!   (`FileDispositionInfoEx`, then the plain class), never by name, so a file
//!   swapped in under the temporary name is never the one deleted.
//!
//! Two differences from Unix, both narrower than a guarantee: Windows has no
//! directory fsync (the data is flushed before the rename, so a crash leaves
//! the old file or the new one, never a torn one), and the temporary file
//! takes the directory's inherited ACL where Unix sets mode 0600 (the cache
//! roots live in the user's own profile).

use super::{MAX_PUBLISH_COMPONENT_BYTES, Rules, check_component};
use rand::{RngCore, rngs::OsRng};
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, RawHandle};
use std::path::Path;
use std::ptr;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_INFORMATION_CLASS, FILE_NON_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION,
    FILE_RENAME_POSIX_SEMANTICS, FILE_RENAME_REPLACE_IF_EXISTS, FILE_SYNCHRONOUS_IO_NONALERT, FileRenameInformation,
    FileRenameInformationEx, NtCreateFile, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    HANDLE, NTSTATUS, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER,
    STATUS_NOT_IMPLEMENTED, STATUS_NOT_SUPPORTED, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO,
    FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
    FileDispositionInfo, FileDispositionInfoEx, SYNCHRONIZE, SetFileInformationByHandle,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

/// An already-open trusted directory. All publication operations are
/// relative to this handle, so renaming or replacing an ancestor cannot
/// redirect the eventual file create.
#[derive(Debug)]
pub struct TrustedDirectory {
    directory: File,
}

impl TrustedDirectory {
    pub fn open(path: &Path) -> io::Result<Self> {
        let directory = OpenOptions::new()
            .access_mode(FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
            // Others may still use, rename or delete the directory, as on Unix;
            // the handle keeps naming the directory that was opened.
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let attributes = directory.metadata()?.file_attributes();
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the directory is a reparse point (a junction or symbolic link); refused",
            ));
        }
        if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(io::Error::new(io::ErrorKind::NotADirectory, "not a directory"));
        }
        Ok(Self { directory })
    }

    /// Create a no-follow sibling temp file. Dropping the pending publication
    /// deletes it through its own handle.
    pub fn begin_publish(&self, name: &str, rules: Rules) -> io::Result<(PendingPublish, File)> {
        check_component(name, rules).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if name.len() > MAX_PUBLISH_COMPONENT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("publish name is longer than {MAX_PUBLISH_COMPONENT_BYTES} bytes"),
            ));
        }
        let mut random = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut random)
            .map_err(|error| io::Error::other(format!("generate temp suffix: {error}")))?;
        let mut suffix = String::with_capacity(32);
        for byte in random {
            suffix.push_str(&format!("{byte:02x}"));
        }
        let temp_name = format!(".bbtmp-{suffix}");
        // Everything that can fail runs before the create or while the
        // pending publication already owns the file, so a failure here never
        // leaves the temp file behind.
        let directory = self.directory.try_clone()?;
        let sync_file = create_in(&directory, &temp_name)?;
        let pending = PendingPublish {
            directory,
            sync_file,
            target_name: name.to_owned(),
            committed: false,
        };
        let file = pending.sync_file.try_clone()?;
        Ok((pending, file))
    }

    pub fn publish_bytes(&self, name: &str, rules: Rules, bytes: &[u8]) -> io::Result<()> {
        use std::io::Write as _;
        let (pending, mut file) = self.begin_publish(name, rules)?;
        file.write_all(bytes)?;
        drop(file);
        pending.commit()
    }
}

#[derive(Debug)]
pub struct PendingPublish {
    directory: File,
    /// The temp file's own handle: flushed, renamed and (uncommitted) deleted
    /// through, so its name is never needed again after the create.
    sync_file: File,
    target_name: String,
    committed: bool,
}

impl PendingPublish {
    /// Flush file data, then atomically replace the final directory entry.
    pub fn commit(mut self) -> io::Result<()> {
        self.sync_file.sync_all()?;
        rename_into(&self.sync_file, &self.directory, &self.target_name)?;
        // The handle names the published file now: drop must never delete
        // through it again.
        self.committed = true;
        Ok(())
    }
}

impl Drop for PendingPublish {
    fn drop(&mut self) {
        if !self.committed {
            let _ = delete_on_close(&self.sync_file);
        }
    }
}

/// Create `name` (one component, already checked) under `directory`'s handle:
/// never an existing entry, never through a reparse point.
fn create_in(directory: &File, name: &str) -> io::Result<File> {
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    let length = u16::try_from(wide.len() * size_of::<u16>())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "temp name too long"))?;
    let object_name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: wide.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: directory.as_raw_handle() as HANDLE,
        ObjectName: &object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut handle: HANDLE = ptr::null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: every pointer refers to a live local for the duration of the
    // call (`wide` outlives `object_name`, which outlives `attributes`), and
    // `RootDirectory` is the open directory handle `directory` borrows.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES,
            &attributes,
            &mut status_block,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            // No sharing: nothing else opens the plaintext before it is published.
            0,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            ptr::null(),
            0,
        )
    };
    nt_result(status)?;
    // SAFETY: NtCreateFile succeeded, so `handle` is a new, synchronous file
    // handle that nothing else owns.
    Ok(unsafe { File::from_raw_handle(handle as RawHandle) })
}

/// Rename the file behind `file` to `target` under `directory`'s handle,
/// replacing an existing file.
fn rename_into(file: &File, directory: &File, target: &str) -> io::Result<()> {
    let wide: Vec<u16> = target.encode_utf16().collect();
    let name_bytes = wide.len() * size_of::<u16>();
    let length = size_of::<FILE_RENAME_INFORMATION>() + name_bytes;
    // u64 storage: aligned for FILE_RENAME_INFORMATION, which holds a HANDLE.
    let mut buffer = vec![0u64; length.div_ceil(size_of::<u64>())];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: `buffer` is zeroed, 8-aligned and at least `length` bytes; the
    // name lands at `FileName`'s offset and ends inside the buffer.
    unsafe {
        (*info).RootDirectory = directory.as_raw_handle() as HANDLE;
        (*info).FileNameLength = name_bytes as u32;
        let name = info
            .cast::<u8>()
            .add(offset_of!(FILE_RENAME_INFORMATION, FileName))
            .cast::<u16>();
        ptr::copy_nonoverlapping(wide.as_ptr(), name, wide.len());
    }
    let set = move |class: FILE_INFORMATION_CLASS| -> NTSTATUS {
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: `info` points to a complete FILE_RENAME_INFORMATION of
        // `length` bytes in `buffer`, which outlives the call; `file` is open
        // with DELETE access.
        unsafe {
            NtSetInformationFile(
                file.as_raw_handle() as HANDLE,
                &mut status_block,
                info.cast_const().cast(),
                length as u32,
                class,
            )
        }
    };
    // SAFETY: `info` points into `buffer`, as above.
    unsafe { (*info).Anonymous.Flags = FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS };
    let status = set(FileRenameInformationEx);
    if !matches!(
        status,
        STATUS_INVALID_INFO_CLASS | STATUS_INVALID_PARAMETER | STATUS_NOT_SUPPORTED | STATUS_NOT_IMPLEMENTED
    ) {
        return nt_result(status);
    }
    // An older Windows or a volume without POSIX rename: the plain class.
    // SAFETY: `info` points into `buffer`, as above.
    unsafe {
        (*info).Anonymous.Flags = 0;
        (*info).Anonymous.ReplaceIfExists = true;
    }
    nt_result(set(FileRenameInformation))
}

/// Delete the file behind `file` (open with DELETE access) through the
/// handle: at once with POSIX semantics, otherwise when its last handle closes.
fn delete_on_close(file: &File) -> io::Result<()> {
    let handle = file.as_raw_handle() as HANDLE;
    let ex = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: `ex` is a FILE_DISPOSITION_INFO_EX and its size is passed;
    // `handle` is open for the call.
    let done = unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfoEx,
            (&raw const ex).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if done != 0 {
        return Ok(());
    }
    let plain = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: as above, with FILE_DISPOSITION_INFO.
    let done = unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            (&raw const plain).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if done != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn nt_result(status: NTSTATUS) -> io::Result<()> {
    if status >= 0 {
        return Ok(());
    }
    // SAFETY: a table lookup with no pointer arguments.
    let code = unsafe { RtlNtStatusToDosError(status) };
    Err(io::Error::from_raw_os_error(code as i32))
}

#[cfg(test)]
#[path = "publish_windows_tests.rs"]
mod tests;
