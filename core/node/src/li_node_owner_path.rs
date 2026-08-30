// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

// Names one closed unsafe or unavailable Unix path without copying its machine value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePrivateUnixPathError {
    UnsafePath,
}

impl fmt::Display for NodePrivateUnixPathError {
    // Presents fixed path-safety language without revealing the configured path.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the private Node Unix path is unsafe")
    }
}

impl std::error::Error for NodePrivateUnixPathError {}

// Retains every opened directory descriptor until one protected path operation completes.
pub struct NodePrivateUnixPathGuard {
    _directories: Vec<File>,
}

impl NodePrivateUnixPathGuard {
    // Opens every parent component without following links and validates its mutation authority.
    pub fn acquire(path: &Path, owner_user_id: u32) -> Result<Self, NodePrivateUnixPathError> {
        guarded_path(path, owner_user_id).map_err(|()| NodePrivateUnixPathError::UnsafePath)
    }
}

// Performs one descriptor-anchored traversal while keeping the public error surface closed.
fn guarded_path(path: &Path, owner_user_id: u32) -> Result<NodePrivateUnixPathGuard, ()> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(());
    }
    let parent = path.parent().ok_or(())?;
    let components = normal_components(parent)?;
    let mut directories = Vec::with_capacity(components.len() + 1);
    directories.push(open_root_directory()?);
    validate_directory(directories.last().ok_or(())?, owner_user_id, false)?;
    for (index, component) in components.iter().enumerate() {
        let directory = open_child_directory(directories.last().ok_or(())?, component)?;
        let is_final = index + 1 == components.len();
        validate_directory(&directory, owner_user_id, is_final)?;
        directories.push(directory);
    }
    if components.is_empty() {
        validate_directory(directories.last().ok_or(())?, owner_user_id, true)?;
    }
    Ok(NodePrivateUnixPathGuard {
        _directories: directories,
    })
}

// Returns only ordinary relative names from one already-absolute parent path.
fn normal_components(path: &Path) -> Result<Vec<&OsStr>, ()> {
    let mut values = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => values.push(value),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => return Err(()),
        }
    }
    Ok(values)
}

// Opens the filesystem root as the immutable start of one descriptor-anchored traversal.
fn open_root_directory() -> Result<File, ()> {
    let root = CString::new("/").map_err(|_| ())?;
    let descriptor = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    file_from_descriptor(descriptor)
}

// Opens one child directory relative to the descriptor already proven for its parent.
fn open_child_directory(parent: &File, name: &OsStr) -> Result<File, ()> {
    let name = CString::new(name.as_bytes()).map_err(|_| ())?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    file_from_descriptor(descriptor)
}

// Transfers one successful native descriptor into automatic close ownership.
fn file_from_descriptor(descriptor: libc::c_int) -> Result<File, ()> {
    if descriptor < 0 {
        return Err(());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

// Requires safe immutable ancestors and one exact owner-only final parent directory.
fn validate_directory(directory: &File, owner_user_id: u32, is_final: bool) -> Result<(), ()> {
    let metadata = directory.metadata().map_err(|_| ())?;
    if !metadata.file_type().is_dir() {
        return Err(());
    }
    let mode = metadata.mode() & 0o7777;
    if is_final {
        if metadata.uid() != owner_user_id || mode & 0o077 != 0 {
            return Err(());
        }
        return Ok(());
    }
    if mode & 0o022 == 0 {
        return Ok(());
    }
    if metadata.uid() == 0 && mode & libc::S_ISVTX as u32 != 0 {
        return Ok(());
    }
    Err(())
}
