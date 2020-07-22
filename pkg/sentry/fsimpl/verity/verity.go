// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package verity provides a filesystem implementation that is a wrapper of
// another file system. This file system accesses the underlying file system to
// access files, but provide an additional step to verify the read content
// through Merkle trees.
package verity

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	fslock "gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Name is the default filesystem name.
const Name = "verity"

// FilesystemType implements vfs.FilesystemType.
type FilesystemType struct{}

// filesystem implements vfs.FilesystemImpl.
type filesystem struct {
	vfsfs vfs.Filesystem

	// creds is a copy of the filesystem's creator's credentials, which are
	// used for accesses to the underlying file system. creds is immutable.
	creds *auth.Credentials

	// allowRuntimeEnable allows using ioctl with FS_IOC_ENABLE_VERITY to
	// build merkle trees in the verity file system. If this is false, the
	// merkle trees were already built, and this file system only verifies
	// the contents read in the file system, and disallow enabling new
	// files.
	allowRuntimeEnable bool

	// lowerMount is the underlying file system mount.
	lowerMount *vfs.Mount

	// rootDentry is the mount root Dentry for this file system, which
	// stores the root hash of the whole file system in bytes.
	rootDentry *dentry
}

// InternalFilesystemOptions may be passed as
// vfs.GetFilesystemOptions.InternalData to FilesystemType.GetFilesystem.
type InternalFilesystemOptions struct {
	// VerityName is the name of the verity root merkle tree file.
	VerityName string
	// LowerName is the name for the lower layer file system wrapped in
	// verity file system.
	LowerName string
	// RootHash is the root hash of the overall verity file system.
	RootHash []byte
	// AllowRuntimeEnable specifies whether the verity file system allows
	// building merkle tree and enabling verity for files during runtime.
	AllowRuntimeEnable bool
	// LowerGetFSOptions is the file system option for the lower layer file
	// system wrapped by verity file system.
	LowerGetFSOptions vfs.GetFilesystemOptions
}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fstype FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	//TODO(b/159261227): Implement GetFilesystem.
	return nil, nil, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release() {
	fs.lowerMount.DecRef()
}

// dentry implements vfs.DentryImpl.
type dentry struct {
	vfsd vfs.Dentry

	refs int64

	// fs is the owning filesystem. fs is immutable.
	fs *filesystem

	// mode, uid and gid are the file mode, owner, and group of the file in
	// the underlying file system.
	mode uint32
	uid  uint32
	gid  uint32

	// parent is the dentry corresponding to this dentry's parent directory.
	// name is this dentry's name in parent. If this dentry is a filesystem
	// root, parent is nil and name is the empty string. parent and name are
	// protected by fs.renameMu.
	parent *dentry
	name   string

	// If this dentry represents a directory, children maps the names of
	// children for which dentries have been instantiated to those dentries,
	// and dirents (if not nil) is a cache of dirents as returned by
	// directoryFDs representing this directory. children is protected by
	// dirMu.
	dirMu    sync.Mutex
	children map[string]*dentry

	// lowerVD is the VirtualDentry in the underlying file system.
	lowerVD vfs.VirtualDentry

	// lowerMerkleVD is the VirtualDentry of the corresponding merkle tree
	// in the underlying file system.
	lowerMerkleVD vfs.VirtualDentry

	// rootHash is the rootHash for the current directory.
	rootHash []byte
}

// newDentry creates a new dentry representing the given verity file.
func (fs *filesystem) newDentry() *dentry {
	d := &dentry{
		fs: fs,
	}
	d.vfsd.Init(d)
	return d
}

// IncRef implements vfs.DentryImpl.IncRef.
func (d *dentry) IncRef() {
	atomic.AddInt64(&d.refs, 1)
}

// TryIncRef implements vfs.DentryImpl.TryIncRef.
func (d *dentry) TryIncRef() bool {
	for {
		refs := atomic.LoadInt64(&d.refs)
		if refs <= 0 {
			return false
		}
		if atomic.CompareAndSwapInt64(&d.refs, refs, refs+1) {
			return true
		}
	}
}

// DecRef implements vfs.DentryImpl.DecRef.
func (d *dentry) DecRef() {
	if refs := atomic.AddInt64(&d.refs, -1); refs == 0 {
		d.checkDropLocked()
	} else if refs < 0 {
		panic("overlay.dentry.DecRef() called without holding a reference")
	}
}

// checkDropLocked should be called after d's reference count becomes 0 or it
// becomes deleted.
func (d *dentry) checkDropLocked() {
	// Dentries with a positive reference count must be retained. Dentries
	// with a negative reference count have already been destroyed.
	if atomic.LoadInt64(&d.refs) != 0 {
		return
	}
	// Refs is still zero; destroy it.
	d.destroyLocked()
	return
}

// destroyLocked destroys the dentry.
//
// Preconditions: d.refs == 0.
func (d *dentry) destroyLocked() {
	switch atomic.LoadInt64(&d.refs) {
	case 0:
		// Mark the dentry destroyed.
		atomic.StoreInt64(&d.refs, -1)
	case -1:
		panic("verity.dentry.destroyLocked() called on already destroyed dentry")
	default:
		panic("verity.dentry.destroyLocked() called with references on the dentry")
	}

	if d.lowerVD.Ok() {
		d.lowerVD.DecRef()
	}

	if d.lowerMerkleVD.Ok() {
		d.lowerMerkleVD.DecRef()
	}

	if d.parent != nil {
		d.parent.dirMu.Lock()
		if !d.vfsd.IsDead() {
			delete(d.parent.children, d.name)
		}
		d.parent.dirMu.Unlock()
		if refs := atomic.AddInt64(&d.parent.refs, -1); refs == 0 {
			d.parent.checkDropLocked()
		} else if refs < 0 {
			panic("verity.dentry.DecRef() called without holding a reference")
		}
	}
}

// InotifyWithParent implements vfs.DentryImpl.InotifyWithParent.
func (d *dentry) InotifyWithParent(events, cookie uint32, et vfs.EventType) {
	//TODO(b/159261227): Implement InotifyWithParent.
}

// Watches implements vfs.DentryImpl.Watches.
func (d *dentry) Watches() *vfs.Watches {
	//TODO(b/159261227): Implement Watches.
	return nil
}

// OnZeroWatches implements vfs.DentryImpl.OnZeroWatches.
func (d *dentry) OnZeroWatches() {
	//TODO(b/159261227): Implement OnZeroWatches.
}

func (d *dentry) isSymlink() bool {
	return atomic.LoadUint32(&d.mode)&linux.S_IFMT == linux.S_IFLNK
}

func (d *dentry) isDir() bool {
	return atomic.LoadUint32(&d.mode)&linux.S_IFMT == linux.S_IFDIR
}

func (d *dentry) checkPermissions(creds *auth.Credentials, ats vfs.AccessTypes) error {
	return vfs.GenericCheckPermissions(creds, ats, linux.FileMode(atomic.LoadUint32(&d.mode)), auth.KUID(atomic.LoadUint32(&d.uid)), auth.KGID(atomic.LoadUint32(&d.gid)))
}

func (d *dentry) readlink(ctx context.Context) (string, error) {
	return d.fs.vfsfs.VirtualFilesystem().ReadlinkAt(ctx, d.fs.creds, &vfs.PathOperation{
		Root:  d.lowerVD,
		Start: d.lowerVD,
	})
}

// FileDescription implements vfs.FileDescriptionImpl for verity fds.
// FileDescription is a wrapper of the underlying lowerFD, with support to build
// Merkle trees through fs-verity APIs and verity read content.
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD

	// d is the corresponding dentry to the fileDescription.
	d *dentry

	// isDir specifies whehter the fileDescription points to a directory.
	isDir bool

	// lowerFD is the FileDescription in the underlying file system.
	lowerFD *vfs.FileDescription

	// merkleReader is the read-only FileDescription of the corresponding
	// merkle tree file in the underlying file system.
	merkleReader *vfs.FileDescription

	// merkleWriter is the FileDescription of the corresponding merkle tree
	// file in the underlying file system for write. This should only be
	// used when allowRuntimeEnable is set to true.
	merkleWriter *vfs.FileDescription

	// parentMerkleWriter is the FileDescription of the merkle tree for the
	// directory that contains the current file/directory. This is only used
	// if enableForcing to update the directory when a sub tree is
	// generated.
	parentMerkleWriter *vfs.FileDescription

	// verityMu protects merkleReader, merkleWriter and parentMerkleWriter
	// to ensure they are in sync when allowRuntimeEnable is set.
	verityMu sync.Mutex
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *fileDescription) Release() {
	fd.lowerFD.DecRef()
	fd.merkleReader.DecRef()
	if fd.merkleWriter != nil {
		fd.merkleWriter.DecRef()
	}
	if fd.parentMerkleWriter != nil {
		fd.parentMerkleWriter.DecRef()
	}
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *fileDescription) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	stat, err := fd.lowerFD.Stat(ctx, opts)
	if err != nil {
		return linux.Statx{}, err
	}
	return stat, nil
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	// verity files are read-only.
	return syserror.EPERM
}

// LockPOSIX implements vfs.FileDescriptionImpl.LockPOSIX.
func (fd *fileDescription) LockPOSIX(ctx context.Context, uid fslock.UniqueID, t fslock.LockType, start, length uint64, whence int16, block fslock.Blocker) error {
	return fd.Locks().LockPOSIX(ctx, &fd.vfsfd, uid, t, start, length, whence, block)
}

// UnlockPOSIX implements vfs.FileDescriptionImpl.UnlockPOSIX.
func (fd *fileDescription) UnlockPOSIX(ctx context.Context, uid fslock.UniqueID, start, length uint64, whence int16) error {
	return fd.Locks().UnlockPOSIX(ctx, &fd.vfsfd, uid, start, length, whence)
}
