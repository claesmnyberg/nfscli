# nfscli
## ©️ 2023-2026 Claes M Nyberg <cmn@signedness.org>
## ©️ 2025-2026 John Cartwright <johnc@grok.org.uk>

---
<img src="nfscli.gif" width="100%" height="100%"/>

---

## What is this?

This is an almost complete implementation of the NFS v2/v3 protocols as
a stand alone binary with an ftp-alike commandline interface.
See the ReadMe.txt inside the src directory for more information.

This tool was developed as part of the research presented at 44Con 2024
and you can watch the full video here: 
https://www.youtube.com/watch?v=NuxCUMIH5M8

If you find this useful, you probably want to check out brutefh as well:
https://github.com/claesmnyberg/brutefh

The purpose was to create a tool that easily can be moved around
to different systems with minimal impact on the system itself in regards
to configuration files and installed packages, which is crucial
when visiting systems for example in a red-team operation.

Apart from the NFS specific implementations, it also support spoofing
your src IPv4, to simplify access to those exports limited to certain hosts.

This implementation allow for regular file transfers in both directions,
as well as hexdump/patch at certain offset in given files, which makes
it a complete attack tool. The curious user should look into the mknod
command, and perhaps explore creating device files on different OS's,
with different NFS configurations. Maybe kmem could be useful?

The source code has been built on Ubuntu 22.04.2 LTS and FreeBSD 13.1 (amd64).

```
Available commands:
!<command> ................... Execute (local) shell command
access ....................... (NFS v3 ACCESS) Check access permissions
browse ....................... Browse remote filesystem
cache ........................ Control directory cache
cat .......................... (NFS READ) Read file and write to terminal
commit ....................... (NFS v3 COMMIT) Commit cached writes to stable storage
create ....................... (NFS CREATE) Create regular file in directory
df ........................... (NFS STATFS/FSSTAT) Get filesystem statistics
dump ......................... (Mount DUMP) List file systems mounted by all clients
explore ...................... Explore remote NFS server
exports ...................... (Mount EXPORT) Show the NFS server's export list
fsinfo ....................... (NFS v3 FSINFO) Get filesystem information
get .......................... (NFS READ) Download file
getattr ...................... (NFS GETATTR) Get attributes for file or directory
getfh ........................ (Mount MNT + UMNTALL) Get fh for exported directory and unregister this client
getoff ....................... (NFS READ) Download file from offset to local file
getport ...................... (Portmap v2 GETPORT/v3 GETADDR) Query portmap service for port number
gid .......................... Show or set GID to use in calls
help ......................... Show command help
link ......................... (NFS LINK) Create hard link to file
lookup ....................... (NFS LOOKUP) Lookup name in directory
ls ........................... List directory contents (alias for readdirplus)
mkdir ........................ (NFS MKDIR) Create directory
mknod ........................ (NFS v3 MKNOD) Create device or special file
mnt .......................... (Mount MNT) Get file handle for mount of exported path
pathconf ..................... (NFS v3 PATHCONF) Get POSIX path configuration
ping ......................... (RPC NULL) Test connectivity to RPC service
protocol ..................... Display or set protocol version
put .......................... (NFS CREATE + WRITE) Upload file to directory represented by file handle
putoff ....................... (NFS WRITE) Resume file upload from offset
quit ......................... Quit
read ......................... (NFS READ) Read from file
readdir ...................... (NFS READDIR) Read directory contents
readdirplus .................. (NFS v3 READDIRPLUS) Read directory contents
readlink ..................... (NFS READLINK) Read target of symbolic link
remove ....................... (NFS REMOVE) Remove file from directory
rename ....................... (NFS RENAME) Rename file or directory from src-dirfh/src-name to dst-dirfh/dst-name
rmdir ........................ (NFS RMDIR) Remove directory
rpcinfo ...................... (Portmap DUMP) List registered RPC services
setattr ...................... (NFS SETATTR) Set attributes for file or directory
settings ..................... Display current settings
symlink ...................... (NFS SYMLINK) Create symbolic link
uid .......................... Show or set UID to use in calls
umnt ......................... (Mount UMNT) Unmount a specific export path
umntall ...................... (Mount UMNTALL) Removes all of the mount entries for this client at server
verbose ...................... Show or set verbosity level
write ........................ (NFS WRITE) Write to file
```
