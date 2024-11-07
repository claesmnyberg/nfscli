# nfscli
## ©️ 2023-2024 Claes M Nyberg, cmn@signedness.org

---

<img src="https://github.com/claesmnyberg/nfscli/blob/main/nfscli.gif" width="50%" height="50%"/>

---

## What is this?

This is an almost complete implementation of the NFS v3 protocol as
a stand alone binary with an ftp-alike commandline interface.

The purpose was to create a tool that easily can be moved around
to different systems with minimal impact on the system itself in regards
to configuration files and installed packages, which is crucial
when visiting systems.

The current implementation has mainly been tested towards the
NFS server on OpenBSD 7.4, and the source code has been built
on Ubuntu 22.04.2 LTS and FreeBSD 13.1 (amd64).

## NFS v3 CLI v1.5, by Claes M Nyberg <cmn@signedness.org>, Aug 2023
```
Available commands:
cat .......................... (NFS v3 READ) Read file and write to terminal
create ....................... (NFS v3 CREATE) Create a file inside directory represented by file handle
dump ......................... (Mount v3 DUMP) List file systems mounted by all clients
explore ...................... Explore remote NFS server
exports ...................... (Mount v3 EXPORT) Show the NFS server's export list
get .......................... (NFS v3 READ) Download file
getattr ...................... (NFS v3 GETATTR) Get attributes for file handle
getfh ........................ (Mount v3 MNT + UMNTALL) Get fh for exported directory and unregister this client
getoff ....................... (NFS v3 READ) Download file from offset to local file
getport ...................... (Portmap v2 GETPORT) Query portmap service for port number
gid .......................... Set GID to use in calls
help ......................... Display help for all or specific command
link ......................... (NFS v3 LINK) Link the file represented by fh to a file inside the directory represented by dir-fh
lookup ....................... (NFS v3 LOOKUP) Lookup file handle for filename in directory represented by file handle
ls ........................... Alias for readdirplus
mkdir ........................ (NFS v3 MKDIR) Create a directory inside directory represented by file handle
mknod-blk .................... (NFS v3 MKNOD) Create block device file in directory represented by fh
mknod-chr .................... (NFS v3 MKNOD) Create character device file in directory represented by fh
mnt .......................... (Mount v3 MNT) Get file handle for mount of exported path
put .......................... (NFS v3 CREATE + WRITE) Upload file to directory represented by file handle
putoff ....................... (NFS v3 WRITE) Resume upload from offset in local file to remote file represented by fh
quit ......................... Quit
read ......................... (NFS v3 READ) Read from file
readdir ...................... (NFS v3 READDIR) Read directory contents
readdirplus .................. (NFS v3 READDIRPLUS) Read directory contents
readlink ..................... (NFS v3 READLINK) Read data from symbolic link represented by fh
remove ....................... (NFS v3 REMOVE) Remove a file inside directory represented by file handle
rename ....................... (NFS v3 RENAME) Rename a file in directory represented by src-fh, to dst-name inside directory dst-fh
rmdir ........................ (NFS v3 RMDIR) Remove directory inside directory represented by file handle
setattr ...................... (NFS v3 SETATTR) Set mode on file represented by file handle
settings ..................... Display current settings
symlink ...................... (NFS v3 SYMLINK) Create symbolic link in directory represented by fh
uid .......................... Set UID to use in calls
umntall ...................... (Mount v3 UMNTALL) Removes all of the mount entries for this client at server
verbose ...................... Set level of verboseness
write ........................ (NFS v3 WRITE) Write to file
```
