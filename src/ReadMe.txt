Copyright Claes M. Nyberg <cmn@signedness.org>, 2023-2026
Copyright John Cartwright <johnc@grok.org.uk>, 2025-2026

-=[ What is this?
This is an almost complete implementation of the NFS v2/v3 protocols
as a stand alone binary with an ftp-alike commandline interface.

The purpose was to create a tool that easily can be moved around
to different systems with minimal impact on the system itself in
regards to configuration files and installed packages, which is
crucial when visiting systems.

The current implementation has mainly been tested towards the
NFS server on OpenBSD 7.4, and the source code has been built
on Ubuntu 22.04.2 LTS and FreeBSD 13.1 (amd64).

-=[ Limitations
Currently, only UDP is supported.  Buffer sizes have been fixed in an 
attempt to keep data in single UDP packets with an MTU of 1500.

-=[ TODO
	- Add download directory for explore command to store shadow file 
	  and SSH keys

-=[ Changelog
1.8
	--( Architecture
	Added lightweight path resolution layer (pathctx) for path-based
	operations throughout the codebase.

	--( Performance
	Caching subsystem with O(1) hash-based directory lookups,
	attribute cache with configurable TTL, and file handle cache
	for name resolution.

	--( Network
	Overhauled portmap code for better version detection and to handle
	buggy portmappers that return ports for unregistered versions.

	--( IP Spoofing
	Major performance improvement for raw socket mode (-S/--spoof-ip).
	Spoofed RPC calls now execute at near-native UDP speed.
	Added BPF kernel filtering and gratuitous ARP on startup.

	--( CLI
	Tab completion for file handles (queries cached entries).
	Tab completion for NFS paths and filenames.
	Tab completion for help topics, now greatly expanded.

	--( Command: access
	New command (NFS v3 ACCESS) for checking file/directory permissions.

	--( Command: browse
	New interactive filesystem browser with path-based navigation.
	Eliminates the need to work with file handles for common operations.
	Auto-uid mode reads passwd/group files to automatically switch
	credentials for reading files owned by non-root users.

	--( Command: cache
	New cache control command added.

	--( Command: df
	New command for filesystem statistics (STATFS v2, FSSTAT v3).

	--( Command: fsinfo
	New command for filesystem information (NFS v3 FSINFO).

	--( Command: mknod
	Consolidated mknod-blk and mknod-chr into unified mknod command.
	Now supports chr, blk, fifo, and sock types.

	--( Command: pathconf
	New command for POSIX path configuration (NFS v3 PATHCONF).

	--( Command: protocol
	Renamed 'version' command for clarity and reworked output.

	--( Build
	Added no-readline build targets (make norl, make norl-static) for
	minimal-dependency deployments where readline is unavailable.

1.7
	--( Architecture
	Refactored codebase into modular components.

	--( Performance
	Multiple performance enhancements across the codebase.

	--( Network
	Various fixes/improvements to the IP spoofing code.
	Added send timeout to match receive timeout.

	--( Bugfix
	Fixed XID displayed in wrong byte order in RPC error messages.

	--( Bugfix
	Fixed resource leaks.

	--( Bugfix
	Fixed signed/unsigned comparison warnings throughout codebase.

	--( Security
	Added bounds checking to mount and portmap response parsing.
	Added payload length underflow protection.

	--( Command: lookup/getattr
	Added -l flag for long format output showing ATIME/CTIME/FSID/FID.

1.6
	--( NFS v2 support
	Added mount v1 / NFS 2 support and 'version' command.
	Implemented synthetic READDIRPLUS using discrete NFS v2 calls.
	Implemented the RPC portmapper 'dump' procedure.

	--( Bugfix:
	Memory leak in explore command.

	--( Bugfix:
	Uninitialised variable usage in explore command.

	--( Bugfix:
	NFS read commands (cat/get/getoff) now show correct size.

	--( Bugfix:
	Fixed incorrect error message in 'getoff' command.

	--( Bugfix:
	Better handling of mount commands when 'getport' hasn't been used.
	Consistent behaviour across exports/dump/getfh/mnt/umntall.

	--( Command: create/mkdir/mknod/put/setattr/symlink
	These now take an octal mode argument, which is more intuitive.

	--( Command: rpcinfo
	New command to dump portmapper output for debugging and analysis.

	--( CLI
	Tab-completion of commands added.
	Improved help text for several commands.
	Implemented handy shell escape.

1.5
	--( Command line option: --arp-spoof removed
	A thread sedning ARP reply packets are now started automatically
	when --spoof-ip is used.

1.4
	--( Output
	The explore command now display the shadow file at the end,
	since it is more demo friendly

	--( Bugfix: Crash in cmd_write because of typo ...
	Accidently used the wrong struct when zero:ed out memory

	--( Command line option: -a
	Added ARP spoof thread to use together with the spoofed 
	source IP (-S). It runs in a separate thread and send
	ARP reply every second to fool the NFS server that the 
	spoofed IP is at the interface given at command line.

	--( Command: removed remote OpeBSD DoS PoC
	Moved this command to a stand alone PoC instead.

	--( Bugfix:
	Changed type from unsigned to signed for response from
	str_hex2bin which returns -1 on error.
	Changed return value of str_hex2bin to zero on error.

1.3
	--( Command line option: -t
	Added timeout in seconds for receive on UDP socket and
	raw socket when spoofing. Combined with -e (described below)
	this simplify "scripting".

	The read timeout is already set to 3 seconds when spoofing, 
	this option also gives an opportunity to change that value.

	--( CLI
	The CLI now accepts a string of semicolon separated commands
	as input, which makes "scripting" easier.
	Example, you can easily traverse a list of IP addresses
	and run the explore command against each one of them:
	./516-nfscli 192.168.56.109 -e "explore;quit"

	--( Command line option: -e
	Changed option -e to execute command(s) given as argument

	--( Bugfix
	Fixed bug in the str_to_argv() function that caused first 
	string to be an empty string in some situations.

	--( Output
	Added server IP to logged output after date.

1.2
	--( Bugfix
	The length of the file handle was set to an unsigned 32 bit
	integer instead of signed at some locations. This sometimes 
	caused a crash when str_hex2bin() returned an error.
	This has been fixed by using int as the type for file handle 
	length.

	--( Command line option: -e
	Added command line option -e for running command explore
	when starting

	--( Command: explore
	Added explore command that attempt to list top directory 
	for each share that has a known file handle. IF the
	root filesystem is found, attempts are made to list and/or display
	/root, /etc and access passwd,shadow, id_rsa, .history, etc.

	--( Design
	Rewrote most of the NFS v3 commands to return results in a 
	buffer rather than printing to terminal. This simplify 
	programmatic control when implementing new commands.

	Added functions nfsv3_readdirplus_init() and nfsv3_readdirplus_next()
	for reading a directory entry by entry using readdirectory plus.

	--( Command: getattr
	Added getattr command to retrieve attributes based on file handle

	--( Command: getoff
	Added getoff to download a file from a given offset

	--( Command: create
	Create command now print the file handle for the created file

	--( Command: putoff
	Added putoff command that can be used to resume upload
	from a certain offset in a local file to a file represented
	by a file handle.

	--( Spoof
	Added support for spoofing source IP using a raw socket.
	Responses are limited to a single UDP packet. Typically
	this is used to get a handle for a mount point only 
	available for certain clients. 
	Since nobody seem to check if a filehandle is used by
	a specific client, it can then be used with a regular UDP socket
	from any ip in most (all at this point) cases.

1.1 
	--( Command: mknod-chr
	Added mknod-chr command for creating character device files

	--( Command: mknod-blk
	Added mknod-blk command for creating block device files

	--( Output
	Added number of links to readdirplus output
	
	--( Output
	Now printing '<everyone>' to export list for shares to
	everyone instead of empty string.

	--( Output
	Sometimes file/directory names does not have attributes or a handle, 
	so now print readdirplus output with everything set to zero
	for those files, instead of just ignoring them.

	--( Bugfix
	Fixed alignment bug in mount.c:mount_dump() where unaligned
	output was not printed

	--( Command: cat
	Added cat command that print a file to the terminal

	--( Command: ls
	Added ls command as alias for readdirplus

	--( Command: getfh
	Added getfh command (MNT + UMNTALL)

	--( Output
	Added -c flag to readdirplus for coloring of
	file names using ansi escape sequences

1.0 - First release

-=[ Build environment Setup
Ubuntu 22.04:
	apt-get install libreadline-dev

FreeBSD 13.1:
	pkg install readline

-=[ Compile
run 'make' or 'make static'

-=[ Author
Copyright 2023-2026, Claes M. Nyberg <cmn@signedness.org>
Copyright 2025-2026, John Cartwright <johnc@grok.org.uk>
