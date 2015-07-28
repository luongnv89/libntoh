This is a fork from project: [https://github.com/sch3m4/libntoh](https://github.com/sch3m4/libntoh) with some modifications and updates.

# Modifications and Updates:

* Fix issues [Never finding stream](https://github.com/sch3m4/libntoh/issues/11)
* Default building libntoh as a **static library** - not **dynamic library**
* Simplify compilation and installisation.
* Add more examples and comments
* Not using **pkg-config** any more
* Add **libpcap-dev, python-dev** to list of dependency
* Fix dependency package name. **libpthread-dev** should be **libpth-dev**

#Introduction

**Q: What is libntoh?**

A: Libntoh aims to be an user-friendly library to provide a easy way to perform defragmentation and reassembly of network/transport/(more?) protocols.

**Q: Why libntoh?**

A: It's true there are some libraries which aims to do the same things (like libnids), but libntoh is intended to provide a flexible, thread-safe and highly configurable environment for the final user. And most of all, libntoh is released under Modified BSD License to avoid many license issues.

**Q: Which protocols does libntoh support?**

A: Currently libntoh performs IPv4 defragmentation and TCP reassembly

#Mailing List

There is a mailing list for libntoh development issues: libntoh-dev@safetybits.net

#Getting the source

```sh
$ git clone https://github.com/luongnv89/libntoh.git
```

#Dependencies


To successfully compile libntoh you only need gcc, make, cmake, python-dev and libpth-dev.

Debian-like OS:

```sh
$ sudo apt-get install -y cmake gcc make build-essential python-dev swig libpth-dev libpcap
```
If you want to generate the source code documentation, you will also need doxygen:

```sh
$ sudo apt-get install doxygen
```

You need CMake to compile libntoh and ntohexample.

#Compilation instructions

```sh
$ cd libntoh/src
../src$ mkdir build
../src$ cd build
../src/build$ cmake ..
```	

On the other hand you can change the installation prefix by defining CMAKE_INSTALL_PREFIX:

```sh
$ cmake ../ -DCMAKE_INSTALL_PREFIX=/usr
```

So the new installation prefix will be "/usr"

For more information, refer to the wiki page.

#Python Wrapper

Once you have installed libntoh, you can use the python wrapper to comunicate with the library as follows:

```sh
~$ python
Python 2.7.3 (default, Mar 14 2014, 11:57:14) 
[GCC 4.7.2] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from libntoh import ntoh_version
>>> print ntoh_version()
0.4a
>>> quit()
~$
```
A more complete example will be added soon.
	

#"ntohexample" Compilation instructions - _This is different with sch3m4/libntoh_

```sh
../libntoh$ cd example
../libntoh/example$ gcc -o example example.c -lntoh -lpthread -lpcap
```

#"ntohexample" Output:

```sh
$ sudo ./example

###########################
#     libntoh Example     #
# ----------------------- #
# Written by Chema Garcia #
# Modified and updated by Luong Nguyen #
# ----------------------- #
#  http://safetybits.net  #
#   chema@safetybits.net  #
#   sch3m4@brutalsec.net  #
#   luongnv89@gmail.com   # 
###########################

[i] libntoh version: 0.4a

[+] Usage: ./example <options>

+ Options:
	-i | --iface <val> -----> Interface to read packets from
	-f | --file <val> ------> File path to read packets from
	-F | --filter <val> ----> Capture filter (must contain "tcp" or "ip")
	-c | --client ----------> Receive client data only
	-s | --server ----------> Receive server data only
```

Capture live streaming

```sh
$ sudo ./example -i eth0 -F "tcp and host 10.0.0.1 and port 22"

###########################
#     libntoh Example     #
# ----------------------- #
# Written by Chema Garcia #
# Modified and updated by Luong Nguyen #
# ----------------------- #
#  http://safetybits.net  #
#   chema@safetybits.net  #
#   sch3m4@brutalsec.net  #
#   luongnv89@gmail.com   # 
###########################

[i] libntoh version: 0.4a

[i] Source: eth0 / Ethernet
[i] Filter: tcp and host 10.0.0.1 and port 22
[i] Receive data from client: Yes
[i] Receive data from server: Yes
[i] Max. TCP streams allowed: 1024
[i] Max. IPv4 flows allowed: 1024

.... 

[+] Capture finished!
$
```

More information in [wiki page](https://github.com/luongnv89/libntoh/wiki)
