How to compile DVRF:

Note: I've been compiling this in a Fedora Core 11 x86 environment. If you're compiling on a >2.6.29 host then your results may vary. I suggest compiling on a x86 2.6 host.

Step 1: Copy toolchain binary code to / directly but if you don't have root permissions then place the toolkit somewhere and remember the path
   $ cd /home/DVRF
   $ cp DVRF_v02/tools/projects / -a

Step 2: Set the toolchain PATH. (Assume the toolchain is installed in /projects)
   $ export PATH=/projects/hnd/tools/linux/hndtools-mipsel-linux-uclibc-4.2.3/bin:$PATH
 
Step 3: Go to DVRF folder and execute make.sh.
   $ cd /home/DVRF
   $ cd DVRF_v02
   $ ./make.sh

This will generate a binary file called code.bin under release/image/ and the release/Result folder will contain the binary as well as the Makefile log.

-b1ack0wl

