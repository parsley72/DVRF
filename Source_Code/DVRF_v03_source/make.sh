#!/bin/bash
# To prevent changes from not being copied over to the binary
if [ -d ./release/src/router/mipsel-uclibc/ ]; 
then
	cd release/src/router
	rm -rf ./mipsel-uclibc/
        cd ../../../
fi

# To prevent symbol file from getting huge
if [ -f ./release/src/router/lib/.symbols ]; 
then
	rm ./release/src/router/lib/.symbols
fi

# Remove depends files so user can rename build directory
if [ -f ./release/src/router/rp-l2tp/.depend ]; 
then
	rm ./release/src/router/rp-l2tp/.depend
fi

if [ -f ./release/src/router/nvram/.nvram_convert.depend ]; 
then
	rm ./release/src/router/nvram/.nvram_convert.depend
fi

if [ -f ./release/src/router/nvram/.nvram_linux.depend ]; 
then
	rm ./release/src/router/nvram/.nvram_linux.depend
fi

rm -rf Result
source ./toolchain.sh
mkdir Result  
# ./compile.sh | tee Result/DVRF_makefile_output.txt
