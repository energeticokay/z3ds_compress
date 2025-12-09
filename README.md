Simple CLI tool to compress 3DS files (.cci, .cia,) for use in Azahar emulator

Note that only CCI files have been tested: confirmed to have good compression ratios, run in Azahar, and have identical checksums after decompressing.  Other file types should be regarded as "experimental" until someone confirms they work properly.

Usage:

The windows build includes a .bat file. Place the executable, dlls, and batch file in the same folder with the .cci or .cia files and run the batch file. Compressed equivalents will be made alongside them.

The linux build is an executable program. Again place it in the folder with your files, but in this case simply run the following command in bash:

find . -name "*.cci" -exec ./z3ds_compressor {} ;
