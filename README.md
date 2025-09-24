Simple CLI tool to compress 3DS files (.cci, .cia,) for use in Azahar emulator

Usage:

The windows build includes a .bat file. Simply place the executable, dlls, and batch file in the same folder with the .cci or .cia files and run the batch file. Compressed equivalents will be made alongside them.

The linux build is simply an executable program. Again place it in the folder with your files, but in this case simply run the following command in bash:

find . -name "*.cci" -exec ./z3ds_compressor {} ;
