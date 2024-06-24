# uasset-data-parser

Tired of digging through files with a hex editor?  Sick of manually converting 
floating point numbers to binary?  Getting lost trying to find the property 
you want to edit inside a giant map or array?  uasset-data-parser might be the
solution you're looking for!

This tool converts io-store formatted .uasset files to and from a yaml-like
text format for easy editing.  Simply run this tool to "decode" a uasset file,
make your edits in a regular text editor, then run this tool again to "encode"
back to the .uasset format.

## Commands

If you're ready to try this tool out, there are three basic commands you'll
want to know about:

1. `uasset-data-parser test <file>`
   This command is useful to verify that the tool will work with the file you
   want to edit.  It decodes the file into text, reencodes that text back into
   binary, and verifies the end result matches the input byte-for-byte.

2. `uasset-data-parser decode <file> (result)`
   This command will decode the .uasset binary file into an easily readable
   text format.  So much easier to understand than raw binary, let me tell you.
   The `result` parameter is optional and can be used to set the output path.

3. `uasset-data-parser encode <file> (result)`
   This command will reencode a previously decoded binary file.  Again, the
   `result` parameter is optional.


## Disclaimer

This tool was made and tested exclusively with UE4.27 files (P3R to be
specific).  There are no guarantees that it will work with everything - it
was built primarily to make editing that game's files easier.
