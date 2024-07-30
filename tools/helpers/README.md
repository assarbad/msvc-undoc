# Just some little helper scripts here

* `get-help-output.ps1`: is meant to retrieve the help output from the usual MSVC toolchain tools across a directory hierarchy
* `normalize-buildlogs.py`: is meant to aid in normalizing the output file created with `LOG_BUILD_COMMANDLINES` for easier comparison
  * it currently will parse the output from `cl.exe` and `link.exe` (includes `lib.exe`) only
  * the file paths in the output are compared and sorted case-insensitively but they are not currently processed in any way (e.g. normalized, resolved)
  * for the individual tools the respective items are grouped, options are _not_ getting sorted (this leaves a minor edge case where the order of `.lib` or `.obj` files influences which symbol "wins"; but this is simply a limitation acceptable to me)
* `symdl.cmd`: can be used to fetch the debug symbols for the PE files in the current directory
* `symdl_global.cmd`: can be used to fetch the debug symbols for the PE files beneath the current directory
