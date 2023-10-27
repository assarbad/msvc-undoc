# The linker: `link.exe`

## Command Line Switches for `link.exe`

NB: the following list has not yet been checked and mostly contains findings from looking at `link.exe` in raw form. Some of the arguments to individual command line switches certainly require more research and confirmation.

Also note: not all findings will apply to older or newer versions of the toolchain.

The undocumented or barely mentioned switches are in bold, [the documented ones][1] are not.

| Command line switch                        | Purpose                                            |
|--------------------------------------------|----------------------------------------------------|
| [`/align`](https://learn.microsoft.com/cpp/build/reference/align-section-alignment) | Specifies the alignment of each section. |
| **`/allowbadrvaforfirstsection`** |  |
| [`/allowbind`](https://learn.microsoft.com/cpp/build/reference/allowbind-prevent-dll-binding) | Specifies that a DLL can't be bound. |
| **`/allowimagesizeover2gb`** |  |
| [`/allowisolation`](https://learn.microsoft.com/cpp/build/reference/allowisolation-manifest-lookup) | Specifies behavior for manifest lookup. |
| **`/allpdata`** |  |
| **[`/alternatename`](https://devblogs.microsoft.com/oldnewthing/20200731-00/?p=104024)** | By specifying `/alternatename:X=Y` you can tell the linker to use `Y` when searching for symbol `Y` |
| [`/appcontainer`](https://learn.microsoft.com/cpp/build/reference/appcontainer-windows-store-app) | Specifies whether the app must run within an appcontainer process environment. |
| **`/arm64hazardexist`** |  |
| **`/arm64hazardfree`** |  |
| **`/arm64xaggressiverwdatafold`** |  |
| **`/arm64xcrossresolve`** |  |
| **`/arm64xemulatorbuild`** |  |
| **`/arm64xfastforward`** |  |
| **`/arm64xfoldrwdata`** |  |
| **`/arm64xhack`** |  |
| **`/arm64xnewchameleonlibfmt`** |  |
| **`/arm64xnomergeimports`** |  |
| **`/arm64xnoreorderobjs`** |  |
| **`/arm64xsameaddress`** |  |
| **`/arm64xuselegacyffs`** |  |
| **`/armhazardexist`** |  |
| **`/armhazardfree`** |  |
| [`/assemblydebug`](https://learn.microsoft.com/cpp/build/reference/assemblydebug-add-debuggableattribute) | Adds the [System.Diagnostics.DebuggableAttribute](https://learn.microsoft.com/search/?terms=System.Diagnostics.DebuggableAttribute&category=Documentation) to a managed image. |
| [`/assemblylinkresource`](https://learn.microsoft.com/cpp/build/reference/assemblylinkresource-link-to-dotnet-framework-resource) | Creates a link to a managed resource. |
| [`/assemblymodule`](https://learn.microsoft.com/cpp/build/reference/assemblymodule-add-a-msil-module-to-the-assembly) | Specifies that a Microsoft intermediate language (MSIL) module should be imported into the assembly. |
| **`/assemblymodulemap`** |  |
| [`/assemblyresource`](https://learn.microsoft.com/cpp/build/reference/assemblyresource-embed-a-managed-resource) | Embeds a managed resource file in an assembly. |
| **[`/b2`](https://www.geoffchappell.com/studies/msvc/link/link/options/b2.htm)** |  |
| [`/base`](https://learn.microsoft.com/cpp/build/reference/base-base-address) | Sets a base address for the program. |
| **`/baserelocclustering`** |  |
| **[`/brepro`](https://www.geoffchappell.com/studies/msvc/link/link/options/brepro.htm)** |  |
| [`/cetcompat`](https://learn.microsoft.com/cpp/build/reference/cetcompat) | Marks the binary as CET Shadow Stack compatible. |
| **`/cetcompatstrict`** |  |
| **`/cetdynamicapisinproc`** |  |
| **`/cetipvalidationrelaxed`** |  |
| [`/cgthreads`](https://learn.microsoft.com/cpp/build/reference/cgthreads-compiler-threads) | Sets number of cl.exe threads to use for optimization and code generation when link-time code generation is specified. |
| [`/clrimagetype`](https://learn.microsoft.com/cpp/build/reference/clrimagetype-specify-type-of-clr-image) | Sets the type (IJW, pure, or safe) of a CLR image. |
| **`/clrloaderoptimization`** |  |
| **`/clrnetcore`** |  |
| **`/clrrvaentry`** |  |
| **`/clrsignhash`** |  |
| [`/clrsupportlasterror`](https://learn.microsoft.com/cpp/build/reference/clrsupportlasterror-preserve-last-error-code-for-pinvoke-calls) | Preserves the last error code of functions that are called through the P/Invoke mechanism. |
| **`/clrsupportlasterrordll`** |  |
| [`/clrthreadattribute`](https://learn.microsoft.com/cpp/build/reference/clrthreadattribute-set-clr-thread-attribute) | Specifies the threading attribute to apply to the entry point of your CLR program. |
| [`/clrunmanagedcodecheck`](https://learn.microsoft.com/cpp/build/reference/clrunmanagedcodecheck-add-suppressunmanagedcodesecurityattribute) | Specifies whether the linker will apply the `SuppressUnmanagedCodeSecurity` attribute to linker-generated P/Invoke stubs that call from managed code into native DLLs. |
| **`/coffsecttopdbstrm`** |  |
| **`/crashondiag`** |  |
| **`/cvtres`** |  |
| **`/cxxmodulestrongownership`** |  |
| **[`/d2`](https://www.geoffchappell.com/studies/msvc/link/link/options/d2.htm)** |  |
| **[`/db`](gc.msvc://link/index.htm)** |  |
| [`/debug`](https://learn.microsoft.com/cpp/build/reference/debug-generate-debug-info) | Creates debugging information. |
| [`/debugtype`](https://learn.microsoft.com/cpp/build/reference/debugtype-debug-info-options) | Specifies which data to include in debugging information. |
| [`/def`](https://learn.microsoft.com/cpp/build/reference/def-specify-module-definition-file) | Passes a module-definition (.def) file to the linker. |
| **`/defarm64native`** |  |
| [`/defaultlib`](https://learn.microsoft.com/cpp/build/reference/defaultlib-specify-default-library) | Searches the specified library when external references are resolved. |
| [`/delay`](https://learn.microsoft.com/cpp/build/reference/delay-delay-load-import-settings) | Controls the delayed loading of DLLs. |
| [`/delayload`](https://learn.microsoft.com/cpp/build/reference/delayload-delay-load-import) | Causes the delayed loading of the specified DLL. |
| [`/delaysign`](https://learn.microsoft.com/cpp/build/reference/delaysign-partially-sign-an-assembly) | Partially signs an assembly. |
| [`/dependentloadflag`](https://learn.microsoft.com/cpp/build/reference/dependentloadflag) | Sets default flags on dependent DLL loads. |
| **`/didatownsection`** |  |
| **[`/disallowlib`](https://www.geoffchappell.com/studies/msvc/link/link/options/disallowlib.htm)** |  |
| **`/discardtrack`** |  |
| [`/dll`](https://learn.microsoft.com/cpp/build/reference/dll-build-a-dll) | Builds a DLL. |
| **`/dllrename`** |  |
| [`/driver`](https://learn.microsoft.com/cpp/build/reference/driver-windows-nt-kernel-mode-driver) | Creates a kernel mode driver. |
| [`/dynamicbase`](https://learn.microsoft.com/cpp/build/reference/dynamicbase-use-address-space-layout-randomization) | Specifies whether to generate an executable image that's rebased at load time by using the address space layout randomization (ASLR) feature. |
| **`/dynamicvalue`** |  |
| **[`/editandcontinue`](https://devblogs.microsoft.com/cppblog/c-edit-and-continue-in-visual-studio-2015-update-3/)** |  |
| **`/emitasx64image`** |  |
| **`/emitasx64imagewithaa64`** |  |
| **`/emitpogophaseinfo`** |  |
| **`/emittoolversioninfo`** |  |
| **`/emitvolatilemetadata`** |  |
| **`/enclave`** |  |
| **[`/encpadsize`](https://www.geoffchappell.com/studies/msvc/link/link/options/encpadsize.htm)** |  |
| [`/entry`](https://learn.microsoft.com/cpp/build/reference/entry-entry-point-symbol) | Sets the starting address. |
| [`/errorreport`](https://learn.microsoft.com/cpp/build/reference/errorreport-report-internal-linker-errors) | Deprecated. Error reporting is controlled by [Windows Error Reporting (WER)](https://learn.microsoft.com/windows/win32/wer/windows-error-reporting) settings. |
| **`/etm`** |  |
| **`/expectedoutputsize`** |  |
| **`/experimental`** |  |
| [`/export`](https://learn.microsoft.com/cpp/build/reference/export-exports-a-function) | Exports a function. |
| **`/exportarm64native`** |  |
| **`/exportpadmin`** |  |
| **`/fastfail`** |  |
| [`/fastgenprofile`](https://learn.microsoft.com/cpp/build/reference/genprofile-fastgenprofile-generate-profiling-instrumented-build) | Both of these options specify generation of a *`.pgd`* file by the linker to support profile-guided optimization (PGO). /GENPROFILE and /FASTGENPROFILE use different default parameters. |
| **[`/fe`](https://www.geoffchappell.com/studies/msvc/link/link/options/fe.htm)** |  |
| [`/filealign`](https://learn.microsoft.com/cpp/build/reference/filealign) | Aligns sections within the output file on multiples of a specified value. |
| [`/fixed`](https://learn.microsoft.com/cpp/build/reference/fixed-fixed-base-address) | Creates a program that can be loaded only at its preferred base address. |
| [`/force`](https://learn.microsoft.com/cpp/build/reference/force-force-file-output) | Forces a link to complete even with unresolved symbols or symbols defined more than once. |
| **`/forcewinmdversion12`** |  |
| **[`/fullbuild`](https://www.geoffchappell.com/studies/msvc/link/link/options/fullbuild.htm)** |  |
| **`/funcoverride`** |  |
| **`/funcoverridedisablefunc`** |  |
| **`/funcoverrideemitcand`** |  |
| **`/funcoverrideoncallsites`** |  |
| [`/functionpadmin`](https://learn.microsoft.com/cpp/build/reference/functionpadmin-create-hotpatchable-image) | Creates an image that can be hot patched. |
| **`/genpdbfromscratch`** |  |
| [`/genprofile`](https://learn.microsoft.com/cpp/build/reference/genprofile-fastgenprofile-generate-profiling-instrumented-build) | Both of these options specify generation of a *`.pgd`* file by the linker to support profile-guided optimization (PGO). /GENPROFILE and /FASTGENPROFILE use different default parameters. |
| [`/guard`](https://learn.microsoft.com/cpp/build/reference/guard-enable-guard-checks) | Enables Control Flow Guard protection. |
| **`/guardsym`** |  |
| [`/heap`](https://learn.microsoft.com/cpp/build/reference/heap-set-heap-size) | Sets the size of the heap, in bytes. |
| [`/highentropyva`](https://learn.microsoft.com/cpp/build/reference/highentropyva-support-64-bit-aslr) | Specifies support for high-entropy 64-bit address space layout randomization (ASLR). |
| **`/hotpatchcompatible`** |  |
| **`/hybriddefupgrade`** |  |
| **`/hybridexportthunks`** |  |
| **`/hybriduseguestmachine`** |  |
| **`/icfsection`** |  |
| [`/idlout`](https://learn.microsoft.com/cpp/build/reference/idlout-name-midl-output-files) | Specifies the name of the *`.idl`* file and other MIDL output files. |
| [`/ignore`](https://learn.microsoft.com/cpp/build/reference/ignore-ignore-specific-warnings) | Suppresses output of specified linker warnings. |
| [`/ignoreidl`](https://learn.microsoft.com/cpp/build/reference/ignoreidl-don-t-process-attributes-into-midl) | Prevents the processing of attribute information into an *`.idl`* file. |
| [`/ilk`](https://learn.microsoft.com/cpp/build/reference/ilk-name-incremental-database-file) | Overrides the default incremental database file name. |
| **`/iltcgwarningoff`** |  |
| [`/implib`](https://learn.microsoft.com/cpp/build/reference/implib-name-import-library) | Overrides the default import library name. |
| **`/impthunkalign`** |  |
| [`/include`](https://learn.microsoft.com/cpp/build/reference/include-force-symbol-references) | Forces symbol references. |
| **`/includecoffsection`** |  |
| [`/incremental`](https://learn.microsoft.com/cpp/build/reference/incremental-link-incrementally) | Controls incremental linking. |
| [`/inferasanlibs`](https://learn.microsoft.com/cpp/build/reference/inferasanlibs) | Uses inferred sanitizer libraries. |
| [`/integritycheck`](https://learn.microsoft.com/cpp/build/reference/integritycheck-require-signature-check) | Specifies that the module requires a signature check at load time. |
| **`/kernel`** |  |
| [`/keycontainer`](https://learn.microsoft.com/cpp/build/reference/keycontainer-specify-a-key-container-to-sign-an-assembly) | Specifies a key container to sign an assembly. |
| [`/keyfile`](https://learn.microsoft.com/cpp/build/reference/keyfile-specify-key-or-key-pair-to-sign-an-assembly) | Specifies a key or key pair to sign an assembly. |
| [`/largeaddressaware`](https://learn.microsoft.com/cpp/build/reference/largeaddressaware-handle-large-addresses) | Tells the compiler that the application supports addresses larger than 2 gigabytes |
| **[`/last`](https://www.geoffchappell.com/studies/msvc/link/link/options/last.htm)** |  |
| **`/layoutpagesize`** |  |
| [`/libpath`](https://learn.microsoft.com/cpp/build/reference/libpath-additional-libpath) | Specifies a path to search before the environmental library path. |
| [`/linkrepro`](https://learn.microsoft.com/cpp/build/reference/linkrepro) | Specifies a path to generate link repro artifacts in. |
| [`/linkreprotarget`](https://learn.microsoft.com/cpp/build/reference/linkreprotarget) | Generates a link repro only when producing the specified target.<sup>16.1</sup> |
| **`/logo`** |  |
| [`/ltcg`](https://learn.microsoft.com/cpp/build/reference/ltcg-link-time-code-generation) | Specifies link-time code generation. |
| **`/ltcgasmlist`** |  |
| **`/ltcgout`** |  |
| [`/machine`](https://learn.microsoft.com/cpp/build/reference/machine-specify-target-platform) | Specifies the target platform. |
| [`/manifest`](https://learn.microsoft.com/cpp/build/reference/manifest-create-side-by-side-assembly-manifest) | Creates a side-by-side manifest file and optionally embeds it in the binary. |
| [`/manifestdependency`](https://learn.microsoft.com/cpp/build/reference/manifestdependency-specify-manifest-dependencies) | Specifies a \<dependentAssembly> section in the manifest file. |
| [`/manifestfile`](https://learn.microsoft.com/cpp/build/reference/manifestfile-name-manifest-file) | Changes the default name of the manifest file. |
| [`/manifestinput`](https://learn.microsoft.com/cpp/build/reference/manifestinput-specify-manifest-input) | Specifies a manifest input file for the linker to process and embed in the binary. You can use this option multiple times to specify more than one manifest input file. |
| [`/manifestuac`](https://learn.microsoft.com/cpp/build/reference/manifestuac-embeds-uac-information-in-manifest) | Specifies whether User Account Control (UAC) information is embedded in the program manifest. |
| [`/map`](https://learn.microsoft.com/cpp/build/reference/map-generate-mapfile) | Creates a mapfile. |
| [`/mapinfo`](https://learn.microsoft.com/cpp/build/reference/mapinfo-include-information-in-mapfile) | Includes the specified information in the mapfile. |
| **`/maxilksize`** |  |
| [`/merge`](https://learn.microsoft.com/cpp/build/reference/merge-combine-sections) | Combines sections. |
| [`/midl`](https://learn.microsoft.com/cpp/build/reference/midl-specify-midl-command-line-options) | Specifies MIDL command-line options. |
| **`/midlexe`** |  |
| **`/minpdbpathlen`** |  |
| **`/mt`** |  |
| [`/natvis`](https://learn.microsoft.com/cpp/build/reference/natvis-add-natvis-to-pdb) | Adds debugger visualizers from a Natvis file to the program database (PDB). |
| [`/noassembly`](https://learn.microsoft.com/cpp/build/reference/noassembly-create-a-msil-module) | Suppresses the creation of a .NET Framework assembly. |
| **`/nocoffgrpinfo`** |  |
| **`/nocomentry`** |  |
| **[`/nod`](https://www.geoffchappell.com/studies/msvc/link/link/options/nod.htm)** |  |
| **`/nodbgdirmerge`** |  |
| [`/nodefaultlib`](https://learn.microsoft.com/cpp/build/reference/nodefaultlib-ignore-libraries) | Ignores all (or the specified) default libraries when external references are resolved. |
| [`/noentry`](https://learn.microsoft.com/cpp/build/reference/noentry-no-entry-point) | Creates a resource-only DLL. |
| **`/noexp`** |  |
| **`/nofunctionpadsection`** |  |
| **`/noilinkcoffgrppad`** |  |
| **`/noimplib`** |  |
| **`/nolinkrepro`** |  |
| [`/nologo`](https://learn.microsoft.com/cpp/build/reference/nologo-suppress-startup-banner-linker) | Suppresses the startup banner. |
| **`/noltcgoptref`** |  |
| **`/nomap`** |  |
| **`/noonfailrepro`** |  |
| **`/nooptcfg`** |  |
| **`/nooptdidat`** |  |
| **`/nooptgids`** |  |
| **[`/nooptidata`](https://www.geoffchappell.com/studies/msvc/link/link/options/nooptidata.htm)** |  |
| **`/nooptrefbeforeltcg`** |  |
| **`/noopttls`** |  |
| **`/novcfeature`** |  |
| **`/noxdatamerge`** |  |
| [`/nxcompat`](https://learn.microsoft.com/cpp/build/reference/nxcompat-compatible-with-data-execution-prevention) | Marks an executable as verified to be compatible with the Windows Data Execution Prevention feature. |
| **`/objmap`** |  |
| **`/odr`** |  |
| **`/odrignore`** |  |
| **`/odrignoresamesize`** |  |
| **`/onfailrepro`** |  |
| [`/opt`](https://learn.microsoft.com/cpp/build/reference/opt-optimizations) | Controls LINK optimizations. |
| **`/opticfbytecomp`** |  |
| [`/order`](https://learn.microsoft.com/cpp/build/reference/order-put-functions-in-order) | Places COMDATs into the image in a predetermined order. |
| **[`/osversion`](https://www.geoffchappell.com/studies/msvc/link/link/options/osversion.htm)** |  |
| [`/out`](https://learn.microsoft.com/cpp/build/reference/out-output-file-name) | Specifies the output file name. |
| **`/pagesize`** |  |
| **`/pathmap`** |  |
| **[`/pchmap`](https://www.geoffchappell.com/studies/msvc/link/link/options/pchmap.htm)** |  |
| [`/pdb`](https://learn.microsoft.com/cpp/build/reference/pdb-use-program-database) | Creates a PDB file. |
| [`/pdbaltpath`](https://learn.microsoft.com/cpp/build/reference/pdbaltpath-use-alternate-pdb-path) | Uses an alternate location to save a PDB file. |
| **[`/pdbcompress`](https://www.geoffchappell.com/studies/msvc/link/link/options/pdbcompress.htm)** |  |
| **`/pdbdbgqsize`** |  |
| **`/pdbdbgst`** |  |
| **`/pdbdll`** |  |
| **`/pdbmap`** |  |
| **`/pdbmodclosethreads`** |  |
| **`/pdbpagesize`** |  |
| **[`/pdbpath`](https://www.geoffchappell.com/studies/msvc/link/link/options/pdbpath.htm)** |  |
| **`/pdbrpc`** |  |
| [`/pdbstripped`](https://learn.microsoft.com/cpp/build/reference/pdbstripped-strip-private-symbols) | Creates a PDB file that has no private symbols. |
| **`/pdbthreads`** |  |
| **`/pdbtmcache`** |  |
| [`/pgd`](https://learn.microsoft.com/cpp/build/reference/pgd-specify-database-for-profile-guided-optimizations) | Specifies a *`.pgd`* file for profile-guided optimizations. |
| **`/pogonoshare`** |  |
| [`/pogosafemode`](https://learn.microsoft.com/cpp/build/reference/pogosafemode-linker-option) | **Obsolete** Creates a thread-safe PGO instrumented build. |
| **`/prefetch`** |  |
| [`/profile`](https://learn.microsoft.com/cpp/build/reference/profile-performance-tools-profiler) | Produces an output file that can be used with the Performance Tools profiler. |
| **`/rc`** |  |
| **[`/re`](https://www.geoffchappell.com/studies/msvc/link/link/options/re.htm)** |  |
| [`/release`](https://learn.microsoft.com/cpp/build/reference/release-set-the-checksum) | Sets the Checksum in the *`.exe`* header. |
| **`/reportnoncomdatguardfunc`** |  |
| **`/retryonfileopenfailure`** |  |
| **`/runbelow4gb`** |  |
| [`/safeseh`](https://learn.microsoft.com/cpp/build/reference/safeseh-image-has-safe-exception-handlers) | Specifies that the image will contain a table of safe exception handlers. |
| **`/savebaserelocations`** |  |
| [`/section`](https://learn.microsoft.com/cpp/build/reference/section-specify-section-attributes) | Overrides the attributes of a section. |
| **`/sectionlayout`** |  |
| **`/simarm`** |  |
| **`/simarm64`** |  |
| **`/skipincrementalchecks`** |  |
| [`/sourcelink`](https://learn.microsoft.com/cpp/build/reference/sourcelink) | Specifies a SourceLink file to add to the PDB. |
| **[`/sourcemap`](https://www.geoffchappell.com/studies/msvc/link/link/options/sourcemap.htm)** |  |
| **`/spdembed`** |  |
| **`/spdidstr`** |  |
| **`/spdin`** |  |
| **`/spdindex`** |  |
| **`/spgo`** |  |
| [`/stack`](https://learn.microsoft.com/cpp/build/reference/stack-stack-allocations) | Sets the size of the stack in bytes. |
| **`/stricticfthunkalign`** |  |
| **`/striprtti`** |  |
| [`/stub`](https://learn.microsoft.com/cpp/build/reference/stub-ms-dos-stub-file-name) | Attaches an MS-DOS stub program to a Win32 program. |
| [`/subsystem`](https://learn.microsoft.com/cpp/build/reference/subsystem-specify-subsystem) | Tells the operating system how to run the *`.exe`* file. |
| **`/subsystemversion`** |  |
| [`/swaprun`](https://learn.microsoft.com/cpp/build/reference/swaprun-load-linker-output-to-swap-file) | Tells the operating system to copy the linker output to a swap file before it's run. |
| **[`/test`](https://www.geoffchappell.com/studies/msvc/link/link/options/test.htm)** |  |
| **`/throwingnew`** |  |
| [`/time`](https://learn.microsoft.com/cpp/build/reference/time-linker-time-information) | Output linker pass timing information. |
| **`/time+`** |  |
| [`/tlbid`](https://learn.microsoft.com/cpp/build/reference/tlbid-specify-resource-id-for-typelib) | Specifies the resource ID of the linker-generated type library. |
| [`/tlbout`](https://learn.microsoft.com/cpp/build/reference/tlbout-name-dot-tlb-file) | Specifies the name of the *`.tlb`* file and other MIDL output files. |
| **`/trimfile`** |  |
| [`/tsaware`](https://learn.microsoft.com/cpp/build/reference/tsaware-create-terminal-server-aware-application) | Creates an application that is designed specifically to run under Terminal Server. |
| [`/useprofile`](https://learn.microsoft.com/cpp/build/reference/useprofile) | Uses profile-guided optimization training data to create an optimized image. |
| [`/verbose`](https://learn.microsoft.com/cpp/build/reference/verbose-print-progress-messages) | Prints linker progress messages. |
| [`/version`](https://learn.microsoft.com/cpp/build/reference/version-version-information) | Assigns a version number. |
| **`/vulcannotrecognizenewdelaythunk`** |  |
| **`/warnduplicatesections`** |  |
| **`/wbrdcfg`** |  |
| **`/wbrddll`** |  |
| **`/wbrdlog`** |  |
| **`/wbrdreporterrors`** |  |
| **`/wbrdschema`** |  |
| **`/wbrdsummary`** |  |
| **`/wbrdtestencrypt`** |  |
| **`/weakorder`** |  |
| [`/wholearchive`](https://learn.microsoft.com/cpp/build/reference/wholearchive-include-all-library-object-files) | Includes every object file from specified static libraries. |
| **`/win32version`** |  |
| [`/winmd`](https://learn.microsoft.com/cpp/build/reference/winmd-generate-windows-metadata) | Enables generation of a Windows Runtime Metadata file. |
| [`/winmddelaysign`](https://learn.microsoft.com/cpp/build/reference/winmddelaysign-partially-sign-a-winmd) | Partially signs a Windows Runtime Metadata (*`.winmd`*) file by placing the public key in the winmd file. |
| [`/winmdfile`](https://learn.microsoft.com/cpp/build/reference/winmdfile-specify-winmd-file) | Specifies the file name for the Windows Runtime Metadata (winmd) output file that's generated by the [`/winmd`](https:/learn.microsoft.com/cpp/build/reference/winmd-generate-windows-metadata) linker option. |
| [`/winmdkeycontainer`](https://learn.microsoft.com/cpp/build/reference/winmdkeycontainer-specify-key-container) | Specifies a key container to sign a Windows Metadata file. |
| [`/winmdkeyfile`](https://learn.microsoft.com/cpp/build/reference/winmdkeyfile-specify-winmd-key-file) | Specifies a key or key pair to sign a Windows Runtime Metadata file. |
| **`/winmdmap`** |  |
| **`/winmdsignhash`** |  |
| **`/winmdversion`** |  |
| **`/wowa64`** |  |
| **`/wowa64lib`** |  |
| [`/wx`](https://learn.microsoft.com/cpp/build/reference/wx-treat-linker-warnings-as-errors) | Treats linker warnings as errors. |
| **`/x86pdata`** |  |
| **[`/xoff`](https://www.geoffchappell.com/studies/msvc/link/link/options/xoff.htm)** |  |
| **`@`** | Specify a command (or response) file with one command line option per line |

## Environment variables for `link.exe`

| Environment variable               | Description                                        |
|------------------------------------|----------------------------------------------------|
| `_CVTCIL_`                         |                                                    |
| `_LIB_`                            |                                                    |
| `_LINK_`                           | used after the command line (and `LINK`)           |
| `_PRELIB_`                         |                                                    |
| `_PUSHTHUNKOBJ_`                   |                                                    |
| `EnterpriseWDK`                    |                                                    |
| `LOG_BUILD_COMMANDLINES`           | file name to log command lines into                |
| `LINK`                             | used before command line                           |
| `LINK_DB`                          | .ilk file name?                                    |
| `LINK_REPRO`                       | directory for link repro? can be used instead of `/linkrepro`|
| `LINK_REPRO_NAME`                  |                                                    |
| `SPGO_SPD_IDSTR`                   |                                                    |
| `MSVCETW_PARENT_CONTEXT_THREAD_ID` |                                                    |
| `PRINT_HRESULT_ON_FAIL`            | `1` (or even non-empty?)                           |
| `VSLANG`                           | the LANGID (e.g. 1033/0x409 for US-English)        |
| `VS_UNICODE_OUTPUT`                | file number (integer, such as for stdout, stderr), used by Visual Studio IDE, used to detect running in the IDE|
| `VSTEL_SolutionSessionID`          | some GUID; adhoc generated?                        |
| `VSTEL_CurrentSolutionBuildID`     | an (unsigned?) integer (PID/TID?)                  |
| `VSTEL_ProjectID`                  | a GUID; does it correspond to project GUID?        |

Used (and populated) internally for `/pdbaltpath`:

* `_EXT`
* `_PDB`

## Glossary (guessed)

* ICF: identical COMDAT folding
* POGO: Profile Guided Optimization
* WarBird (also wrbrd/wbrd) ... some sort of [obfuscation technology][2] (also [here][3], [here][4] and [here][5])

## Subjects of the study

These are subject to change, eventually.
- `link.exe` (14.34.31933)
  - SHA256: `38f375b084e796c6be3ae724641136897770fbc4858e578724f7956c41c48fce`
  - Host/Target: `x86-64` / `x86-64`
  - Version:
    - File: 14.34.31937.0
    - Product: 14.34.31937.0
- `link.exe` (14.36.32532)
  - SHA256: `3b0e8472ab78036f3cdaf67b392aee631228ce1dc6131e486d0041f6191c6a9e`
  - Host/Target: `x86-64` / `x86-64`
  - Version:
    - File: 14.36.32534.0
    - Product: 14.36.32534.0


[1]: https://learn.microsoft.com/cpp/build/reference/linker-options
[2]: https://github.com/KiFilterFiberContext/warbird-obfuscator
[3]: https://www.youtube.com/watch?v=gu_i6LYuePg
[4]: https://github.com/airbus-seclab/warbirdvm
[5]: https://github.com/KiFilterFiberContext/microsoft-warbird/
