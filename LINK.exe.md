# The linker: `link.exe`

Subject of the study: MSVC 14.34.31933, x64 version, targeting x64 (this is expected to change over time)
  * File Version: 14.34.31937.0
  * Product Version: 14.34.31937.0
  * File Description: Microsoft® Incremental Linker
  * Original Filename: `LINK.EXE`

NB: the following list has not yet been checked and mostly contains findings from looking at `link.exe` in raw form. Some of the arguments to invididual command line switches certainly require more research and confirmation.

Also note: not all findings will apply to older or newer versions of the toolchain.

## Switches for `link.exe`

The undocumented or barely mentioned switches are in bold, [the documented ones][1] are not.

| Command line switch                        | Description                                        |
|--------------------------------------------|----------------------------------------------------|
| `/align`                                   |                                                    |
| `/allowbind`                               |                                                    |
| **`/allowbadrvaforfirstsection`**          |                                                    |
| **`/allowimagesizeover2gb`**               |                                                    |
| `/allowisolation`                          | (:no)?                                             |
| **`/allpdata`**                            |                                                    |
| **`/alternatename`**                       | mentioned                                          |
| `/appcontainer`                            | (:no)?                                             |
| **`/arm64hazardexist`**                    |                                                    |
| **`/arm64hazardfree`**                     |                                                    |
| **`/arm64xaggressiverwdatafold`**          |                                                    |
| **`/arm64xcrossresolve`**                  |                                                    |
| **`/arm64xemulatorbuild`**                 |                                                    |
| **`/arm64xfastforward`**                   |                                                    |
| **`/arm64xfoldrwdata`**                    |                                                    |
| **`/arm64xhack`**                          |                                                    |
| **`/arm64xnewchameleonlibfmt`**            | (:no)?                                             |
| **`/arm64xnomergeimports`**                |                                                    |
| **`/arm64xnoreorderobjs`**                 |                                                    |
| **`/arm64xsameaddress`**                   |                                                    |
| **`/arm64xuselegacyffs`**                  | (:no)?                                             |
| **`/armhazardexist`**                      |                                                    |
| **`/armhazardfree`**                       |                                                    |
| `/assemblydebug`                           | (:disable)?                                        |
| `/assemblylinkresource`                    | (:private)                                         |
| `/assemblymodule`                          |                                                    |
| **`/assemblymodulemap`**                   |                                                    |
| `/assemblyresource`                        | (:private)                                         |
| **`/b2`**                                  |                                                    |
| `/base`                                    | /base:@ (read from file?)                          |
| **`/baserelocclustering`**                 | (:no)?                                             |
| **`/brepro`**                              |                                                    |
| `/cetcompat`                               | (:no)?                                             |
| **`/cetcompatstrict`**                     | (:no)?                                             |
| **`/cetdynamicapisinproc`**                | (:no)?                                             |
| **`/cetipvalidationrelaxed`**              | (:no)?                                             |
| `/cgthreads`                               | (warning CGTHREADS; LNK4271)                       |
| `/clrimagetype`                            | ijw/pure/safe/safe32bitpreferred                   |
| **`/clrloaderoptimization`**               | sd|md|mdh|none                                     |
| **`/clrnetcore`**                          |                                                    |
| **`/clrrvaentry`**                         | (:no)?                                             |
| **`/clrsignhash`**                         | sha1/sha256/sha384/sha512                          |
| **`/clrsupportlasterror`**                 | systemdll/no                                       |
| **`/clrsupportlasterrordll`**              |                                                    |
| `/clrthreadattribute`                      | sta/mta/none                                       |
| `/clrunmanagedcodecheck`                   | (:no)?                                             |
| **`/coffsecttopdbstrm`**                   |                                                    |
| **`/crashondiag`**                         |                                                    |
| **`/cvtres`**                              | folddups                                           |
| **`/cxxmodulestrongownership`**            | (:no)?                                             |
| **`/d2`**                                  |                                                    |
| **`/db`**                                  |                                                    |
| `/debug`                                   | forcefull/full/fastlink/mini/none/lazy/vc120/ctypes|
| `/debugtype`                               | cv/fixup/pdata                                     |
| `/def`                                     |                                                    |
| **`/defarm64native`**                      |                                                    |
| `/defaultlib`                              |                                                    |
| `/delay`                                   | nobind/unload                                      |
| `/delayload`                               |                                                    |
| `/delaysign`                               | (:no)?                                             |
| `/dependentloadflag`                       |                                                    |
| **`/didatownsection`**                     |                                                    |
| **`/disallowlib`**                         |                                                    |
| **`/discardtrack`**                        |                                                    |
| `/dll`                                     | system                                             |
| **`/dllrename`**                           |                                                    |
| `/driver`                                  | uonly/wdm                                          |
| `/dynamicbase`                             | (:no)?                                             |
| **`/dynamicvalue`**                        |                                                    |
| **`/editandcontinue`**                     |                                                    |
| **`/emitasx64image`**                      |                                                    |
| **`/emitasx64imagewithaa64`**              |                                                    |
| **`/emitpogophaseinfo`**                   |                                                    |
| **`/emittoolversioninfo`**                 | (:no)?                                             |
| **`/emitvolatilemetadata`**                | (:no)?                                             |
| **`/enclave`**                             | (:no)?                                             |
| **`/encpadsize`**                          |                                                    |
| `/entry`                                   |                                                    |
| `/errorreport`                             | none/prompt/queue/send/test/internal               |
| **`/etm`**                                 |                                                    |
| **`/expectedoutputsize`**                  |                                                    |
| **`/experimental`**                        | deterministic/tlsDllInterface                      |
| `/export`                                  |                                                    |
| **`/exportarm64native`**                   |                                                    |
| **`/exportpadmin`**                        |                                                    |
| **`/fastfail`**                            | (:no)?                                             |
| **`/fe`**                                  |                                                    |
| `/filealign`                               |                                                    |
| `/fixed`                                   |                                                    |
| `/force`                                   | guardehcont/multiple/pgo/pgorepro/unresolved       |
| **`/forcewinmdversion12`**                 |                                                    |
| **`/fullbuild`**                           |                                                    |
| **`/funcoverride`**                        | (:no)?                                             |
| **`/funcoverridedisablefunc`**             |                                                    |
| **`/funcoverrideemitcand`**                |                                                    |
| **`/funcoverrideoncallsites`**             |                                                    |
| `/functionpadmin`                          |                                                    |
| **`/genpdbfromscratch`**                   | (:no)?                                             |
| `/genprofile` / `/fastgenprofile`          | memmin/memmax/pgd/exact/noexact/path/nopath/trackeh/notrackeh/counter32/counter64|
| `/guard`                                   | no/addrtakeniat/noaddrtakeniat/delayloadsignret/nodelayloadsignret/delayloadsignretnopunwind/nodelayloadsignretnopunwind/ehcont/noehcont/export/noexport/exportsuppress/noexportsuppress/exportsuppressinfo/noexportsuppressinfo/mixed/nomixed/cf/cfw/32bytealign/langexcpthandler/nolangexcpthandler/longjmp/nolongjmp/retpoline/noretpoline/xfg/noxfg/memcpy/nomemcpy|
| **`/guardsym`**                            |                                                    |
| `/heap`                                    |                                                    |
| `/highentropyva`                           | (:no)?                                             |
| **`/hotpatchcompatible`**                  | (:no)?                                             |
| **`/hybriddefupgrade`**                    |                                                    |
| **`/hybridexportthunks`**                  | (:no)?                                             |
| **`/hybriduseguestmachine`**               | (:no)?                                             |
| **`/icfsection`**                          |                                                    |
| `/idlout`                                  |                                                    |
| `/ignore`                                  |                                                    |
| `/ignoreidl`                               |                                                    |
| `/ilk`                                     |                                                    |
| **`/iltcgwarningoff`**                     |                                                    |
| `/implib`                                  |                                                    |
| **`/impthunkalign`**                       |                                                    |
| `/include`                                 |                                                    |
| **`/includecoffsection`**                  |                                                    |
| `/incremental`                             | yes/no/rebuild/stress/nostress                     |
| `/inferasanlibs`                           | (:no)?                                             |
| `/integritycheck`                          |                                                    |
| **`/kernel`**                              |                                                    |
| `/keycontainer`                            |                                                    |
| `/keyfile`                                 |                                                    |
| `/largeaddressaware`                       | (:no)?                                             |
| **`/last`**                                |                                                    |
| **`/layoutpagesize`**                      |                                                    |
| `/libpath`                                 |                                                    |
| `/linkrepro`                               |                                                    |
| `/linkreprotarget`                         |                                                    |
| `/logo`                                    |                                                    |
| `/ltcg`                                    |                                                    |
| **`/ltcgasmlist`**                         |                                                    |
| **`/ltcgout`**                             |                                                    |
| `/machine`                                 |                                                    |
| `/manifest`                                | no/embed/id (resource ID?)                         |
| `/manifestdependency`                      |                                                    |
| `/manifestfile`                            |                                                    |
| `/manifestinput`                           |                                                    |
| `/manifestuac`                             | (:no)?                                             |
| `/map`                                     |                                                    |
| `/mapinfo`                                 | exports/pdata/tokens                               |
| **`/maxilksize`**                          |                                                    |
| `/merge`                                   |                                                    |
| **`/midl`**                                | (:@rspfile)                                        |
| **`/midlexe`**                             |                                                    |
| **`/minpdbpathlen`**                       |                                                    |
| **`/mt`**                                  |                                                    |
| `/natvis`                                  |                                                    |
| `/noassembly`                              |                                                    |
| **`/nocoffgrpinfo`**                       |                                                    |
| **`/nocomentry`**                          |                                                    |
| **`/nodbgdirmerge`**                       |                                                    |
| `/nodefaultlib` / **`/nod`**               | those seem to be synonymous                        |
| `/noentry`                                 |                                                    |
| **`/noexp`**                               |                                                    |
| **`/nofunctionpadsection`**                |                                                    |
| **`/noilinkcoffgrppad`**                   |                                                    |
| **`/noimplib`**                            |                                                    |
| **`/nolinkrepro`**                         |                                                    |
| `/nologo`                                  |                                                    |
| **`/noltcgoptref`**                        |                                                    |
| **`/nomap`**                               |                                                    |
| **`/noonfailrepro`**                       |                                                    |
| **`/nooptdidat`**                          |                                                    |
| **`/nooptcfg`**                            |                                                    |
| **`/nooptgids`**                           |                                                    |
| **`/nooptidata`**                          |                                                    |
| **`/noopttls`**                            |                                                    |
| **`/nooptrefbeforeltcg`**                  |                                                    |
| **`/novcfeature`**                         |                                                    |
| **`/noxdatamerge`**                        |                                                    |
| `/nxcompat`                                | (:no)?                                             |
| **`/objmap`**                              |                                                    |
| **`/odr`**                                 |                                                    |
| **`/odrignore`**                           | (/odrignore:@rspfile)                              |
| **`/odrignoresamesize`**                   |                                                    |
| `/opt`                                     | icf/stricticf/lbr/noicf/nolbr/noref/nostricticf/ref|
| **`/opticfbytecomp`**                      |                                                    |
| **`/onfailrepro`**                         |                                                    |
| `/order`                                   | (/order:@rspfile) (:no)?                           |
| **`/osversion`**                           |                                                    |
| `/out`                                     |                                                    |
| **`/pchmap`**                              |                                                    |
| **`/pdbmap`**                              |                                                    |
| **`/winmdmap`**                            |                                                    |
| **`/pathmap`**                             | PDB-related                                        |
| `/pdb`                                     |                                                    |
| `/pdbaltpath`                              |                                                    |
| **`/pdbcompress`**                         | (:no)?                                             |
| **`/pdbdbgqsize`**                         |                                                    |
| **`/pdbdbgst`**                            |                                                    |
| **`/pdbdll`**                              |                                                    |
| **`/pdbmodclosethreads`**                  |                                                    |
| **`/pdbpagesize`** ==? **`/pagesize`**     |                                                    |
| **`/pdbpath`**                             | sourcemap                                          |
| **`/pdbrpc`**                              | (:no)?                                             |
| `/pdbstripped`                             |                                                    |
| **`/pdbthreads`**                          |                                                    |
| **`/pdbtmcache`**                          | (:no)?                                             |
| `/pgd`                                     |                                                    |
| **`/pogonoshare`**                         |                                                    |
| `/pogosafemode`                            |                                                    |
| **`/prefetch`**                            |                                                    |
| `/profile`                                 |                                                    |
| **`/rc`**                                  |                                                    |
| **`/re`**                                  |                                                    |
| **`/reportnoncomdatguardfunc`**            |                                                    |
| **`/retryonfileopenfailure`**              |                                                    |
| **`/runbelow4gb`**                         | (:no)?                                             |
| `/safeseh`                                 | (:no)?                                             |
| **`/savebaserelocations`**                 |                                                    |
| `/section`                                 |                                                    |
| **`/sectionlayout`**                       |                                                    |
| **`/simarm`**                              |                                                    |
| **`/simarm64`**                            |                                                    |
| **`/skipincrementalchecks`**               |                                                    |
| `/sourcelink`                              |                                                    |
| **`/sourcemap`**                           |                                                    |
| **`/spdidstr`**                            |                                                    |
| **`/spdin`**                               |                                                    |
| **`/spdindex`**                            |                                                    |
| **`/spdembed`**                            |                                                    |
| **`/spgo`**                                |                                                    |
| `/stack`                                   |                                                    |
| **`/stricticfthunkalign`**                 |                                                    |
| **`/striprtti`**                           | (:no)?                                             |
| `/stub`                                    | (/stub:)                                           |
| `/subsystem`                               |                                                    |
| **`/subsystemversion`**                    |                                                    |
| **`/swaprun`**                             | cd/net                                             |
| **`/test`**                                |                                                    |
| **`/throwingnew`**                         |                                                    |
| `/time`                                    | (:no)?                                             |
| **`/time+`**                               |                                                    |
| `/tlbid`                                   |                                                    |
| `/tlbout`                                  |                                                    |
| **`/trimfile`**                            |                                                    |
| `/tsaware`                                 | (:no)?                                             |
| `/useprofile`                              |                                                    |
| `/version`                                 |                                                    |
| `/verbose`                                 | lib/ref/icf/safeseh/clr/unuseddelayload/unusedlibs/incr/telemetry|
| **`/vulcannotrecognizenewdelaythunk`**     |                                                    |
| **`/warnduplicatesections`**               |                                                    |
| **`/wbrdcfg`**                             |                                                    |
| **`/wbrddll`**                             |                                                    |
| **`/wbrdlog`**                             |                                                    |
| **`/wbrdreporterrors`**                    |                                                    |
| **`/wbrdschema`**                          |                                                    |
| **`/wbrdsummary`**                         |                                                    |
| **`/wbrdtestencrypt`**                     |                                                    |
| **`/weakorder`**                           |                                                    |
| **`/win32version`**                        |                                                    |
| `/winmd`                                   | no/only                                            |
| `/winmddelaysign`                          | (:no)?                                             |
| `/winmdfile`                               |                                                    |
| `/winmdkeycontainer`                       |                                                    |
| `/winmdkeyfile`                            |                                                    |
| **`/winmdsignhash`**                       | sha1/sha256/sha384/sha512                          |
| **`/winmdversion`**                        |                                                    |
| **`/wholearchive`**                        |                                                    |
| **`/wowa64`**                              | (:no)?                                             |
| **`/wowa64lib`**                           |                                                    |
| `/wx`                                      |                                                    |
| **`/x86pdata`**                            | (:no)?                                             |
| **`/xoff`**                                |                                                    |

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
| `VS_UNICODE_OUTPUT`                | some "port" (pipe?), used by Visual Studio IDE, used to detect running in the IDE|
| `VSTEL_SolutionSessionID`          | some GUID; adhoc generated?                        |
| `VSTEL_CurrentSolutionBuildID`     | an (unsigned?) integer (PID/TID?)                  |
| `VSTEL_ProjectID`                  | a GUID; does it correspond to project GUID?        |

Used (and populated) internally for `/pdbaltpath`:

* `_EXT`
* `_PDB`

## Glossary (guessed)

* POGO: Profile Guided Optimization

[1]: https://learn.microsoft.com/cpp/build/reference/linker-options
