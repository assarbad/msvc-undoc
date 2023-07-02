# Undocumented MSVC

* [link.exe](LINK.exe.md)

## Environment variables

* `LOG_BUILD_COMMANDLINES` file name to log command lines into; this works even for those command lines that _actually_ end up being invoked using response files due to command line length limitation.

### Used internally (requiring further research)

* `MSC_CMD_FLAGS`

# Findings by others

* [Geoff Chappell's seminal studies about Microsoft Visual C++][1], they aged _well_. Some of the findings he gives are still valid, some command line switches have meanwhile been documented.
* Someone going by the moniker @adeyblue [found out about `LOG_BUILD_COMMANDLINES`][2] ten years before I did
* [MSVC hidden flags][3]
* [The Chromium build][4] appears to use plenty of flags, some of which are not documented
* [Microsoft Visual C/C++, Visual Studio tips and tricks][5]
* [Boost-MSBuild][6]

[1]: https://www.geoffchappell.com/studies/msvc/index.htm
[2]: http://blog.airesoft.co.uk/2013/01/plug-in-to-cls-kitchen/
[3]: https://lectem.github.io/msvc/reverse-engineering/build/2019/01/21/MSVC-hidden-flags.html
[4]: https://chromium.googlesource.com/chromium/src/build/config/+/refs/heads/main/win/BUILD.gn
[5]: https://bearwindows.zcm.com.au/msvc.htm
[6]: https://github.com/ENikS/Boost-MSBuild
