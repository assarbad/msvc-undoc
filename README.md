# Undocumented MSVC

* [link.exe](LINK.exe.md)

## Environment variables

* `LOG_BUILD_COMMANDLINES` file name to log command lines into; this works even for those command lines that _actually_ end up being invoked using response files due to command line length limitation.

### Used internally (requiring further research)

* `MSC_CMD_FLAGS`

# Findings by others

* [Geoff Chappell's seminal studies about Microsoft Visual C++][1], they aged _well_. Some of the findings he gives are still valid, some command line switches have meanwhile been documented.
* [Someone going by the moniker @adeyblue found out about `LOG_BUILD_COMMANDLINES` ten years before I did][2]

[1]: https://www.geoffchappell.com/studies/msvc/index.htm
[2]: http://blog.airesoft.co.uk/2013/01/plug-in-to-cls-kitchen/
