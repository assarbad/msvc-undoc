# Undocumented MSVC

* [link.exe](LINK.exe.md)

## Environment variables

* `LOG_BUILD_COMMANDLINES`, see below.

### Used internally (requiring further research)

* `MSC_CMD_FLAGS`

# Findings by others

* [Geoff Chappell's seminal studies about Microsoft Visual C++][1], they aged _well_. Some of the findings he gives are still valid, some command line switches have meanwhile been documented.
* Someone going by the moniker @adeyblue [found out about `LOG_BUILD_COMMANDLINES`][2] ten years before I did
* [The Chromium build][3] appears to use plenty of flags, some of which are not documented
* [Microsoft Visual C/C++, Visual Studio tips and tricks][4]
* [Boost-MSBuild][5]
* [MSVC hidden flags][6] (unfortunately not much "meat")

# Additional resources

* [Versions of Visual C++][7] and the `_MSC_VER` and `_MSC_FULL_VER` values for various versions documented ([archived][8])
  * BSD-2-Clause-licensed [project to read the values from binaries][9] created with MSVC (can be suppressed via `/emittoolversioninfo:no` to the `link.exe`)
* [The mysterious 'Rich' header][10] ([archived][11])
  * [Article by Daniel Pistelli][12]
* Performance-related resources
  * [Visual Studio 2017 Throughput Improvements and Advice][13]
  * [Finding build bottlenecks with C++ Build Insights][20]
  * [C++ build throughput investigation and tune up][19]
  * [Best unknown MSVC flag: d2cgsummary][14]
  * [Another cool MSVC flag: /d1reportTime][15]
* Deterministic builds:
  * [Why are the module timestamps in Windows 10 so nonsensical?][16]
  * [The Chromium Projects: Deterministic builds][17]
  * [reproducible-builds.org][18]

# Useful tips

## Use `LOG_BUILD_COMMANDLINES` to log build command lines

Ever wondered what command lines get effectively executed "behind" those response files used by Visual Studio and MSBuild?

`LOG_BUILD_COMMANDLINES` has the answer. The environment variable should be set to a file path, which will be a plain text log file receiving all those build command lines. This works even for those command lines that _actually_ end up being invoked using response files due to command line length limitations on Windows.

The following `Directory.Build.props` provides a simple example of how to use this method. It uses the `SetEnv` MSBuild target to ensure that the environment variable gets set prior to invocation of the tools that honor the presence of this variable.

```
<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="Current" xmlns="http://schemas.microsoft.com/developer/msbuild/2003" InitialTargets="LogBuild">
	<PropertyGroup>
		<ThisProjectBuildLogFileName Condition="'$(MSBuildProjectName)' == ''">$(MSBuildThisFileDirectory)BuildCommandLines.log</ThisProjectBuildLogFileName>
		<ThisProjectBuildLogFileName Condition="'$(MSBuildProjectName)' != ''">$(MSBuildThisFileDirectory)BuildCommandLines-$(MSBuildProjectName).log</ThisProjectBuildLogFileName>
	</PropertyGroup>
	<Target Name="LogBuild" BeforeTargets="SetUserMacroEnvironmentVariables;SetBuildDefaultEnvironmentVariables">
		<Message Text="Setting LOG_BUILD_COMMANDLINES='$(ThisProjectBuildLogFileName)'" />
		<SetEnv Name="LOG_BUILD_COMMANDLINES" Value="$(ThisProjectBuildLogFileName)" Prefix="false" />
	</Target>
</Project>
```

# ETW-related GUIDs

*  `GUID_MSVC_PROVIDER`: `{9C642431-C036-7958-4B0E-FE163528322B}`

[1]: https://www.geoffchappell.com/studies/msvc/index.htm
[2]: http://blog.airesoft.co.uk/2013/01/plug-in-to-cls-kitchen/
[3]: https://chromium.googlesource.com/chromium/src/build/config/+/refs/heads/main/win/BUILD.gn
[4]: https://bearwindows.zcm.com.au/msvc.htm
[5]: https://github.com/ENikS/Boost-MSBuild
[6]: https://lectem.github.io/msvc/reverse-engineering/build/2019/01/21/MSVC-hidden-flags.html
[7]: https://dev.to/yumetodo/list-of-mscver-and-mscfullver-8nd
[8]: https://web.archive.org/web/20230000000000*/https://dev.to/yumetodo/list-of-mscver-and-mscfullver-8nd
[9]: https://github.com/dishather/richprint
[10]: http://bytepointer.com/articles/the_microsoft_rich_header.htm
[11]: https://web.archive.org/web/20230000000000*/http://bytepointer.com/articles/the_microsoft_rich_header.htm
[12]: https://ntcore.com/files/richsign.htm
[13]: https://devblogs.microsoft.com/cppblog/visual-studio-2017-throughput-improvements-and-advice/
[14]: https://aras-p.info/blog/2017/10/23/Best-unknown-MSVC-flag-d2cgsummary/
[15]: https://aras-p.info/blog/2019/01/21/Another-cool-MSVC-flag-d1reportTime/
[16]: https://devblogs.microsoft.com/oldnewthing/20180103-00/?p=97705
[17]: https://www.chromium.org/developers/testing/isolated-testing/deterministic-builds/
[18]: https://reproducible-builds.org/
[19]: https://devblogs.microsoft.com/cppblog/cpp-build-throughput-investigation-and-tune-up/
[20]: https://devblogs.microsoft.com/cppblog/finding-build-bottlenecks-with-cpp-build-insights/
