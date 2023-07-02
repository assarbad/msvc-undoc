# Undocumented MSVC

* [link.exe](LINK.exe.md)

## Environment variables

* `LOG_BUILD_COMMANDLINES`, see below.

### Used internally (requiring further research)

* `MSC_CMD_FLAGS`

# Findings by others

* [Geoff Chappell's seminal studies about Microsoft Visual C++][1], they aged _well_. Some of the findings he gives are still valid, some command line switches have meanwhile been documented.
* Someone going by the moniker @adeyblue [found out about `LOG_BUILD_COMMANDLINES`][2] ten years before I did
* [The Chromium build][4] appears to use plenty of flags, some of which are not documented
* [Microsoft Visual C/C++, Visual Studio tips and tricks][5]
* [Boost-MSBuild][6]
* [MSVC hidden flags][3] (unfortunately not much "meat")

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

[1]: https://www.geoffchappell.com/studies/msvc/index.htm
[2]: http://blog.airesoft.co.uk/2013/01/plug-in-to-cls-kitchen/
[3]: https://lectem.github.io/msvc/reverse-engineering/build/2019/01/21/MSVC-hidden-flags.html
[4]: https://chromium.googlesource.com/chromium/src/build/config/+/refs/heads/main/win/BUILD.gn
[5]: https://bearwindows.zcm.com.au/msvc.htm
[6]: https://github.com/ENikS/Boost-MSBuild
