# RegRipper3.0

Here's what's new in this release

## WHAT'S NEW

- With the GUI (`rr.exe`), you no longer have to select a `profile;`. 
Instead, select the hive to parse, and the output directory and the GUI will 
automatically run all applicable plugins against the hive. This capability is 
included in `rip.exe`, as well, via the `-a` switch.  As an 
alternative, you can use the `-aT` switch to run all hive-specific TLN plugins
against the hive.  The ability to run individual plugins, as well as profiles, 
has been retained, as well.  You can see other options available by typing
`rip` or `rip -h` or `rip /?` at the command line.

- Date Format - There was a GitHub issue posted, asking that the date format be 
changed to be IAW [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601). However, the actual format provided as part of the 
issue/request was IAW the RFC 3339 profile (i.e., space between the date and 
time).

### NOTE

This tool does NOT automatically process hive transaction logs. If you need
to incorporate data from hive transaction logs into your analysis, consider merging
the data via Maxim Suhanov's `yarp` + `registryFlush.py`, or via Eric Zimmerman's `rla.exe`
which is included in [Eric's Registry Explorer/RECmd](https://f001.backblazeb2.com/file/EricZimmermanTools/RegistryExplorer_RECmd.zip).

The following Perl module files have been modified, and the modified versions are 
provided as part of this repo:

```
C:\Perl\site\lib\Parse\Win32Registry\WinNT\File.pm
C:\Perl\site\lib\Parse\Win32Registry\WinNT\Base.pm
C:\Perl\site\lib\Parse\Win32Registry\WinNT\Key.pm
```

If you're using the Windows `exe` version of the tools, this is irrelevant, as the 
modified files are "**compiled**" into the `exe`. However, if you're installing on Linux,
copy the files from the repo to the appropriate locations in your installation.
