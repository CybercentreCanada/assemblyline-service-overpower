# Overpower Service
Uses *modified* open-source tools to de-obfuscate and score PowerShell files, such as:
* [PSDecode](https://github.com/R3MRUM/PSDecode): PowerShell script for de-obfuscating encoded PowerShell scripts
* [PowerShellProfiler](https://github.com/pan-unit42/public_tools/tree/master/powershellprofiler): Palo Alto Networks Unit42 tool for statically analyzing PowerShell scripts by de-obfuscating and normalizing the content which is then profiled for behavioural indicators.
* [box-ps](https://github.com/ConnorShride/box-ps): Powershell sandboxing utility.

## Submission Parameters
Generic parameters:
* `tool_timeout`: The length of time we will allow tools to individually run for.
* `add_supplementary`: If you want supplementary files to be added to the result, select this.
PSDecode parameters:
* `fake_web_download`: A flag that is used for indicating if a web request to download a file to disk should be faked.
