/**
 * Behaviour analysis for living-off-the-land binaries (LOLBins) and other command-line tradecraft.
 *
 * Why this exists: a LOLBin (rundll32, certutil, mshta, regsvr32, powershell…) is a signed, clean
 * Microsoft binary, so reputation lookups always say "benign". What makes it malicious is HOW it is
 * used. This module reads command lines, parent/child pairs and executable paths, and turns known abuse
 * patterns into literal statements with a MITRE ATT&CK technique, which Jev then judges.
 *
 * Pure code, no network. Patterns follow the public LOLBAS project (lolbas-project.github.io) and
 * MITRE ATT&CK. Strength:
 *   strong   – essentially never legitimate admin work (blocks a benign close, like a reputation hard hit)
 *   moderate – suspicious, sometimes legitimate (shown to Jev, does not block on its own)
 *   weak     – context worth knowing (discovery commands, decoded content)
 */

export type Strength = "strong" | "moderate" | "weak";
export type Behavior = {
  id: string;
  technique: string; // MITRE ATT&CK ID and name
  strength: Strength;
  statement: string; // plain sentence shown to Jev and to the analyst
  evidence: string; // the command line (or pair) that matched, trimmed
};

/** Linux/macOS tools that commonly appear in pasted alert text (used to find command lines in free text). */
const UNIX_TOOLS = ["curl", "wget", "bash", "zsh", "python", "python3", "perl", "ncat", "socat", "osascript", "launchctl", "xattr", "spctl", "csrutil", "dscl", "crontab", "systemctl", "useradd", "usermod", "insmod", "setenforce", "iptables", "tccutil", "sysadminctl", "screencapture", "xmrig", "nsenter", "docker", "security", "chmod", "nohup", "sudo", "sh"];

/** Built-in tools attackers abuse, with their normal purpose (so Jev can judge deviation from it). */
export const LOLBINS: Record<string, string> = {
  "powershell.exe": "a scripting shell used for administration",
  "pwsh.exe": "a scripting shell used for administration",
  "cmd.exe": "the Windows command shell",
  "rundll32.exe": "runs functions exported from system DLLs, e.g. Control Panel applets",
  "regsvr32.exe": "registers COM DLLs during software installation",
  "mshta.exe": "runs legacy HTML Application (.hta) files",
  "certutil.exe": "manages certificates and certificate stores",
  "bitsadmin.exe": "manages Background Intelligent Transfer Service jobs",
  "msbuild.exe": "builds .NET projects for developers",
  "installutil.exe": "installs .NET services",
  "regasm.exe": "registers .NET assemblies for COM",
  "regsvcs.exe": "registers .NET component services",
  "wmic.exe": "queries and manages Windows through WMI",
  "cscript.exe": "runs VBScript/JScript from the console",
  "wscript.exe": "runs VBScript/JScript files",
  "schtasks.exe": "manages scheduled tasks",
  "reg.exe": "reads and edits the registry",
  "sc.exe": "manages Windows services",
  "msiexec.exe": "installs MSI packages",
  "cmstp.exe": "installs VPN connection profiles",
  "odbcconf.exe": "configures ODBC database drivers",
  "forfiles.exe": "runs a command on a set of files",
  "pcalua.exe": "the Program Compatibility Assistant",
  "esentutl.exe": "repairs and copies ESE databases",
  "ntdsutil.exe": "maintains Active Directory databases",
  "vssadmin.exe": "manages Volume Shadow Copies",
  "wbadmin.exe": "manages Windows backups",
  "bcdedit.exe": "edits boot configuration",
  "wevtutil.exe": "queries and manages event logs",
  "net.exe": "manages users, groups, shares and services",
  "net1.exe": "manages users, groups, shares and services",
  "nltest.exe": "tests domain trust and domain controller status",
  "hh.exe": "opens compiled Windows Help (.chm) files",
  "msdt.exe": "runs Microsoft Support Diagnostic packages",
  "curl.exe": "transfers data from URLs",
  "findstr.exe": "searches text in files",
  "netsh.exe": "configures networking and the firewall",
  "csc.exe": "the C# compiler, used by developers and by PowerShell Add-Type",
  "vbc.exe": "the VB.NET compiler, used by developers",
  "jsc.exe": "the JScript.NET compiler, used by developers",
};

/** A file created or written, as reported by the alert (Sysmon FileCreate, EDR file events...). */
export type FileRecord = { path: string; entropy?: number; operation?: string };

/** System DLL names that programs load from their own folder first: the classic DLL side-loading targets. */
const SIDELOAD_DLLS = new Set("version.dll winmm.dll dbghelp.dll dbgcore.dll wtsapi32.dll cryptbase.dll cryptsp.dll dwrite.dll uxtheme.dll userenv.dll secur32.dll sspicli.dll msimg32.dll dxgi.dll iphlpapi.dll netapi32.dll profapi.dll propsys.dll samlib.dll winhttp.dll wininet.dll mswsock.dll dnsapi.dll wldp.dll mpclient.dll edputil.dll wer.dll faultrep.dll oleacc.dll dwmapi.dll winsta.dll logoncli.dll ntmarta.dll libcurl.dll".split(" "));
/** Executable names of Windows core and security components: an impostor is almost never legitimate. */
const CRITICAL_NAMES = new Set("svchost.exe lsass.exe csrss.exe winlogon.exe smss.exe services.exe wininit.exe lsm.exe spoolsv.exe msmpeng.exe nissrv.exe mpcmdrun.exe securityhealthsystray.exe securityhealthservice.exe".split(" "));
/** Other Windows component names attackers borrow. */
const COMPONENT_NAMES = new Set("explorer.exe dllhost.exe taskhostw.exe conhost.exe rundll32.exe runtimebroker.exe sihost.exe ctfmon.exe searchindexer.exe audiodg.exe wuauclt.exe taskmgr.exe smartscreen.exe fontdrvhost.exe dwm.exe".split(" "));
const SYSTEM_DIR = /\\windows\\(system32|syswow64|winsxs|servicing|softwaredistribution|microsoft\.net)\\|\\program files( \(x86\))?\\windows defender|\\programdata\\microsoft\\windows defender\\/i;
const USER_WRITABLE = /\\users\\|\\programdata\\|\\windows\\temp\\|^[a-z]:\\temp\\|\\perflogs\\|\\\$recycle\.bin\\/i;

const OFFICE = /^(winword|excel|powerpnt|outlook|onenote|onenotem|msaccess|mspub|visio|acrord32|acrobat|foxitreader|foxitpdfreader)\.exe$/;
const BROWSER = /^(chrome|msedge|firefox|iexplore|brave|opera)\.exe$/;
const UNIX_SERVICES = /^(apache2?|httpd|nginx|php-fpm[\d.]*|php-cgi|php|tomcat\d*|catalina\.sh|java|node|mysqld|mariadbd|postgres|redis-server|mongod|jenkins|gitlab-workhorse|confluence|jboss|weblogic|lighttpd|caddy|uwsgi|gunicorn)$/;
const UNIX_SHELLISH = /^(sh|bash|dash|zsh|ksh|busybox|python[\d.]*|perl|ruby|nc|ncat|netcat|socat|curl|wget|base64|id|whoami|uname)$/;
const WEBSERVER = /^(w3wp|httpd|nginx|tomcat\d*|php-cgi|java|sqlservr|umworkerprocess)\.exe$/;
const SCRIPTY = /^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msbuild|schtasks|wmic|curl|hh|msiexec|csc|vbc|jsc)\.exe$/;
const SYSTEM_NAMES = /^(svchost|lsass|csrss|services|winlogon|smss|spoolsv|taskhostw|dllhost|wininit|lsm|conhost|rundll32|explorer)\.exe$/;
const USER_PATH = String.raw`(?:\\users\\[^\\"]+\\(?:appdata|downloads|desktop|documents|music|pictures|videos)|\\users\\public|\\programdata|\\windows\\temp|\\temp|\\perflogs|\\recycler|\\\$recycle\.bin)\\`;
const REMOTE = String.raw`(?:https?:|ftp:|\\\\[a-z0-9._-]+\\)`;

type Rule = { id: string; technique: string; strength: Strength; test: RegExp; also?: RegExp; unless?: RegExp; statement: string };

// Every regex runs on a normalised, lower-cased command line (carets and doubled quotes removed).
const RULES: Rule[] = [
  // --- PowerShell
  { id: "ps_download_exec", technique: "T1059.001 PowerShell / T1105 Ingress Tool Transfer", strength: "strong",
    test: /(downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|start-bitstransfer|\bwget\b)/,
    also: /(\biex\b|invoke-expression|\|\s*iex|\.invoke\(|start-pro(?:cess)|&\s*\(|\bsal\b)/,
    statement: "PowerShell downloads content and executes it straight away (download-and-run, usually in memory)." },
  { id: "ps_download", technique: "T1105 Ingress Tool Transfer", strength: "moderate",
    test: /(powershell|pwsh).*(downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\b|start-bitstransfer)/,
    statement: "PowerShell downloads a file from the internet." },
  { id: "ps_encoded", technique: "T1027 Obfuscated Files / T1059.001 PowerShell", strength: "moderate",
    test: /(powershell|pwsh)(\.exe)?\b.*\s[-/]e(c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedcommand)?\s+[a-z0-9+/=]{16,}/,
    statement: "PowerShell runs a base64-encoded command, which hides what it does." },
  { id: "ps_hidden_bypass", technique: "T1564.003 Hidden Window / T1059.001 PowerShell", strength: "moderate",
    test: /[-/]w(i|in|ind|indo|indow|indows|indowst|indowsty|indowstyl|indowstyle)?\s+h(i|id|idd|idde|idden)?\b/,
    also: /[-/](ep|exec|executionpolicy)\s+bypass|[-/]nop(rofile)?\b/,
    statement: "PowerShell runs in a hidden window with profile/execution-policy protections skipped." },
  { id: "ps_amsi_defender", technique: "T1562.001 Disable or Modify Tools", strength: "strong",
    test: /(amsiutils|amsiinitfailed|amsiscanbuffer|set-mppreference\s.*-disable|add-mppreference\s.*-exclusion(path|pro(?:cess)|extension))/,
    statement: "A command disables or bypasses antivirus scanning (AMSI bypass or Defender settings change)." },
  // --- certutil / bitsadmin / curl downloads
  { id: "certutil_download", technique: "T1105 Ingress Tool Transfer (certutil)", strength: "strong",
    test: /certutil(\.exe)?\b.*(-urlcache|\/urlcache|-verifyctl|-split\s+-f)/, also: new RegExp(REMOTE),
    statement: "certutil, a certificate tool, is used to download a file from a remote address." },
  { id: "certutil_decode", technique: "T1140 Deobfuscate/Decode Files", strength: "moderate",
    test: /certutil(\.exe)?\b.*\s[-/](decode|decodehex)\b/,
    statement: "certutil is used to decode a file (commonly a base64-wrapped payload)." },
  { id: "bitsadmin_transfer", technique: "T1197 BITS Jobs / T1105 Ingress Tool Transfer", strength: "strong",
    test: /bitsadmin(\.exe)?\b.*\/(transfer|addfile|setnotifycmdline)\b/,
    statement: "bitsadmin creates a background transfer job to fetch or run a file." },
  { id: "curl_download", technique: "T1105 Ingress Tool Transfer", strength: "moderate",
    test: /\bcurl(\.exe)?\b.*\s(-o|--output|-O)\s/, also: new RegExp(REMOTE),
    // Adding a vendor's package-signing key or repository is routine server setup.
    unless: /https:\/\/(packages\.microsoft\.com|download\.docker\.com|apt\.releases\.hashicorp\.com|deb\.nodesource\.com|dl\.google\.com|packages\.cloud\.google\.com|apt\.kubernetes\.io|pkgs\.k8s\.io|repo\.mysql\.com|nginx\.org)\/\S*\s.*(\/usr\/share\/keyrings|\/etc\/apt|\/etc\/yum\.repos\.d|\/etc\/pki)|(\/usr\/share\/keyrings|\/etc\/apt|\/etc\/yum\.repos\.d)\/\S*\s+https:\/\/(packages\.microsoft\.com|download\.docker\.com|apt\.releases\.hashicorp\.com|deb\.nodesource\.com|dl\.google\.com|packages\.cloud\.google\.com)/,
    statement: "curl downloads a file from a remote address and saves it to disk." },
  // --- proxy execution through signed binaries
  { id: "mshta_remote_script", technique: "T1218.005 Mshta", strength: "strong",
    test: new RegExp(String.raw`mshta(\.exe)?\b.*(${REMOTE}|javascript:|vbscript:)`),
    statement: "mshta runs script code or an HTA fetched from a remote address." },
  { id: "mshta_local_hta", technique: "T1218.005 Mshta", strength: "moderate",
    test: /mshta(\.exe)?\b.*\.hta\b/, statement: "mshta runs a local HTML Application (.hta) file." },
  { id: "regsvr32_squiblydoo", technique: "T1218.010 Regsvr32", strength: "strong",
    test: new RegExp(String.raw`regsvr32(\.exe)?\b.*(\/i:\s*${REMOTE}|scrobj\.dll)`),
    statement: "regsvr32 loads a remote scriptlet through scrobj.dll (the 'Squiblydoo' technique)." },
  { id: "regsvr32_user_path", technique: "T1218.010 Regsvr32", strength: "moderate",
    test: new RegExp(String.raw`regsvr32(\.exe)?\b.*${USER_PATH}`),
    statement: "regsvr32 registers/loads a DLL from a user-writable folder." },
  { id: "rundll32_script", technique: "T1218.011 Rundll32", strength: "strong",
    test: /rundll32(\.exe)?\b.*(javascript:|vbscript:|mshtml\s*,\s*runhtmlapplication)/,
    statement: "rundll32 runs script code through mshtml instead of a DLL function." },
  { id: "lsass_minidump", technique: "T1003.001 LSASS Memory", strength: "strong",
    test: /comsvcs(\.dll)?\s*[, ]\s*#?(minidump|24)\b|procdump(64)?(\.exe)?\b.*\blsass\b|sekurlsa|mimikatz/,
    statement: "Process memory is dumped in a way used to steal credentials from LSASS." },
  { id: "rundll32_user_path", technique: "T1218.011 Rundll32", strength: "moderate",
    test: new RegExp(String.raw`rundll32(\.exe)?["\s]+[^,]*${USER_PATH}`),
    statement: "rundll32 runs a DLL from a user-writable or temporary folder rather than a system folder." },
  { id: "rundll32_odd_ext", technique: "T1218.011 Rundll32", strength: "moderate",
    test: /rundll32(\.exe)?["\s]+[^,\s]*\.(dat|tmp|png|jpg|gif|txt|log|bin|db|ocx|cpl)\s*[,\s]/,
    statement: "rundll32 loads a 'DLL' with a non-DLL file extension, a common disguise." },
  { id: "rundll32_no_args", technique: "T1218.011 Rundll32 (sacrificial host)", strength: "moderate",
    test: /(^|\\)rundll32(\.exe)?"?\s*$/,
    statement: "rundll32 runs with no arguments, typical of a program created only to host injected code." },
  { id: "lolbin_unc", technique: "T1218 System Binary Proxy Execution", strength: "moderate",
    test: /(rundll32|regsvr32|mshta|msiexec|wscript|cscript)(\.exe)?["\s]+"?\\\\[a-z0-9._-]+\\/,
    statement: "A built-in tool loads code straight from a network share." },
  { id: "msbuild_user_path", technique: "T1127.001 MSBuild", strength: "strong",
    test: new RegExp(String.raw`msbuild(\.exe)?\b.*${USER_PATH}[^\s"]*\.(xml|csproj|proj|txt|targets)`),
    statement: "MSBuild compiles and runs a project file from a user-writable folder (inline-task execution)." },
  { id: "installutil_uninstall", technique: "T1218.004 InstallUtil", strength: "strong",
    test: /installutil(\.exe)?\b.*(\/u\b|\/logtoconsole=false)/,
    statement: "InstallUtil is used with /U or hidden logging to run code in an assembly's uninstall routine." },
  { id: "regasm_regsvcs", technique: "T1218.009 Regsvcs/Regasm", strength: "strong",
    test: /(regasm|regsvcs)(\.exe)?\b.*\/u\b/, statement: "RegAsm/RegSvcs is used with /U to run code from an assembly." },
  { id: "cmstp_inf", technique: "T1218.003 CMSTP", strength: "strong",
    test: /cmstp(\.exe)?\b.*\/(s|au)\b.*\.inf/, statement: "CMSTP silently installs an .inf profile, a known way to run code and bypass UAC." },
  { id: "odbcconf_regsvr", technique: "T1218.008 Odbcconf", strength: "strong",
    test: /odbcconf(\.exe)?\b.*(regsvr|\/a\s*\{)/, statement: "odbcconf registers a DLL through a driver action, which runs its code." },
  { id: "msiexec_remote", technique: "T1218.007 Msiexec", strength: "strong",
    test: new RegExp(String.raw`msiexec(\.exe)?\b.*\/(i|package|y)\s*"?${REMOTE}`),
    statement: "msiexec installs a package straight from a remote address." },
  { id: "wmic_remote_exec", technique: "T1047 WMI (remote execution)", strength: "strong",
    test: /wmic(\.exe)?\b.*\/node:.*pro(?:cess)\s+call\s+create/, statement: "WMIC starts a program on another machine." },
  { id: "wmic_exec", technique: "T1047 WMI", strength: "moderate",
    test: /wmic(\.exe)?\b.*pro(?:cess)\s+call\s+create/, statement: "WMIC is used to start a program." },
  { id: "wmic_xsl", technique: "T1220 XSL Script Processing", strength: "strong",
    test: new RegExp(String.raw`wmic(\.exe)?\b.*\/format:\s*"?(${REMOTE}|[^\s"]*\.xsl)`),
    statement: "WMIC loads an XSL stylesheet that can carry script code ('SquiblyTwo')." },
  { id: "hh_remote", technique: "T1218.001 Compiled HTML File", strength: "strong",
    test: new RegExp(String.raw`\bhh(\.exe)?\s+"?${REMOTE}`), statement: "hh.exe opens a remote compiled help file, which can run script." },
  { id: "msdt_follina", technique: "T1218 / CVE-2022-30190 (Follina)", strength: "strong",
    test: /msdt(\.exe)?\b.*(it_browseforfile|ms-msdt:|pcwdiagnostic.*\$\()/, statement: "msdt is called with the parameters used by the Follina exploit." },
  { id: "script_host_user_path", technique: "T1059.005/.007 VBScript/JScript", strength: "strong",
    test: new RegExp(String.raw`(wscript|cscript)(\.exe)?\b.*${USER_PATH}[^\s"]*\.(js|jse|vbs|vbe|wsf|hta)`),
    statement: "A script host runs a script from a user-writable folder (typical of email or download delivery)." },
  { id: "indirect_exec", technique: "T1202 Indirect Command Execution", strength: "moderate",
    test: /(forfiles(\.exe)?\b.*\/c\s|pcalua(\.exe)?\b.*\s-a\s)/, statement: "A helper tool is used to launch another program indirectly." },
  // --- persistence
  { id: "schtasks_suspicious", technique: "T1053.005 Scheduled Task", strength: "strong",
    test: /schtasks(\.exe)?\b.*\/create\b/,
    also: new RegExp(String.raw`(powershell|pwsh|cmd(\.exe)?\s+\/c|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin|${USER_PATH}|https?:)`),
    statement: "A scheduled task is created that runs a script host, a proxy tool, or a file from a user-writable folder." },
  { id: "schtasks_create", technique: "T1053.005 Scheduled Task", strength: "weak",
    test: /schtasks(\.exe)?\b.*\/create\b/, statement: "A scheduled task is created." },
  { id: "run_key", technique: "T1547.001 Registry Run Keys / T1546.012 IFEO", strength: "strong",
    test: /reg(\.exe)?\s+add\s+.*(currentversion\\(run|runonce|policies\\explorer\\run)|winlogon\b.*(userinit|shell)|image file execution options)/,
    statement: "A registry autostart location (Run key, Winlogon or IFEO) is modified." },
  { id: "service_create", technique: "T1543.003 Windows Service", strength: "moderate",
    test: new RegExp(String.raw`\bsc(\.exe)?\s+(\\\\[^\s]+\s+)?create\b.*(${USER_PATH}|powershell|cmd(\.exe)?\s+\/c|rundll32|mshta)`),
    statement: "A new service is created that runs a script host or a file from a user-writable folder." },
  { id: "account_created", technique: "T1136 Create Account / T1098 Account Manipulation", strength: "strong",
    test: /net1?(\.exe)?\s+(user\s+\S+\s+\S+.*\/add\b|localgroup\s+"?administrators"?\s+\S+.*\/add\b|group\s+"?domain admins"?\s+\S+.*\/add\b)/,
    statement: "An account is created or added to an administrators group from the command line." },
  // --- credential access
  { id: "sam_hive_save", technique: "T1003.002 Security Account Manager", strength: "strong",
    test: /reg(\.exe)?\s+save\s+.*hklm\\(sam|system|security)\b/, statement: "The SAM/SYSTEM/SECURITY registry hive is saved to a file (offline password extraction)." },
  { id: "ntds_copy", technique: "T1003.003 NTDS", strength: "strong",
    test: /(ntdsutil(\.exe)?\b.*\b(ifm|create full)\b|esentutl(\.exe)?\b.*\/(y|vss)\b.*ntds|copy\s+.*ntds\.dit|vssadmin(\.exe)?\s+create\s+shadow)/,
    statement: "The Active Directory database (NTDS.dit) is copied, which exposes every domain password hash." },
  { id: "gpp_passwords", technique: "T1552.006 Group Policy Preferences", strength: "strong",
    test: /findstr(\.exe)?\b.*cpassword.*sysvol|sysvol.*cpassword/, statement: "SYSVOL is searched for stored Group Policy passwords." },
  // --- defense evasion / impact
  { id: "inhibit_recovery", technique: "T1490 Inhibit System Recovery", strength: "strong",
    test: /(vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\b.*shadowcopy\s+delete|wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup|backup)|bcdedit(\.exe)?\b.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures))/,
    statement: "Backups or shadow copies are deleted or recovery is disabled, a common step right before ransomware encryption." },
  { id: "clear_logs", technique: "T1070.001 Clear Windows Event Logs", strength: "strong",
    test: /wevtutil(\.exe)?\s+(cl|clear-log)\b|clear-eventlog\b/, statement: "Windows event logs are cleared." },
  { id: "defense_off", technique: "T1562.001/.004 Impair Defenses", strength: "strong",
    test: /(sc(\.exe)?\s+(stop|config|delete)\s+(windefend|sense|wdboot|wdfilter|wdnissvc)\b|mpcmdrun(\.exe)?\b.*-removedefinitions|netsh(\.exe)?\b.*advfirewall.*state\s+off|netsh(\.exe)?\s+firewall\s+set\s+opmode\s+disable)/,
    statement: "Security software or the firewall is stopped or disabled." },
  // --- discovery (weak: common in admin work, meaningful in combination)
  { id: "discovery", technique: "T1087/T1482/T1033 Discovery", strength: "weak",
    test: /(nltest(\.exe)?\s+\/(domain_trusts|dclist)|net1?(\.exe)?\s+group\s+"?(domain admins|enterprise admins)|whoami(\.exe)?\s+\/(all|priv|groups)|\bnet1?(\.exe)?\s+(view|session)\b|\bdsquery\b|\badfind\b)/,
    statement: "Account, group or domain-trust discovery commands are run." },
  // ================= Linux / Unix (patterns from GTFOBins and common intrusion tradecraft)
  { id: "unix_pipe_to_shell", technique: "T1059.004 Unix Shell / T1105 Ingress Tool Transfer", strength: "strong",
    test: /\b(curl|wget|fetch)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?python[23]?\b/,
    statement: "A script is downloaded and piped straight into a shell, so it runs without ever being saved or reviewed." },
  { id: "unix_reverse_shell", technique: "T1059.004 Unix Shell (reverse shell)", strength: "strong",
    test: /\/dev\/(tcp|udp)\/|\bnc(at)?\b.*\s-(e|c)\s|mkfifo\b.*\bnc\b|\bsocat\b.*exec:|python[23]?\b.*socket.*(subprocess|pty\.spawn|os\.dup2)|\bperl\b.*socket.*exec|\bphp\b.*fsockopen|\bruby\b.*tcpsocket/,
    statement: "A reverse shell connects this machine's command shell to a remote address, giving someone interactive control." },
  { id: "unix_base64_exec", technique: "T1140 Deobfuscate/Decode / T1059.004", strength: "strong",
    test: /base64\s+(-d|--decode)\b[^;]*\|\s*(sudo\s+)?(ba|z)?sh\b|\becho\s+["']?[a-z0-9+/=]{40,}["']?\s*\|\s*base64\s+(-d|--decode)/,
    statement: "Base64-encoded content is decoded and run, hiding what the command does." },
  { id: "unix_tmp_exec", technique: "T1059.004 / T1036 Masquerading (temp execution)", strength: "moderate",
    test: /chmod\s+(\+x|[0-7]*[1357][0-7]*)\s+["']?\/(tmp|dev\/shm|var\/tmp|run\/user\/\d+)\/|(^|[\s;&|])(\/tmp|\/dev\/shm|\/var\/tmp)\/\.?[a-z0-9._-]+(\s|$)|(^|[\s;&|])\.\/[a-z0-9._-]+\s*(&|$)/,
    statement: "A program is made executable in, or run from, a temporary folder such as /tmp or /dev/shm." },
  { id: "unix_cron_payload", technique: "T1053.003 Cron", strength: "strong",
    test: /crontab\b|\/etc\/cron|\/var\/spool\/cron|\/etc\/crontab/, also: /(curl|wget|base64|\/dev\/tcp|\/tmp\/|\/dev\/shm\/|nc\s)/,
    statement: "A cron job is created that downloads, decodes or runs code from a temporary folder." },
  { id: "unix_cron", technique: "T1053.003 Cron", strength: "moderate",
    test: /crontab\s+(-\s*$|\/|-l\s*\|)|(echo|printf)\b.*>+\s*\/(etc\/cron|var\/spool\/cron)|>+\s*\/etc\/crontab/,
    statement: "A cron job is written from the command line." },
  { id: "unix_systemd_persist", technique: "T1543.002 Systemd Service", strength: "moderate",
    test: /systemctl\s+(enable|daemon-reload|start)|\/(etc|lib)\/systemd\/system\/[^\s]+\.(service|timer)/, also: /(\/tmp\/|\/dev\/shm\/|curl|wget|base64|\/dev\/tcp|>+\s*\/(etc|lib)\/systemd)/,
    statement: "A systemd service or timer is created or enabled that points at a download, encoded content or a temporary folder." },
  { id: "unix_ssh_keys", technique: "T1098.004 SSH Authorized Keys", strength: "strong",
    test: />+\s*["']?[^\s]*\.ssh\/authorized_keys|\btee\s+(-a\s+)?[^\s]*\.ssh\/authorized_keys|ssh-copy-id\b.*root@/,
    statement: "An SSH key is added to authorized_keys, giving someone a password-less way back in." },
  { id: "unix_ld_preload_file", technique: "T1574.006 Dynamic Linker Hijacking", strength: "strong",
    test: /\/etc\/ld\.so\.preload/, statement: "/etc/ld.so.preload is written, which forces a library into every program (a rootkit technique)." },
  { id: "unix_ld_preload_env", technique: "T1574.006 Dynamic Linker Hijacking", strength: "moderate",
    test: /\bld_preload=[^\s]*\/(tmp|dev\/shm|var\/tmp|home)\//, statement: "A program is started with LD_PRELOAD pointing at a library in a temporary or home folder." },
  { id: "unix_history_wipe", technique: "T1070.003 Clear Command History", strength: "moderate",
    test: /history\s+-c\b|unset\s+histfile|histfile=\/dev\/null|export\s+histsize=0|rm\s+(-[a-z]+\s+)?[^\s]*\.(bash|zsh|sh)_history|>\s*[^\s]*\.(bash|zsh)_history/,
    statement: "Shell command history is cleared or disabled." },
  { id: "unix_log_wipe", technique: "T1070.002 Clear Linux or Mac System Logs", strength: "strong",
    test: /(rm|shred|truncate|unlink)\b.*\/var\/log\/(auth|secure|syslog|messages|wtmp|btmp|lastlog|audit)|>\s*\/var\/log\/(auth|secure|wtmp|btmp|lastlog)|journalctl\s+--(vacuum|rotate)/,
    statement: "System or authentication logs are deleted or emptied." },
  { id: "unix_defense_off", technique: "T1562.001/.004 Impair Defenses", strength: "strong",
    test: /setenforce\s+0|systemctl\s+(stop|disable|mask)\s+(auditd|apparmor|falcon-sensor|wazuh-agent|osqueryd|mdatp|firewalld|ufw|sentinelone|cbagentd|elastic-agent)|\bufw\s+disable|iptables\s+-f\b|service\s+(auditd|apparmor)\s+stop|auditctl\s+-e\s*0/,
    statement: "Security monitoring (auditd, SELinux/AppArmor, EDR agent) or the firewall is stopped or disabled." },
  { id: "unix_shadow", technique: "T1003.008 /etc/passwd and /etc/shadow", strength: "strong",
    test: /\b(cat|cp|less|more|head|tail|base64|tar|scp|curl)\b[^|;]*\/etc\/shadow|\bunshadow\b|\/etc\/security\/opasswd/,
    statement: "The password hash file /etc/shadow is read or copied." },
  { id: "unix_priv_account", technique: "T1136.001 Local Account / T1548.003 Sudo", strength: "strong",
    test: /usermod\s+.*-a?g\s*["']?(sudo|wheel|root|admin)\b|\b(useradd|adduser|usermod)\b[^|;]*\s-u\s*0\b|(echo|printf|tee)\b.*(>>?\s*|\s)\/etc\/(sudoers|passwd)\b|\bnopasswd:\s*all/,
    statement: "An account is given sudo/root rights or the sudoers/passwd file is edited from the command line." },
  { id: "unix_useradd", technique: "T1136.001 Local Account", strength: "weak",
    test: /\b(useradd|adduser)\s+/, statement: "A local user account is created." },
  { id: "unix_setuid", technique: "T1548.001 Setuid and Setgid", strength: "moderate",
    test: /chmod\s+([ugo]*\+s|[2467][0-7]{3})\s/, statement: "A file is given setuid/setgid permissions, so it runs with its owner's (often root's) rights." },
  { id: "unix_miner", technique: "T1496 Resource Hijacking (crypto-mining)", strength: "strong",
    test: /\b(xmrig|minerd|cpuminer|xmr-stak|nbminer|t-rex)\b|stratum\+(tcp|ssl|tls):\/\/|--donate-level|\brandomx\b|cryptonight/,
    statement: "A crypto-miner or mining-pool connection is started." },
  { id: "unix_kmod", technique: "T1547.006 Kernel Modules", strength: "strong",
    test: /\b(insmod|modprobe)\s+[^\s]*\/(tmp|dev\/shm|var\/tmp|home)\//, statement: "A kernel module is loaded from a temporary or home folder (rootkit behaviour)." },
  { id: "container_escape", technique: "T1611 Escape to Host", strength: "strong",
    test: /docker\s+run\b.*(--privileged|-v\s+["']?\/:\/|--pid[= ]host)|\bnsenter\s+.*(-t\s*1\b|--target\s+1\b)|\bchroot\s+\/host\b/,
    statement: "A container is started with host-level access (privileged, host root mounted, or host PID namespace), a container-escape technique." },
  { id: "tunnel_tool", technique: "T1572 Protocol Tunneling", strength: "moderate",
    test: /\bssh\b[^|;]*\s-[a-z]*[rdl]\s*\d+|\bssh\b.*-o\s*["']?proxycommand|\bchisel\s+(client|server)|\bngrok\s+(tcp|http)|\bfrpc\b|\bgost\s+-l/,
    statement: "A tunnel is opened (SSH port forwarding, chisel, ngrok, frp) that can expose internal services or hide traffic." },
  { id: "unix_discovery", technique: "T1082/T1087 Discovery", strength: "weak",
    test: /\bcat\s+\/etc\/passwd\b|\buname\s+-a\b|find\s+\/\s+.*-perm\s+-?[u/]?[4+]000|getent\s+passwd|\bsudo\s+-l\b|\b(ss|netstat)\s+-[a-z]*p/,
    statement: "System, account or privilege discovery commands are run." },
  // ================= macOS (patterns from LOOBins and macOS malware such as info-stealers)
  { id: "mac_password_prompt", technique: "T1056.002 GUI Input Capture", strength: "strong",
    test: /osascript\b.*(with hidden answer|display dialog.*password|password.*display dialog)/,
    statement: "osascript shows a fake dialog asking for the user's password, the hallmark of macOS info-stealers." },
  { id: "mac_quarantine_strip", technique: "T1553.001 Gatekeeper Bypass", strength: "moderate",
    test: /\bxattr\s+(-[a-z]*[dc][a-z]*\s+)?(-[a-z]*\s+)*com\.apple\.quarantine|\bxattr\s+-[a-z]*c[a-z]*\s/,
    statement: "The quarantine flag is removed from a downloaded file so Gatekeeper does not check it." },
  { id: "mac_gatekeeper_off", technique: "T1553 Subvert Trust Controls", strength: "strong",
    test: /spctl\s+--(master|global)-disable|csrutil\s+disable|lsquarantine\s+-bool\s+(no|false)/,
    statement: "Gatekeeper, System Integrity Protection or quarantine checks are turned off." },
  { id: "mac_keychain_dump", technique: "T1555.001 Keychain", strength: "strong",
    test: /\bsecurity\s+(dump-keychain|export)\b|\bchainbreaker\b|cp\b.*login\.keychain(-db)?/,
    statement: "The macOS keychain (saved passwords and keys) is dumped or copied." },
  { id: "mac_keychain_read", technique: "T1555.001 Keychain", strength: "moderate",
    test: /\bsecurity\s+find-(generic|internet)-password\b/, statement: "A password is read from the macOS keychain from the command line." },
  { id: "mac_launch_persist", technique: "T1543.001 Launch Agent / T1543.004 Launch Daemon", strength: "moderate",
    test: /launchctl\s+(load|bootstrap|submit)\b|\b(cp|mv|tee|cat|echo|plutil)\b.*library\/(launchagents|launchdaemons)\/[^\s]+\.plist/, also: /(\/tmp\/|\/users\/shared\/|\/private\/tmp|launchagents|launchdaemons)/,
    statement: "A LaunchAgent or LaunchDaemon is installed or loaded, which starts a program automatically at login or boot." },
  { id: "mac_login_hook", technique: "T1037.002 Login Hook", strength: "strong",
    test: /defaults\s+write\s+com\.apple\.loginwindow\s+(loginhook|logouthook)/, statement: "A login or logout hook is set, which runs a script as root at every login." },
  { id: "mac_tcc", technique: "T1548.006 TCC Manipulation", strength: "strong",
    test: /\btccutil\s+reset|sqlite3\b.*tcc\.db|com\.apple\.tcc\/tcc\.db/, statement: "The privacy-permission database (TCC) is reset or edited, which can grant silent access to files, camera or screen." },
  { id: "mac_admin_account", technique: "T1136.001 Local Account", strength: "strong",
    test: /dscl\s+\.\s+-(create|append)\s+\/(groups\/admin|users\/)|dseditgroup\s+-o\s+edit\s+-a\s+\S+\s+-t\s+user\s+admin|sysadminctl\s+-adduser/,
    statement: "A macOS account is created or added to the admin group from the command line." },
  { id: "mac_jxa", technique: "T1059.002 AppleScript / JXA", strength: "moderate",
    test: /osascript\s+-l\s+javascript|objc\.import|osascript\b.*do shell script/, statement: "AppleScript or JavaScript-for-Automation runs shell commands or native APIs." },
  { id: "mac_screen_capture", technique: "T1113 Screen Capture", strength: "moderate",
    test: /\bscreencapture\s+-[a-z]*x/, statement: "The screen is captured silently (screencapture -x)." },
  { id: "unix_hidden_payload", technique: "T1564.001 Hidden Files", strength: "moderate",
    test: /(\/users\/shared|\/private\/tmp|\/tmp|\/dev\/shm|\/var\/tmp)\/\.[a-z0-9_-]{2,}/, statement: "A hidden (dot-named) file in a shared or temporary folder is created or run." },
  // --- obfuscation in cmd itself (checked on the raw line, before carets are stripped)
];

function normalise(cmd: string): string {
  return cmd.toLowerCase().replace(/\^/g, "").replace(/""/g, "").replace(/\s+/g, " ").trim();
}
function basename(path: string): string {
  const clean = path.trim().replace(/^["']|["']$/g, "");
  const base = clean.split(/[\\/]/).pop() ?? clean;
  return base.toLowerCase();
}
function firstBinary(cmd: string): { path: string; name: string } {
  const m = cmd.trim().match(/^"([^"]+)"|^(\S+)/);
  const path = (m?.[1] ?? m?.[2] ?? "").trim();
  let name = basename(path);
  if (name && !name.includes(".")) name += ".exe";
  return { path, name };
}
function trim(text: string, n = 220): string {
  const t = text.replace(/\s+/g, " ").trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
}

/** Decode `powershell -enc <base64>` (UTF-16LE). Returns the decoded script or null. */
export function decodePowerShell(cmd: string): string | null {
  const m = cmd.match(/(?:powershell|pwsh)(?:\.exe)?\b.*?\s[-/]e(?:c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedcommand)?\s+["']?([A-Za-z0-9+/=]{16,})/i);
  if (!m?.[1]) return null;
  try {
    const decoded = Buffer.from(m[1], "base64").toString("utf16le");
    const printable = [...decoded].filter((c) => c >= " " || c === "\n" || c === "\r" || c === "\t").length;
    return decoded.length > 3 && printable / decoded.length > 0.9 ? decoded : null;
  } catch {
    return null;
  }
}

/** Lines in the raw alert that look like command lines (used when no command-line field was found). */
export function commandLinesFromText(raw: string): string[] {
  const names = [...Object.keys(LOLBINS).map((n) => n.replace(".exe", "")), ...UNIX_TOOLS].join("|");
  const re = new RegExp(String.raw`(?:^|[\s"'=:>$#])((?:[a-z]:\\[^\s"]*\\|\/[^\s"]*\/)?(?:${names})(?:\.exe)?(?=[\s"',]|$).*)$`, "i");
  const out: string[] = [];
  for (const line of raw.split(/\r?\n|\\n/)) {
    const m = line.match(re);
    if (!m?.[1] || m[1].trim().length <= 3) continue;
    // Unix tool names are also ordinary words ("docker", "bash"), so for them require something that looks like arguments.
    const bin = (m[1].match(/^(?:[a-z]:\\[^\s"]*\\|\/[^\s"]*\/)?([a-z0-9_.-]+)/i)?.[1] ?? "").toLowerCase().replace(/\.exe$/, "");
    if (UNIX_TOOLS.includes(bin) && !LOLBINS[`${bin}.exe`] && !/\s-{1,2}[a-z]|\s\/|\||>/i.test(m[1])) continue;
    out.push(m[1].replace(/["',}\]]+$/, "").trim());
  }
  return [...new Set(out)].slice(0, 20);
}

export function analyzeBehaviors(commandlines: string[], parents: string[], processes: string[], files: FileRecord[] = []): Behavior[] {
  const found = new Map<string, Behavior>();
  const add = (b: Behavior) => { if (!found.has(b.id)) found.set(b.id, b); };
  const lolbinsSeen = new Set<string>();

  const scan = (cmdRaw: string, origin: string) => {
    const cmd = normalise(cmdRaw);
    const carets = (cmdRaw.match(/\^/g) ?? []).length;
    if (carets >= 3 || /%[a-z]+:~-?\d+(,-?\d+)?%/i.test(cmdRaw)) {
      add({ id: "cmd_obfuscation", technique: "T1027.010 Command Obfuscation", strength: "moderate",
        statement: "The command line is obfuscated with caret escapes or environment-variable substrings to evade detection.", evidence: trim(cmdRaw) });
    }
    for (const bin of Object.keys(LOLBINS)) {
      const stem = bin.replace(/\.exe$/, "");
      if (new RegExp(String.raw`(^|[\\/\s"'])${stem}(\.exe)?(?=[\s"',]|$)`).test(cmd)) lolbinsSeen.add(bin);
    }
    for (const rule of RULES) {
      if (rule.test.test(cmd) && (!rule.also || rule.also.test(cmd)) && (!rule.unless || !rule.unless.test(cmd))) {
        add({ id: rule.id, technique: rule.technique, strength: rule.strength, statement: rule.statement, evidence: trim(origin ? `${origin}: ${cmdRaw}` : cmdRaw) });
      }
    }
  };

  for (const raw of commandlines) {
    scan(raw, "");
    const decoded = decodePowerShell(raw);
    if (decoded) {
      add({ id: "ps_decoded", technique: "T1027 Obfuscated Files (decoded)", strength: "weak",
        statement: `Decoded PowerShell command: ${trim(decoded, 300)}`, evidence: trim(decoded, 400) });
      scan(`powershell ${decoded}`, "decoded PowerShell");
    }
    // Masquerading: a system executable name running from outside the Windows system folders.
    const { path, name } = firstBinary(raw);
    if (SYSTEM_NAMES.test(name) && path.includes("\\") && !/\\windows\\(system32|syswow64|winsxs)\\|\\windows\\explorer\.exe/i.test(path)) {
      add({ id: "masquerade_path", technique: "T1036.005 Masquerading", strength: "strong",
        statement: `${name} is running from ${trim(path, 120)}, not from the Windows system folder: a program disguised as a system executable.`, evidence: trim(raw) });
    }
  }
  for (const p of processes) {
    const name = basename(p);
    if (SYSTEM_NAMES.test(name) && p.includes("\\") && !/\\windows\\(system32|syswow64|winsxs)\\|\\windows\\explorer\.exe/i.test(p)) {
      add({ id: "masquerade_path", technique: "T1036.005 Masquerading", strength: "strong",
        statement: `${name} is running from ${trim(p, 120)}, not from the Windows system folder: a program disguised as a system executable.`, evidence: trim(p) });
    }
  }

  // Linux/macOS: a network-facing service starting a shell or download tool is how web shells and exploited services look.
  const unixChildren = commandlines.map((c) => (c.trim().split(/\s+/)[0] ?? "").replace(/^["']|["']$/g, "").split("/").pop()?.toLowerCase() ?? "").concat(processes.filter((p) => p.includes("/")).map((p) => p.split("/").pop()?.toLowerCase() ?? ""));
  for (const parentRaw of parents) {
    const parentBin = (parentRaw.trim().split(/\s+/)[0] ?? "").split("/").pop()?.toLowerCase() ?? "";
    const child = unixChildren.find((c) => UNIX_SHELLISH.test(c));
    if (UNIX_SERVICES.test(parentBin) && child) add({ id: "unix_service_spawns_shell", technique: "T1505.003 Web Shell / T1190 Exploit Public-Facing Application", strength: "strong",
      statement: `${parentBin} (a network-facing service) started ${child}. Web and database servers do not normally start shells or download tools; this is how web shells and exploited services look.`, evidence: `${parentRaw} -> ${child}` });
  }

  // Parent -> child relationships.
  const children = new Set<string>([...processes.map(basename), ...commandlines.map((c) => firstBinary(c).name)].filter(Boolean));
  for (const c of commandlines) for (const m of normalise(c).matchAll(/\b(powershell|pwsh|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin|csc|vbc|jsc)(\.exe)?\b/g)) children.add(`${m[1]}.exe`);
  for (const parentRaw of parents) {
    // Paths may contain spaces ("C:\\Program Files\\...\\WINWORD.EXE"), so find the executable name rather than splitting on spaces.
    const exe = parentRaw.match(/([^\\/"]+?\.exe)\b/i)?.[1];
    const parent = (exe ?? basename(parentRaw.split(/\s/)[0] ?? parentRaw)).trim().toLowerCase();
    const parentName = parent.endsWith(".exe") ? parent : `${parent}.exe`;
    const child = [...children].find((c) => SCRIPTY.test(c));
    if (!child) continue;
    if (OFFICE.test(parentName)) add({ id: "office_spawns_shell", technique: "T1204.002 Malicious File / T1566.001 Phishing Attachment", strength: "strong",
      statement: `${parentName} (an Office or PDF application) started ${child}. Documents do not normally launch shells or proxy tools; this is how macro and exploit payloads run.`, evidence: `${parentRaw} -> ${child}` });
    else if (WEBSERVER.test(parentName) && /^(cmd|powershell|pwsh|certutil|bitsadmin|wscript|cscript)\.exe$/.test(child)) add({ id: "webserver_spawns_shell", technique: "T1505.003 Web Shell", strength: "strong",
      statement: `${parentName} (a web or database server executable) started ${child}, the typical sign of a web shell or server exploitation.`, evidence: `${parentRaw} -> ${child}` });
    else if (BROWSER.test(parentName) && /^(mshta|wscript|cscript|rundll32|regsvr32|powershell|pwsh)\.exe$/.test(child)) add({ id: "browser_spawns_script", technique: "T1204 User Execution", strength: "moderate",
      statement: `${parentName} started ${child}, which suggests a downloaded file or drive-by payload was run.`, evidence: `${parentRaw} -> ${child}` });
    if ([...children].some((c) => /^(csc|vbc|jsc)\.exe$/.test(c)) && (OFFICE.test(parentName) || /^(wscript|cscript|mshta|rundll32|regsvr32)\.exe$/.test(parentName))) add({ id: "compile_after_delivery", technique: "T1127 Trusted Developer Utilities / T1027.004 Compile After Delivery", strength: "moderate",
      statement: `${parentName} started a .NET compiler. Documents and script hosts compiling code on the fly is a way to build a payload on the victim machine.`, evidence: `${parentRaw} -> compiler` });
    if (parentName === "wmiprvse.exe" && /^(powershell|pwsh|cmd|rundll32|mshta)\.exe$/.test(child)) add({ id: "wmi_spawns_shell", technique: "T1047 WMI", strength: "moderate",
      statement: `WMI (wmiprvse.exe) started ${child}, which is how remote WMI execution appears on the target.`, evidence: `${parentRaw} -> ${child}` });
  }

  // Files created or written (Sysmon FileCreate, EDR file events).
  for (const file of files) {
    const path = file.path.trim(); const name = basename(path); const shown = path.split(/[\\/]/).pop() ?? name;
    if (!name || SYSTEM_DIR.test(path)) continue;
    const entropyNote = typeof file.entropy === "number" ? ` Its entropy is ${file.entropy.toFixed(2)} of 8${file.entropy >= 7.2 ? ", typical of packed or encrypted code" : ""}.` : "";
    if (SIDELOAD_DLLS.has(name) && USER_WRITABLE.test(path)) {
      add({ id: `sideload_dll:${name}`, technique: "T1574.002 DLL Side-Loading", strength: (file.entropy ?? 0) >= 7.2 ? "strong" : "moderate",
        statement: `A DLL named ${shown} (a Windows system library name commonly abused for side-loading) was written to ${trim(path, 140)}, outside the Windows system folder. A program in that folder may load it instead of the real library.${entropyNote}`, evidence: trim(`${file.operation ?? "file"}: ${path}`) });
      continue;
    }
    if (/\.(exe|scr|com)$/.test(name) && (CRITICAL_NAMES.has(name) || COMPONENT_NAMES.has(name))) {
      add({ id: `masquerade_file:${name}`, technique: "T1036.005 Masquerading (file name)", strength: CRITICAL_NAMES.has(name) ? "strong" : "moderate",
        statement: `An executable named ${shown}, the name of a Windows ${CRITICAL_NAMES.has(name) ? "core or security " : ""}component, was created at ${trim(path, 140)}, outside the Windows system folders. Programs named like system components are a common disguise.${entropyNote}`, evidence: trim(`${file.operation ?? "file"}: ${path}`) });
      continue;
    }
    if (/\.(exe|dll|scr|sys|cpl|ocx)$/.test(name) && (file.entropy ?? 0) >= 7.2 && USER_WRITABLE.test(path)) {
      add({ id: `packed_binary:${name}`, technique: "T1027.002 Software Packing", strength: "moderate",
        statement: `An executable file ${shown} with entropy ${file.entropy?.toFixed(2)} of 8 (packed or encrypted) was written to a user-writable folder: ${trim(path, 140)}.`, evidence: trim(`${file.operation ?? "file"}: ${path}`) });
    }
  }

  // Tell Jev which built-in tools are involved and what they are normally for (reputation will be clean).
  const out = [...found.values()];
  for (const bin of lolbinsSeen) {
    out.push({ id: `lolbin_present:${bin}`, technique: "context", strength: "weak",
      statement: `${bin} is a built-in, Microsoft-signed Windows tool (normally ${LOLBINS[bin]}). Its clean reputation is expected and says nothing about whether this use is malicious; judge it by what the command does.`, evidence: bin });
  }
  const rank: Record<Strength, number> = { strong: 0, moderate: 1, weak: 2 };
  return out.sort((a, b) => rank[a.strength] - rank[b.strength]).slice(0, 25);
}

export function isLolbinName(name: string | null | undefined): string | null {
  if (!name) return null;
  const base = basename(name);
  const withExe = base.endsWith(".exe") ? base : `${base}.exe`;
  return LOLBINS[withExe] ? withExe : null;
}
