/**
 * Display-only defanging of indicators, so phones and browsers never turn them into tappable links.
 *
 *   https://evil.com/a.zip  ->  hxxps://evil[.]com/a[.]zip
 *   www.evil.com            ->  www[.]evil[.]com
 *   185.220.101.45          ->  185[.]220[.]101[.]45
 *   user@corp.com           ->  user[@]corp[.]com
 *
 * Only what is shown on screen changes. Stored results, lookups and Jev's state keep the real values.
 * File names (powershell.exe, comsvcs.dll, security.hive), versions (4.0.30319), ATT&CK IDs (T1003.002)
 * and probabilities are left as they are.
 */

// Endings that are file types rather than internet domains. Endings that are BOTH (.zip, .mov, .app)
// are deliberately not listed: a phone would link them, so they get defanged.
const FILE_ENDINGS = new Set(
  ("exe dll sys drv ocx cpl scr msi lnk ps1 psm1 psd1 bat cmd vbs vbe js jse wsf wsh hta jar py pyc sh bash " +
    "php asp aspx jsp html htm xml xsl sct inf ini cfg conf config yaml yml json txt log csv tsv dat db sqlite " +
    "tmp bak old reg hive evtx etl pem crt cer pfx key pub gz tgz tar rar 7z cab iso img vhd vhdx dmg pkg deb rpm " +
    "pdf doc docx docm dot dotm xls xlsx xlsm ppt pptx pptm rtf one msg eml png jpg jpeg gif bmp svg webp ico " +
    "mp3 mp4 wav avi mkv so dylib ko plist kext o a lib class war ear nupkg whl gem lock md rst c cpp h cs go rb rs " +
    "local internal corp lan home localdomain").split(" "),
);

const URL_RE = /\b(h)(ttps?)(:\/\/)([^\s<>"'`]+)/gi;
const EMAIL_RE = /\b([a-z0-9._%+-]+)@((?:[a-z0-9-]+\.)+[a-z]{2,24})\b/gi;
const IPV4_RE = /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z][a-z0-9-]{1,23})\b/gi;

const bracketDots = (s: string) => s.replace(/\./g, "[.]");

export function defang(value: string | null | undefined): string {
  if (!value) return value ?? "";
  let text = String(value);
  // 1. URLs: break the scheme and every dot in the host and path.
  text = text.replace(URL_RE, (_m, _h, rest: string, sep: string, tail: string) => `hxx${rest.slice(2)}${sep}${bracketDots(tail)}`);
  // 2. Email addresses.
  text = text.replace(EMAIL_RE, (_m, user: string, domain: string) => `${user}[@]${bracketDots(domain)}`);
  // 3. IPv4 addresses (all four octets, so 4.0.30319 and 0.85 are untouched).
  text = text.replace(IPV4_RE, (ip) => bracketDots(ip));
  // 4. Bare domains, skipping file names and anything already defanged.
  text = text.replace(DOMAIN_RE, (match: string, ending: string, offset: number, whole: string) => {
    if (FILE_ENDINGS.has(ending.toLowerCase())) return match;
    if (whole[offset - 1] === "[" || whole.slice(offset + match.length, offset + match.length + 1) === "]") return match;
    if (/^v?\d+(\.\d+)*$/i.test(match)) return match;
    return bracketDots(match);
  });
  return text;
}
