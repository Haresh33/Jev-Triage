/**
 * Turn an uploaded alert file into text. Same rules as the original Python extractor:
 *  - text files are read as UTF-8 / UTF-16 / Latin-1; binaries (PCAP, executables) are refused
 *  - ZIP archives are opened, including password-protected ones ("infected" is always tried)
 *  - nested ZIPs up to 2 levels, at most 200 entries, 16 MB per member, 32 MB expanded, 24,000 characters kept
 * Nothing in an archive is ever executed or written to disk.
 */

import { configure, Uint8ArrayReader, Uint8ArrayWriter, ZipReader, type Entry } from "@zip.js/zip.js";
import type { ExtractResult } from "./platform";

configure({ useWebWorkers: false });

const MAX_CHARS = 24_000;
const MAX_ZIP_DEPTH = 2;
const MAX_ENTRIES = 200;
const MAX_MEMBER_BYTES = 16 * 1024 * 1024;
const MAX_EXPANDED_BYTES = 32 * 1024 * 1024;

type Manifest = Array<{ name: string; status: string; characters?: number }>;

function isZip(bytes: Uint8Array): boolean { return bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04; }
function hasUtf16Bom(b: Uint8Array): boolean { return (b[0] === 0xff && b[1] === 0xfe) || (b[0] === 0xfe && b[1] === 0xff); }

type Label = ConstructorParameters<typeof TextDecoder>[0];
const decoder = (label: string, fatal = false) => new TextDecoder(label as Label, { fatal });

export function decodeText(bytes: Uint8Array): string {
  if (hasUtf16Bom(bytes)) return decoder(bytes[0] === 0xff ? "utf-16le" : "utf-16be").decode(bytes.subarray(2));
  try { return decoder("utf-8", true).decode(bytes).replace(/^\uFEFF/, ""); } catch { return decoder("latin1").decode(bytes); }
}

export function looksText(bytes: Uint8Array): boolean {
  const sample = bytes.subarray(0, 65_536);
  if (!sample.length) return false;
  if (hasUtf16Bom(sample)) return true;
  if (sample.includes(0)) return false;
  const text = decodeText(sample);
  let printable = 0;
  for (const ch of text) if (ch === "\n" || ch === "\r" || ch === "\t" || !/[\p{Cc}\p{Cs}\p{Co}\p{Cn}]/u.test(ch)) printable += 1;
  return printable / Math.max(text.length, 1) > 0.72;
}

async function openZip(bytes: Uint8Array, passwords: string[]): Promise<{ entries: Entry[]; password?: string; protectedZip: boolean } | null> {
  let entries: Entry[];
  try { entries = await new ZipReader(new Uint8ArrayReader(bytes)).getEntries(); } catch { return null; }
  const first = entries.find((e) => !e.directory);
  if (!first || !first.encrypted) return { entries, protectedZip: false };
  for (const password of passwords) {
    try {
      if (first.getData) await first.getData(new Uint8ArrayWriter(), { password, checkSignature: true });
      return { entries, password, protectedZip: true };
    } catch { /* wrong password: try the next */ }
  }
  return null;
}

export async function extractAlertFile(bytes: Uint8Array, label: string, providedPassword?: string): Promise<ExtractResult> {
  const manifest: Manifest = [];
  const parts: string[] = [];
  const state = { budget: MAX_CHARS, expanded: 0, entries: 0, truncated: false };
  const passwords = [...new Set([providedPassword, "infected"].filter((p): p is string => !!p))];

  async function unpack(data: Uint8Array, depth: number, prefix = ""): Promise<boolean> {
    const zip = await openZip(data, passwords);
    if (!zip) { manifest.push({ name: prefix || "(archive)", status: "unreadable (bad ZIP or wrong password)" }); return false; }
    if (zip.protectedZip) manifest.push({ name: prefix || "(archive)", status: "password-protected (unlocked)" });
    for (const entry of zip.entries) {
      if (entry.directory) continue;
      state.entries += 1;
      const name = prefix + entry.filename;
      if (state.entries > MAX_ENTRIES) { manifest.push({ name, status: "skipped (archive entry limit reached)" }); state.truncated = true; break; }
      if (entry.uncompressedSize > MAX_MEMBER_BYTES || state.expanded + entry.uncompressedSize > MAX_EXPANDED_BYTES) { manifest.push({ name, status: "skipped (expanded size limit)" }); state.truncated = true; continue; }
      let raw: Uint8Array;
      try {
        if (!entry.getData) throw new Error("no data");
        raw = await entry.getData(new Uint8ArrayWriter(), { password: zip.password, checkSignature: true });
        state.expanded += raw.byteLength;
      } catch { manifest.push({ name, status: "read error" }); continue; }
      if ((name.toLowerCase().endsWith(".zip") || isZip(raw)) && depth < MAX_ZIP_DEPTH) { manifest.push({ name, status: "nested ZIP, unpacked" }); await unpack(raw, depth + 1, `${name}!`); continue; }
      if (!looksText(raw)) { manifest.push({ name, status: "binary skipped" }); continue; }
      if (state.budget <= 0) { manifest.push({ name, status: "skipped (text limit reached)" }); state.truncated = true; continue; }
      const text = decodeText(raw);
      const kept = text.slice(0, state.budget);
      if (kept.length < text.length) state.truncated = true;
      state.budget -= kept.length;
      manifest.push({ name, status: "extracted", characters: kept.length });
      parts.push(`--- file: ${name} ---\n${kept}`);
    }
    return true;
  }

  if (label.toLowerCase().endsWith(".zip") || isZip(bytes)) {
    const opened = await unpack(bytes, 0);
    if (!parts.length) {
      const error = opened ? "No readable alert text was found. This agent triages alert text, not packet captures or other binary files." : "Couldn’t open this ZIP. Enter its password and try again; ‘infected’ is tried automatically.";
      return { ok: false, text: "", manifestJson: JSON.stringify(manifest), kind: "zip archive", truncated: state.truncated, error };
    }
    return { ok: true, text: parts.join("\n\n"), manifestJson: JSON.stringify(manifest), kind: "zip archive", truncated: state.truncated, error: null };
  }
  if (looksText(bytes)) {
    const text = decodeText(bytes);
    const kept = text.slice(0, MAX_CHARS);
    manifest.push({ name: label, status: "extracted", characters: kept.length });
    return { ok: true, text: kept, manifestJson: JSON.stringify(manifest), kind: "text file", truncated: kept.length < text.length, error: null };
  }
  return { ok: false, text: "", manifestJson: JSON.stringify([{ name: label, status: "binary rejected" }]), kind: "binary", truncated: false, error: "This file is binary. Alert Triage handles alert text, not packet captures such as PCAP files." };
}
