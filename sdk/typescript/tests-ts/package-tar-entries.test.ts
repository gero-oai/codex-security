import { describe, expect, test } from "bun:test";

type PlainTarEntry = {
  path: string;
  size: number;
};

type PackageTarEntries = {
  plainTarEntries: (archiveBytes: Buffer) => PlainTarEntry[];
};

const { plainTarEntries } = (await import(
  new URL("../scripts/package-tar-entries.mjs", import.meta.url).href
)) as PackageTarEntries;

const blockSize = 512;
const invalidTarEntryError = "npm tarball contains an invalid tar entry.";
const internalReferenceError = "npm tarball contains an internal reference.";

function octal(value: number, width: number, terminator = "\0"): Buffer {
  return Buffer.from(
    value.toString(8).padStart(width - terminator.length, "0") + terminator,
  );
}

function tarHeader({
  name,
  prefix = "",
  size = 0,
  type = 0x30,
  sizeField = octal(size, 12, " "),
  magic = "ustar\0",
  version = "00",
  user = "",
  deviceNumbers = Buffer.alloc(16),
  reserved = Buffer.alloc(12),
}: {
  name: string;
  prefix?: string;
  size?: number;
  type?: number;
  sizeField?: Buffer;
  magic?: string;
  version?: string;
  user?: string;
  deviceNumbers?: Buffer;
  reserved?: Buffer;
}): Buffer {
  const header = Buffer.alloc(blockSize);
  header.write(name, 0, 100, "utf8");
  octal(0o644, 8).copy(header, 100);
  octal(0, 8).copy(header, 108);
  octal(0, 8).copy(header, 116);
  sizeField.copy(header, 124);
  octal(0, 12).copy(header, 136);
  header.fill(0x20, 148, 156);
  header[156] = type;
  header.write(magic, 257, "binary");
  header.write(version, 263, "binary");
  header.write(user, 265, 32, "utf8");
  deviceNumbers.copy(header, 329, 0, 16);
  header.write(prefix, 345, 155, "utf8");
  reserved.copy(header, 500, 0, 12);
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  Buffer.from(checksum.toString(8).padStart(6, "0") + "\0 ").copy(header, 148);
  return header;
}

function tarRecord(
  contents: Buffer,
  options: Omit<Parameters<typeof tarHeader>[0], "size">,
): Buffer {
  return Buffer.concat([
    tarHeader({ ...options, size: contents.length }),
    contents,
    Buffer.alloc(
      Math.ceil(contents.length / blockSize) * blockSize - contents.length,
    ),
  ]);
}

function archive(...records: Buffer[]): Buffer {
  return Buffer.concat([...records, Buffer.alloc(blockSize * 2)]);
}

describe("plain npm tar entries", () => {
  test("accepts canonical ustar files and prefix paths", () => {
    const prefix = `package/${"nested/".repeat(13)}deep`;
    const longPath = `${prefix}/README.md`;
    expect(longPath.length).toBeGreaterThan(100);

    const bytes = archive(
      tarRecord(Buffer.from("license"), { name: "package/LICENSE" }),
      tarRecord(Buffer.from("readme"), { name: "README.md", prefix }),
    );

    expect(plainTarEntries(bytes)).toEqual([
      { path: "package/LICENSE", size: 7 },
      { path: longPath, size: 6 },
    ]);
  });

  test("rejects every unsupported tar entry type", () => {
    for (const type of [
      0, 0x31, 0x32, 0x35, 0x44, 0x4b, 0x4c, 0x53, 0x67, 0x78,
    ]) {
      expect(() =>
        plainTarEntries(
          archive(
            tarRecord(Buffer.from("x"), {
              name: "package/README.md",
              type,
            }),
          ),
        ),
      ).toThrow(invalidTarEntryError);
    }
  });

  test("rejects alternate size encodings", () => {
    const base256 = Buffer.alloc(12);
    base256[0] = 0x80;
    base256[11] = 1;
    for (const sizeField of [
      base256,
      octal(1, 12),
      Buffer.from(" 0000000001 "),
    ]) {
      expect(() =>
        plainTarEntries(
          archive(
            tarRecord(Buffer.from("x"), {
              name: "package/README.md",
              sizeField,
            }),
          ),
        ),
      ).toThrow(invalidTarEntryError);
    }
  });

  test("rejects alternate ustar signatures", () => {
    for (const options of [
      { magic: "ustar " },
      { magic: "ustar\0", version: " \0" },
    ]) {
      expect(() =>
        plainTarEntries(
          archive(
            tarRecord(Buffer.from("x"), {
              name: "package/README.md",
              ...options,
            }),
          ),
        ),
      ).toThrow(invalidTarEntryError);
    }
  });

  test("scans complete header text fields", () => {
    expect(() =>
      plainTarEntries(
        archive(
          tarRecord(Buffer.from("clean"), {
            name: "package/README.md",
            user: "public\0go/example",
          }),
        ),
      ),
    ).toThrow(internalReferenceError);
  });

  test("scans complete raw headers", () => {
    for (const options of [
      {
        deviceNumbers: Buffer.concat([
          Buffer.from("go/example"),
          Buffer.alloc(6),
        ]),
      },
      { reserved: Buffer.from("go/example") },
    ]) {
      expect(() =>
        plainTarEntries(
          archive(
            tarRecord(Buffer.from("clean"), {
              name: "package/README.md",
              ...options,
            }),
          ),
        ),
      ).toThrow(internalReferenceError);
    }
  });

  test("rejects nonzero padding and data after the terminator", () => {
    const record = tarRecord(Buffer.from("x"), {
      name: "package/README.md",
    });
    const badPadding = Buffer.from(record);
    badPadding[badPadding.length - 1] = 1;
    const secondRecord = tarRecord(Buffer.from("y"), {
      name: "package/LICENSE",
    });

    for (const bytes of [
      archive(badPadding),
      Buffer.concat([record, Buffer.alloc(blockSize), secondRecord]),
      Buffer.concat([
        record,
        Buffer.alloc(blockSize * 2),
        secondRecord,
        Buffer.alloc(blockSize * 2),
      ]),
      Buffer.concat([archive(record), Buffer.alloc(1)]),
      record,
    ]) {
      expect(() => plainTarEntries(bytes)).toThrow(invalidTarEntryError);
    }
  });
});
