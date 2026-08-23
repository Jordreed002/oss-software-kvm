import { describe, expect, it } from "vitest";
import { formatBytes, formatNumber, formatRate, formatUptime } from "./format";

describe("formatBytes", () => {
  it("picks the unit for each magnitude tier", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(2_048)).toBe("2.0 KiB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.00 MiB");
    expect(formatBytes(3 * 1024 * 1024 * 1024)).toBe("3.00 GiB");
  });
});

describe("formatRate", () => {
  it("appends a per-second suffix to the byte formatting", () => {
    expect(formatRate(2_048)).toBe("2.0 KiB/s");
    expect(formatRate(0)).toBe("0 B/s");
  });
});

describe("formatNumber", () => {
  it("groups thousands with a locale separator", () => {
    // The exact separator depends on the runtime locale, so accept either.
    expect(formatNumber(1_234_567)).toMatch(/^1[.,]234[.,]567$/);
  });
});

describe("formatUptime", () => {
  it("renders seconds, minutes, and hours tiers", () => {
    expect(formatUptime(0)).toBe("0s");
    expect(formatUptime(59_000)).toBe("59s");
    expect(formatUptime(65_000)).toBe("1m 5s");
    expect(formatUptime(3_723_000)).toBe("1h 2m 3s");
  });
});
