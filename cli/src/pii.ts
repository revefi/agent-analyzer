/**
 * Personal data in transcripts, with patterns tuned for text full of code. Card, bank and ID
 * numbers must also pass their checksum, and IP addresses Node's parser, before they are replaced.
 */

import { isIPv4, isIPv6 } from "node:net";

interface PiiRule {
  id: string;
  re: RegExp;
  placeholder: string;
  valid?: (match: string) => boolean;
  /** Trims a trailing group the pattern may have taken from the next word; retried on failure. */
  shrink?: RegExp;
}

const digitsOf = (s: string) => s.replace(/\D/g, "");

/** Luhn check: payment cards and Canadian SINs. */
export function validateLuhn(value: string): boolean {
  const digits = digitsOf(value);
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    const d = Number(digits[digits.length - 1 - i]);
    sum += i % 2 ? (d * 2 > 9 ? d * 2 - 9 : d * 2) : d;
  }
  return digits.length > 0 && sum % 10 === 0;
}

// IBAN length per country, from the SWIFT IBAN registry.
const IBAN_LENGTHS: Record<string, number> = {
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22, BI: 27, BR: 29, BY: 28,
  CH: 21, CR: 21, CY: 28, CZ: 24, DE: 22, DJ: 27, DK: 18, DO: 28, EE: 20, EG: 29, ES: 24, FI: 18,
  FK: 18, FO: 18, FR: 27, GB: 22, GE: 22, GI: 23, GL: 18, GR: 27, GT: 28, HN: 28, HR: 21, HU: 28,
  IE: 22, IL: 23, IQ: 23, IS: 26, IT: 27, JO: 30, KW: 30, KZ: 20, LB: 28, LC: 32, LI: 21, LT: 20,
  LU: 20, LV: 21, LY: 25, MC: 27, MD: 24, ME: 22, MK: 19, MN: 20, MR: 27, MT: 31, MU: 30, NI: 28,
  NL: 18, NO: 15, OM: 23, PK: 24, PL: 28, PS: 29, PT: 25, QA: 29, RO: 24, RS: 22, RU: 33, SA: 24,
  SC: 31, SD: 18, SE: 24, SI: 19, SK: 24, SM: 27, SO: 23, ST: 25, SV: 28, TL: 23, TN: 24, TR: 26,
  UA: 29, VA: 22, VG: 24, XK: 20, YE: 30,
};

/** The country's IBAN length and the ISO 13616 mod-97 check. */
export function validateIBAN(value: string): boolean {
  const iban = value.replace(/[\s.-]/g, "").toUpperCase();
  if (IBAN_LENGTHS[iban.slice(0, 2)] !== iban.length || !/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(iban)) return false;
  const n = `${iban.slice(4)}${iban.slice(0, 4)}`.replace(/[A-Z]/g, (c) => String(c.charCodeAt(0) - 55));
  return BigInt(n) % 97n === 1n;
}

/** SSA rules: area 000, 666 and 900-999, group 00 and serial 0000 are never issued. */
function validateSSN(value: string): boolean {
  const d = digitsOf(value);
  const area = Number(d.slice(0, 3));
  return d.length === 9 && area !== 0 && area !== 666 && area < 900 && d.slice(3, 5) !== "00" && d.slice(5) !== "0000";
}

/** HMRC rules for National Insurance numbers: excluded letters and prefixes. */
function validateNINO(value: string): boolean {
  const nino = value.replace(/\s/g, "").toUpperCase();
  return /^[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]$/.test(nino) && !/^(?:BG|GB|NK|KN|TN|NT|ZZ)/.test(nino);
}

const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4]];
for (let i = 2; i < 8; i++) VERHOEFF_P.push(VERHOEFF_P[1]!.map((j) => VERHOEFF_P[i - 1]![j]!));

/** Verhoeff check: Aadhaar's last digit. */
export function validateVerhoeff(value: string): boolean {
  const digits = digitsOf(value);
  if (!digits) return false;
  let c = 0;
  for (let i = 0; i < digits.length; i++) {
    c = VERHOEFF_D[c]![VERHOEFF_P[i % 8]![Number(digits[digits.length - 1 - i])]!]!;
  }
  return c === 0;
}

/** UPI handles from the major banks and apps; a bare `name@word` is usually an npm scope or a mention. */
const UPI_HANDLES = [
  "okhdfcbank", "okicici", "oksbi", "okaxis", "ybl", "ibl", "axl", "paytm", "ptyes", "pthdfc",
  "ptsbi", "ptaxis", "apl", "yapl", "rapl", "upi", "waicici", "wahdfcbank", "wasbi", "waaxis",
  "axisbank", "hdfcbank", "icici", "sbi", "kotak", "kmbl", "idfcbank", "yesbank", "indus",
  "federal", "rbl", "aubank", "kbl", "cnrb", "pnb", "unionbank", "boi", "mahb", "barodampay",
  "airtel", "freecharge", "jupiteraxis", "fam", "slice", "naviaxis", "superyes", "abfspay",
  "ikwik", "postbank", "dlb", "axisb", "yescred", "fifederal", "okbizaxis", "jio", "mbk", "idbi",
  "iob", "hsbc", "sc",
];

/**
 * A label just before a number: its own word, or the start or end of a camelCase or snake_case
 * name (`phone`, `userPhone`, `PHONE_NO`), never part of another word (`telemetry`, `hotel_id`).
 */
function label(words: string[]): string {
  const lower = words.join("|");
  const upper = words.map((w) => w.toUpperCase()).join("|");
  const title = words.map((w) => w[0]!.toUpperCase() + w.slice(1)).join("|");
  const suffix = "(?:[ _]?(?:no|No|NO|num|Num|NUM|number|Number|NUMBER))?";
  return `(?:(?<![A-Za-z])(?:${lower}|${upper})|(?<![A-Z])(?:${title}))${suffix}(?![a-z])[\\s"':=#.-]{1,6}`;
}

/** Infrastructure ranges stay readable: they identify no one and matter to the analysis. */
function personalIPv4(ip: string): boolean {
  if (!isIPv4(ip)) return false;
  const [a = 0, b = 0, c = 0, d = 0] = ip.split(".").map(Number);
  // `4.3.2.1` is a section or version number far more often than an address.
  if (a < 10 && b < 10 && c < 10 && d < 10) return false;
  return !(
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

/** Only global unicast (2000::/3); `a[1::2]` and `B2::C` are code. */
function personalIPv6(ip: string): boolean {
  return isIPv6(ip) && /^[23][\da-f]{3}:/i.test(ip);
}

const PII_RULES: PiiRule[] = [
  {
    id: "email",
    re: /(?<![\p{L}\p{N}_.%+])[\p{L}\p{N}_][\p{L}\p{N}_.%+'-]{0,63}(?:@|%40)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?){0,8}\.[A-Za-z]{2,24}/gu,
    placeholder: "<EMAIL>",
    // `git@host` is a git remote, not a person's address.
    valid: (m) => !/^git(?:@|%40)/i.test(m),
  },
  {
    id: "card-number",
    re: /(?<![\w.-])(?:[2-68]\d{3}([ .-]?)\d{4}\1\d{4}\1\d{1,7}|3[47]\d{2}([ .-]?)\d{6}\2\d{5})(?![\w-]|\.\d)/g,
    placeholder: "<CARD_NUMBER>",
    valid: (m) => digitsOf(m).length >= 13 && validateLuhn(m),
  },
  {
    id: "iban",
    re: /(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?![A-Za-z0-9])/gi,
    placeholder: "<IBAN>",
    valid: validateIBAN,
    shrink: / ?[A-Z0-9]{1,4}$/i,
  },
  {
    id: "ssn",
    re: /(?<![\w-])\d{3}([ -])\d{2}\1\d{4}(?![\w-])/g,
    placeholder: "<SSN>",
    valid: validateSSN,
  },
  {
    id: "national-id",
    re: /(?<![A-Za-z0-9])[A-Z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-D](?![A-Za-z0-9])/g,
    placeholder: "<NATIONAL_ID>",
    valid: validateNINO,
  },
  {
    // Aadhaar. Ungrouped only right after its label, because a tenth of all 12-digit numbers (AWS
    // account IDs, timestamps) pass the checksum.
    id: "national-id",
    re: new RegExp(
      String.raw`(?<![\w.-])[2-9]\d{3}[ .-]\d{4}[ .-]\d{4}(?![\w-]|\.\d)|(?<=${label(["aadhaar", "aadhar", "uidai"])})[2-9]\d{11}(?!\w)`,
      "g",
    ),
    placeholder: "<NATIONAL_ID>",
    valid: validateVerhoeff,
  },
  {
    // PAN: the fourth letter is the holder type (P person, C company, H family, ...).
    id: "national-id",
    re: /(?<![A-Za-z0-9])[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z](?![A-Za-z0-9])/g,
    placeholder: "<NATIONAL_ID>",
  },
  {
    id: "upi-id",
    re: new RegExp(
      `(?<![\\w.-])(?:[\\w.-]{2,256}@(?:${UPI_HANDLES.join("|")})|\\d{10}@[a-z]{2,32})(?![\\w.-])`,
      "gi",
    ),
    placeholder: "<UPI_ID>",
  },
  {
    id: "national-id",
    re: /(?<![\w-])\d{3}([ -])\d{3}\1\d{3}(?![\w-])/g,
    placeholder: "<NATIONAL_ID>",
    valid: (m) => digitsOf(m) !== "000000000" && validateLuhn(m),
  },
  {
    id: "ip-address",
    re: /(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?!\w|\.\d)/g,
    placeholder: "<IP_ADDRESS>",
    valid: personalIPv4,
  },
  {
    id: "ip-address",
    re: /(?<![\w:.])(?=[\dA-Fa-f:]{0,39}\d)[\dA-Fa-f]{0,4}(?::[\dA-Fa-f]{0,4}){2,7}(?![\w:])/g,
    placeholder: "<IP_ADDRESS>",
    valid: personalIPv6,
  },
  {
    // Indian mobile. Ten bare digits are a count or an ID far more often, so they need a prefix,
    // a space or dashes, or a label like "phone" just before.
    id: "phone",
    re: new RegExp(
      String.raw`(?<![\w+/.-])(?:\+91[ -]?[6-9]\d{4}[ -]?\d{5}|(?:91|0)[ -][6-9]\d{4}[ -]?\d{5}|[6-9]\d{4} \d{5}|[6-9]\d{3}([ -])\d{3}\1\d{3}|[6-9]\d([ -])\d{4}\2\d{4}|(?<=${label(["phone", "mobile", "mob", "cell", "cellphone", "contact", "whatsapp", "tel", "telephone"])})(?:\+?91|0)?[6-9]\d{9})(?![\w-]|\.\d)`,
      "g",
    ),
    placeholder: "<PHONE>",
    // An exact multiple of 1024 is a byte size (8589934592), not a phone number.
    valid: (m) => Number(m.replace(/\D/g, "").slice(-10)) % 1024 !== 0,
  },
  {
    // Written like a phone number: with a `+` country code, `(415) 555-0132`, `415-555-0132` or
    // `415 555 0132`. A bare run of digits is an ID or a timestamp far more often.
    id: "phone",
    re: /(?<![\w+/.-])(?:\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?\d{1,5}(?:[ .-]\d{2,8}){1,4}|\+\d{1,3}[ .-]?\d{2,5}[ .-]?\d{2,8}|(?:1[ .-])?(?:\(\d{3}\)[ .-]?\d{3}[ .-]\d{4}|\d{3}([ .-])\d{3}\1\d{4}))(?![\w-]|\.\d)/g,
    placeholder: "<PHONE>",
    // E.164 allows at most 15 digits; fewer than 10 is a diff line or an offset (`+86400000`).
    valid: (m) => /^(?:\D*\d){10,15}\D*$/.test(m),
  },
];

export function scrubPersonalData(text: string, counts: Record<string, number>): string {
  let s = text;
  for (const rule of PII_RULES) {
    s = s.replace(rule.re, (m) => {
      let v = m;
      while (rule.valid && !rule.valid(v)) {
        const shorter = rule.shrink ? v.replace(rule.shrink, "") : v;
        if (shorter === v) return m;
        v = shorter;
      }
      counts[rule.id] = (counts[rule.id] ?? 0) + 1;
      return rule.placeholder + m.slice(v.length);
    });
  }
  return s;
}
