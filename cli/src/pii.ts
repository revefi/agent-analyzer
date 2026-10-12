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
    re: /(?<![\w.-])(?:[2-6]\d{3}([ .-]?)\d{4}\1\d{4}\1\d{1,7}|3[47]\d{2}([ .-]?)\d{6}\2\d{5})(?![\w-]|\.\d)/g,
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
    // Written like a phone number: with a `+` country code, `(415) 555-0132`, `415-555-0132` or
    // `415 555 0132`. A bare run of digits is an ID or a timestamp far more often.
    id: "phone",
    re: /(?<![\w+/.-])(?:\+\d{10,14}|\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?\d{1,5}(?:[ .-]\d{2,8}){1,4}|(?:1[ .-])?(?:\(\d{3}\)[ .-]?\d{3}[ .-]\d{4}|\d{3}([ .-])\d{3}\1\d{4}))(?![\w-]|\.\d)/g,
    placeholder: "<PHONE>",
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
