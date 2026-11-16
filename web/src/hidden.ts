// Shared by the paste viewer, discussions and Null Chats.

// Text a room message may not carry: control and format characters (direction
// overrides and isolates, zero-width spaces, soft hyphens, tag characters
// outside flag emoji), line and paragraph separators, fillers and other
// characters that show as nothing (combining grapheme joiner, Khmer inherent
// vowels, Mongolian variation selectors), and variation selectors other than
// the emoji ones. They hide text, or make what shows differ from what is
// copied.
export const HIDDEN = /(?![\u200C\u200D\uFE0E\uFE0F])[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}\p{Default_Ignorable_Code_Point}]|[\u034F\u115F\u1160\u17B4\u17B5\u180B-\u180F\u3164\uFFA0\uFE00-\uFE0D\u{E0100}-\u{E01EF}]/u;
// The flags for parts of a country that systems draw (England, Scotland,
// Wales): a black flag, tag letters and a cancel tag. Any other tag letters
// would draw as a plain flag and hide text.
export const FLAG_TAGS = /\u{1F3F4}(?:\u{E0067}\u{E0062}(?:\u{E0065}\u{E006E}\u{E0067}|\u{E0073}\u{E0063}\u{E0074}|\u{E0077}\u{E006C}\u{E0073}))\u{E007F}/gu;
const isEmojiBase = (c: string) => /[\p{Extended_Pictographic}\p{Emoji_Modifier}\uFE0F]/u.test(c);
const isPictograph = (c: string) => /\p{Extended_Pictographic}/u.test(c);
const isMark = (c: string) => /\p{M}/u.test(c);
const isLetter = (c: string) => /\p{L}/u.test(c);
// Scripts whose spelling needs zero-width joiners and non-joiners.
const JOINING = new RegExp(`[${['Arabic', 'Syriac', 'Nko', 'Devanagari', 'Bengali', 'Gurmukhi', 'Gujarati', 'Oriya', 'Tamil', 'Telugu', 'Kannada', 'Malayalam', 'Sinhala', 'Myanmar', 'Khmer', 'Tibetan', 'Thaana']
  .map((s) => `\\p{Script=${s}}`).join('')}]`, 'u');
const joins = (c: string) => JOINING.test(c);

/**
 * True if a zero-width joiner, non-joiner or variation selector at `i`
 * does a visible job: joining emoji, or Indic letters (after a virama, or
 * before one as in Bengali), keeping Persian or Indic letters apart, or
 * choosing how an emoji looks.
 */
export function joinerOk(cps: string[], i: number): boolean {
  const c = cps[i]!;
  const prev = cps[i - 1] ?? '';
  const next = cps[i + 1] ?? '';
  const joiner = c === '\u200C' || c === '\u200D';
  if (joiner && (next === '\u200C' || next === '\u200D')) return false; // never two in a row
  // A joiner in an emoji sequence, or in a script that spells with it
  // (after a virama, or before one as in Bengali, or at a word's end as in
  // Malayalam chillus); a non-joiner between letters of such a script.
  if (c === '\u200D') return (isEmojiBase(prev) && isPictograph(next)) || (joins(prev) && (joins(next) || next === '' || !isLetter(next) && !isMark(next)));
  if (c === '\u200C') return joins(prev) && joins(next) && isLetter(next);
  // FE0E, FE0F: right after a character that has an emoji form.
  return prev !== '' && /\p{Emoji}/u.test(prev) && prev !== '\uFE0E' && prev !== '\uFE0F';
}

// Paste text and comments may carry anything, but get a warning when they
// hold characters that change how text looks without being visible ("Trojan
// Source", CVE-2021-42574): the ones a room message may not carry (above),
// with the same exceptions for joiners and emoji variation selectors that do
// a visible job, plus a byte-order mark at the start and Windows line breaks.

// HIDDEN, with tabs and line breaks allowed.
const HIDDEN_IN_TEXT = new RegExp(HIDDEN.source.replace('(?![\\u200C', '(?![\\t\\n\\r\\u200C'), 'u');

/** Reports whether text contains characters that can disguise what it says. */
export function hasHiddenChars(text: string): boolean {
  const s = (text.startsWith('\uFEFF') ? text.slice(1) : text).replace(FLAG_TAGS, '\u{1F3F4}');
  if (HIDDEN_IN_TEXT.test(s)) return true;
  // Each joiner or variation selector is judged by its neighbours alone, so
  // a long paste is never copied into an array of code points.
  const re = /[\u200C\u200D\uFE0E\uFE0F]/g;
  for (let m = re.exec(s); m !== null; m = re.exec(s)) {
    const i = m.index;
    const pair = i >= 2 && /[\uDC00-\uDFFF]/.test(s[i - 1]!) && /[\uD800-\uDBFF]/.test(s[i - 2]!);
    const before = i === 0 ? null : pair ? s.slice(i - 2, i) : s[i - 1]!;
    const after = i + 1 < s.length ? String.fromCodePoint(s.codePointAt(i + 1)!) : null;
    const around = [...(before === null ? [] : [before]), m[0], ...(after === null ? [] : [after])];
    if (!joinerOk(around, before === null ? 0 : 1)) return true;
  }
  return false;
}

/**
 * Removes every character hasHiddenChars would flag (and line breaks and
 * tabs), plus blank-looking fillers (Hangul fillers, the Braille blank) that
 * can pad a short label such as a file type. Not used on paste text, where
 * those characters are legitimate.
 */
export function stripHiddenChars(text: string): string {
  return text.replace(/(?![\u200C\u200D])[\p{Cf}\p{Cc}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\u115F\u1160\u3164\uFFA0\u2800]/gu, '');
}
