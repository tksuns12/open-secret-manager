// A card's number as the editor and the preview read it. The shell decides
// what is stored (`card.rs` in the core); these only say it ahead.

/** The digits of a card's number as typed, without its spaces and dashes; `null` unless they could be one. */
export function cardDigits(number: string): string | null {
  const digits = number.replace(/[ -]/g, "");
  return /^\d{12,19}$/.test(digits) ? digits : null;
}
/** The brand a card's number names, as the shell decides it when the number is saved (`card::brand_of`): shown in the editor only. */
export function cardBrand(number: string): string | null {
  const digits = cardDigits(number);
  if (!digits) return null;
  const first = (count: number) => Number(digits.slice(0, count));
  if (digits.startsWith("4")) return "Visa";
  if ([34, 37].includes(first(2))) return "Amex";
  if ((first(2) >= 51 && first(2) <= 55) || (first(4) >= 2221 && first(4) <= 2720)) return "Mastercard";
  if (first(4) === 6011 || (first(3) >= 644 && first(3) <= 649) || first(2) === 65) return "Discover";
  if (first(4) >= 3528 && first(4) <= 3589) return "JCB";
  if ((first(3) >= 300 && first(3) <= 305) || [36, 38, 39].includes(first(2))) return "Diners Club";
  if (first(2) === 62) return "UnionPay";
  return null;
}
/** Whether a card's number passes the check its last digit is for (Luhn), which catches a mistyped digit. */
export function passesCardCheck(number: string): boolean {
  const digits = cardDigits(number);
  if (!digits) return false;
  const sum = [...digits].reverse().reduce((total, digit, place) => {
    const value = Number(digit) * (place % 2 === 1 ? 2 : 1);
    return total + (value > 9 ? value - 9 : value);
  }, 0);
  return sum % 10 === 0;
}
