//! A card's fields. They are kept among an item's other fields
//! (`custom_fields`), under the names the owner reads there, which are also
//! the names a Bitwarden import gives them. Every device reads and writes a
//! card by these names, so they are part of the format.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::model::Item;

pub const CARDHOLDER: &str = "Cardholder name";
pub const NUMBER: &str = "Number";
pub const EXPIRY_MONTH: &str = "Expiry month";
pub const EXPIRY_YEAR: &str = "Expiry year";
pub const SECURITY_CODE: &str = "Security code";
pub const BRAND: &str = "Brand";

/// A card's fields, in the order they are shown.
pub const CARD_FIELDS: [&str; 6] = [
    CARDHOLDER,
    NUMBER,
    EXPIRY_MONTH,
    EXPIRY_YEAR,
    SECURITY_CODE,
    BRAND,
];

/// A change to a card's fields: `None` keeps a field as it is stored, and an
/// empty value removes it. A number given without a brand also sets the
/// brand its digits name, if they name one. The item's other fields are
/// left as they are.
#[derive(Default)]
pub struct CardChange {
    pub cardholder: Option<String>,
    pub number: Option<String>,
    pub expiry_month: Option<String>,
    pub expiry_year: Option<String>,
    pub security_code: Option<String>,
    pub brand: Option<String>,
}

impl CardChange {
    pub fn apply_to(mut self, item: &mut Item) {
        let trimmed = |value: &str| value.trim().to_owned();
        let number = tidied(self.number.take(), compact);
        let detected = self
            .brand
            .is_none()
            .then(|| number.as_deref().and_then(brand_of))
            .flatten()
            .map(str::to_owned);
        let changes = [
            (CARDHOLDER, tidied(self.cardholder.take(), trimmed)),
            (NUMBER, number),
            (EXPIRY_MONTH, tidied(self.expiry_month.take(), month_of)),
            (EXPIRY_YEAR, tidied(self.expiry_year.take(), year_of)),
            (SECURITY_CODE, tidied(self.security_code.take(), trimmed)),
            (BRAND, tidied(self.brand.take(), trimmed).or(detected)),
        ];
        for (name, value) in changes {
            match value {
                None => {}
                Some(mut value) if value.is_empty() => {
                    value.zeroize();
                    if let Some(mut removed) = item.custom_fields.remove(name) {
                        removed.zeroize();
                    }
                }
                Some(value) => {
                    if let Some(mut replaced) = item.custom_fields.insert(name.to_owned(), value) {
                        replaced.zeroize();
                    }
                }
            }
        }
    }
}

impl Drop for CardChange {
    fn drop(&mut self) {
        self.cardholder.zeroize();
        self.number.zeroize();
        self.expiry_month.zeroize();
        self.expiry_year.zeroize();
        self.security_code.zeroize();
        self.brand.zeroize();
    }
}

impl fmt::Debug for CardChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CardChange([REDACTED])")
    }
}

/// `value` as `tidy` writes it, the value as given wiped.
fn tidied(value: Option<String>, tidy: impl Fn(&str) -> String) -> Option<String> {
    value.map(|mut value| {
        let tidy = tidy(&value);
        value.zeroize();
        tidy
    })
}

/// A number as it is stored: without the spaces and dashes it is often
/// written with.
fn compact(number: &str) -> String {
    number.chars().filter(|c| !matches!(c, ' ' | '-')).collect()
}

/// A month of one or two digits, 1 to 12, as two digits; anything else as
/// it was given.
fn month_of(month: &str) -> String {
    let month = month.trim();
    match month.parse::<u8>() {
        Ok(value @ 1..=12) if month.len() <= 2 => format!("{value:02}"),
        _ => month.to_owned(),
    }
}

/// A year of two digits as one of this century; anything else as it was
/// given.
fn year_of(year: &str) -> String {
    let year = year.trim();
    if year.len() == 2 && year.bytes().all(|b| b.is_ascii_digit()) {
        format!("20{year}")
    } else {
        year.to_owned()
    }
}

/// The digits of a number that is only digits, spaces, and dashes, if it
/// has the length of a card's number.
fn card_digits(number: &str) -> Option<Zeroizing<Vec<u8>>> {
    let number = Zeroizing::new(compact(number));
    let digits = Zeroizing::new(
        number
            .bytes()
            .map(|b| b.wrapping_sub(b'0'))
            .collect::<Vec<u8>>(),
    );
    (digits.iter().all(|digit| *digit <= 9) && (12..=19).contains(&digits.len())).then_some(digits)
}

/// Whether `number` has the length of a card's number, 12 to 19 digits,
/// and nothing but digits, spaces, and dashes.
pub fn has_card_length(number: &str) -> bool {
    card_digits(number).is_some()
}

/// The brand a card's number names by its first digits, as Bitwarden calls
/// it; `None` for a number of no brand this knows.
pub fn brand_of(number: &str) -> Option<&'static str> {
    let digits = card_digits(number)?;
    let first = |count: usize| {
        digits[..count]
            .iter()
            .fold(0_u32, |value, digit| value * 10 + u32::from(*digit))
    };
    Some(match (first(1), first(2), first(3), first(4)) {
        (4, ..) => "Visa",
        (_, 34 | 37, ..) => "Amex",
        (_, 51..=55, ..) | (.., 2221..=2720) => "Mastercard",
        (.., 6011) | (_, _, 644..=649, _) | (_, 65, ..) => "Discover",
        (.., 3528..=3589) => "JCB",
        (_, _, 300..=305, _) | (_, 36 | 38 | 39, ..) => "Diners Club",
        (_, 62, ..) => "UnionPay",
        _ => return None,
    })
}

/// Whether a card's number passes the check its last digit is for (Luhn),
/// which catches a mistyped digit. A number that fails it is still kept:
/// the check is only a warning.
pub fn passes_check(number: &str) -> bool {
    let Some(digits) = card_digits(number) else {
        return false;
    };
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(place, digit)| {
            let digit = u32::from(*digit);
            if place % 2 == 1 {
                let doubled = digit * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                digit
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// The last four digits of a card's number, which may be shown: nothing
/// else of the number is. `None` for a number too short for them to leave
/// most of it unsaid.
pub fn ending(number: &str) -> Option<String> {
    let digits = card_digits(number)?;
    Some(
        digits[digits.len() - 4..]
            .iter()
            .map(|digit| char::from(b'0' + digit))
            .collect(),
    )
}
