//! An origin, as a browser or a stored login's address gives it. Reading
//! never fails but by refusing; an origin read is written back exactly as
//! it was given; and the origin of an address reads again as itself.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osm_origin::Origin;

fuzz_target!(|text: &str| {
    if let Some(origin) = Origin::parse(text) {
        assert_eq!(origin.to_string(), text);
    }
    if let Some(origin) = Origin::of_url(text) {
        assert_eq!(Origin::parse(&origin.to_string()), Some(origin));
    }
});
