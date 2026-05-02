//! 256-word SAS wordlist. One word per byte (0..=255).
//!
//! Selection rules:
//! - 4–8 ASCII lowercase letters
//! - distinct enough to read aloud across phone speakers
//! - common, neutral nouns (no slurs, no legal/financial loaded terms)
//!
//! The list is committed and frozen — changing entries breaks SAS verification
//! across versions and constitutes a wire-protocol break.

#[rustfmt::skip]
pub const WORDLIST: [&str; 256] = [
    // 0..15
    "amber",   "anchor",  "apple",   "arrow",   "atlas",   "autumn",  "bacon",   "badge",
    "baker",   "balsa",   "banjo",   "basil",   "beach",   "beacon",  "beaver",  "berry",
    // 16..31
    "bison",   "blade",   "blaze",   "bloom",   "blush",   "boost",   "brass",   "bread",
    "breeze",  "brick",   "bridge",  "bronze",  "brook",   "brush",   "bunny",   "butter",
    // 32..47
    "cabin",   "cable",   "cactus",  "cameo",   "candle",  "canyon",  "carbon",  "carrot",
    "cedar",   "celery",  "cello",   "chalk",   "charm",   "cherry",  "chime",   "cinder",
    // 48..63
    "cipher",  "circle",  "citrus",  "clay",    "clever",  "cloud",   "clover",  "coast",
    "cobalt",  "cobra",   "cocoa",   "comet",   "copper",  "coral",   "cosmos",  "cotton",
    // 64..79
    "cougar",  "crane",   "crater",  "crest",   "crimson", "crisp",   "crystal", "daisy",
    "dance",   "dawn",    "deer",    "delta",   "denim",   "desert",  "dial",    "diamond",
    // 80..95
    "diner",   "dolphin", "dragon",  "dream",   "dune",    "dynamo",  "eagle",   "earth",
    "ebony",   "echo",    "eclipse", "edge",    "ember",   "emerald", "ensign",  "ether",
    // 96..111
    "fable",   "falcon",  "feather", "fern",    "fiber",   "fiesta",  "finch",   "fjord",
    "flame",   "flask",   "flock",   "flora",   "flute",   "forest",  "forge",   "frost",
    // 112..127
    "galaxy",  "garden",  "garnet",  "ginger",  "glacier", "glade",   "glass",   "gleam",
    "globe",   "golem",   "gorge",   "granite", "grape",   "graph",   "grass",   "gravel",
    // 128..143
    "grizzly", "harbor",  "hawk",    "hazel",   "helix",   "herald",  "heron",   "hickory",
    "hollow",  "honey",   "horizon", "husky",   "icon",    "igloo",   "indigo",  "iris",
    // 144..159
    "iron",    "island",  "ivory",   "jade",    "jaguar",  "jasmine", "jasper",  "jelly",
    "jewel",   "jingle",  "jolly",   "jovial",  "jungle",  "juniper", "kayak",   "kelp",
    // 160..175
    "kettle",  "kiln",    "kindle",  "kite",    "kiwi",    "knight",  "koala",   "lagoon",
    "lance",   "lantern", "lark",    "laser",   "laurel",  "lava",    "lemon",   "lens",
    // 176..191
    "lentil",  "lever",   "lilac",   "lily",    "lobster", "locust",  "lodge",   "lotus",
    "lunar",   "lynx",    "magnet",  "mango",   "maple",   "marble",  "marsh",   "meadow",
    // 192..207
    "melody",  "melon",   "meteor",  "mint",    "mirror",  "mocha",   "morning", "moss",
    "muffin",  "mustard", "nectar",  "needle",  "nest",    "nettle",  "nickel",  "nimbus",
    // 208..223
    "nomad",   "north",   "oasis",   "ocean",   "ochre",   "octave",  "olive",   "onion",
    "onyx",    "opal",    "orange",  "orbit",   "orchid",  "otter",   "oyster",  "palace",
    // 224..239
    "pansy",   "papaya",  "parade",  "parrot",  "peach",   "pebble",  "pecan",   "pepper",
    "petal",   "piano",   "pigeon",  "pilot",   "pine",    "planet",  "plum",    "polar",
    // 240..255
    "pollen",  "pond",    "poppy",   "prairie", "prism",   "quartz",  "quill",   "quilt",
    "quince",  "raccoon", "radar",   "raven",   "ribbon",  "river",   "robin",   "rocket",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn wordlist_has_256_entries() {
        assert_eq!(WORDLIST.len(), 256);
    }

    #[test]
    fn wordlist_entries_are_unique() {
        let set: HashSet<&&str> = WORDLIST.iter().collect();
        assert_eq!(set.len(), WORDLIST.len(), "duplicate word(s) in wordlist");
    }

    #[test]
    fn wordlist_entries_are_4_to_8_ascii_lowercase() {
        for (i, w) in WORDLIST.iter().enumerate() {
            assert!(
                (4..=8).contains(&w.len()),
                "word #{i} {w:?} has length {} (must be 4..=8)",
                w.len()
            );
            assert!(
                w.chars().all(|c| c.is_ascii_lowercase()),
                "word #{i} {w:?} must be ASCII lowercase",
            );
        }
    }
}
