// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use emissary_core::{
    crypto::{base32_encode, base64_decode},
    primitives::Destination,
};

use crate::{config::EmissaryConfig, ui::dioxus::LOG_TARGET};

use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    sync::Arc,
};

/// Save router configuration to disk.
pub fn save_router_config(path: PathBuf, config: &EmissaryConfig) {
    if let Ok(serialized) = toml::to_string(config) {
        let _ = std::fs::write(path, serialized);
    }
}

/// Load base32 addresses from disk.
pub fn load_addresses(path: PathBuf) -> BTreeMap<Arc<str>, Arc<str>> {
    let Ok(file) = File::open(&path) else {
        tracing::warn!(
            target: LOG_TARGET,
            path = %path.display(),
            "failed to open address book file",
        );
        return BTreeMap::new();
    };
    let reader = BufReader::new(file);

    reader
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            let (key, value) = line.split_once('=')?;
            Some((Arc::from(key), Arc::from(format!("http://{value}.b32.i2p"))))
        })
        .collect()
}

/// Trim hidden service display name.
///
/// Strips unnecessary prefixes and truncates the base32 address.
pub fn trim_display_name(s: &str) -> String {
    let s = s.strip_prefix("http://").unwrap_or(s);
    let s = s.strip_prefix("https://").unwrap_or(s);
    let s = s.strip_prefix("www").unwrap_or(s);
    let max_len = 50;
    let num_chars = s.chars().count();
    if num_chars <= max_len {
        return s.to_string();
    }
    let keep = max_len - 3;
    let front = keep / 2;
    let back = keep - front;

    // truncate by characters, not bytes, so that multi-byte hostnames don't panic
    let head = s.chars().take(front).collect::<String>();
    let tail = s.chars().skip(num_chars - back).collect::<String>();

    format!("{head}...{tail}")
}

/// Load router configuration from disk.
///
/// Returns `None` if the file cannot be read or parsed.
pub fn load_router_config(path: &Path) -> Option<EmissaryConfig> {
    let contents = std::fs::read_to_string(path).ok()?;

    toml::from_str(&contents).ok()
}

/// Convert key file into a base32 address.
pub fn read_b32_address(path: &str) -> Option<String> {
    let data = std::fs::read_to_string(path).ok()?;
    let decoded = base64_decode(data.trim())?;
    let destination = Destination::parse(&decoded).ok()?;

    Some(base32_encode(destination.id().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use emissary_util::runtime::tokio::Runtime as TokioRuntime;

    #[test]
    fn trim_display_name_handles_multibyte_names() {
        // short names are returned as is
        assert_eq!(trim_display_name("http://example.i2p"), "example.i2p");

        // long ascii name is shortened to 50 characters
        let long = format!("{}.i2p", "a".repeat(80));
        let trimmed = trim_display_name(&long);
        assert_eq!(trimmed.chars().count(), 50);
        assert!(trimmed.contains("..."));

        // long name with multi-byte characters must not panic and keeps whole characters
        let long = format!("{}.i2p", "\u{44f}".repeat(80));
        let trimmed = trim_display_name(&long);
        assert_eq!(trimmed.chars().count(), 50);
        assert!(trimmed.starts_with("\u{44f}"));
        assert!(trimmed.ends_with(".i2p"));

        // exactly at the limit with multi-byte characters
        let exact = "\u{44f}".repeat(50);
        assert_eq!(trim_display_name(&exact), exact);
    }

    #[test]
    fn router_config_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("router.toml");
        let mut config = EmissaryConfig::new::<TokioRuntime>();
        config.floodfill = true;

        save_router_config(path.clone(), &config);

        let loaded = load_router_config(&path).unwrap();
        assert!(loaded.floodfill);
        assert_eq!(loaded.ntcp2.as_ref().unwrap().port, config.ntcp2.as_ref().unwrap().port);

        // missing or malformed file yields `None`
        assert!(load_router_config(&dir.path().join("missing.toml")).is_none());
        std::fs::write(&path, "not = [valid").unwrap();
        assert!(load_router_config(&path).is_none());
    }
}
