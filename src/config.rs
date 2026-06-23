//! Allow-list pattern parsing and matching.
//!
//! The pattern file (`allowed-domains.txt`) is line-oriented. Each line's type is
//! determined unambiguously by a prefix, checked in this order:
//!
//! | Syntax                                         | Meaning                                                   |
//! |------------------------------------------------|-----------------------------------------------------------|
//! | `api.anthropic.com`                            | EXACT host (case-insensitive)                             |
//! | `.sentry.io`                                   | SUFFIX: `sentry.io` and any subdomain `*.sentry.io`       |
//! | `*.gallery.vsassets.io`                        | WILDCARD: one or more subdomain labels of the suffix      |
//! | `re:^[a-z0-9-]+\.pkg\.dev$`                    | REGEX matched against the whole lowercased name           |
//! | `JsonList(https://example.com, [key1, key2])`  | Fetch JSON; keys map to top-level `["cidr", ...]` arrays  |
//! | `JsonList(https://example.com, [arr[].field])` | Fetch JSON; keys map to `[{"field": "cidr"}, ...]` arrays |
//!
//! `#` comments and blank lines are ignored.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;

/// Parsed representation of a `JsonList(url, [key1, key2, ...])` line.
pub struct JsonIpListSpec {
    pub url: String,
    pub keys: Vec<String>,
}

/// The full parsed config: domain allow-list patterns plus any JSON IP-list specs.
pub struct Config {
    pub patterns: PatternSet,
    pub ip_lists: Vec<JsonIpListSpec>,
}

impl Config {
    /// Parse a config file from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading pattern file {}", path.display()))?;
        Self::parse(&text)
    }

    /// Parse config from a string.
    pub fn parse(text: &str) -> Result<Self> {
        let mut exact = HashSet::new();
        let mut suffixes = Vec::new();
        let mut glob_builder = GlobSetBuilder::new();
        let mut have_globs = false;
        let mut regexes = Vec::new();
        let mut regex_sources = Vec::new();
        let mut ip_lists = Vec::new();

        for (lineno, raw) in text.lines().enumerate() {
            let line = match raw.split_once('#') {
                Some((before, _)) => before,
                None => raw,
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if line.starts_with("JsonList(") {
                ip_lists.push(
                    parse_json_list(line)
                        .with_context(|| format!("invalid JsonList on line {}", lineno + 1))?,
                );
                continue;
            }

            let lower = line.to_ascii_lowercase();

            if let Some(body) = lower.strip_prefix("re:") {
                let anchored = anchor_regex(body);
                let re = Regex::new(&anchored)
                    .with_context(|| format!("invalid regex on line {}: {}", lineno + 1, line))?;
                regexes.push(re);
                regex_sources.push(line.to_string());
            } else if let Some(suffix) = lower.strip_prefix("*.") {
                glob_builder.add(
                    Glob::new(&format!("*.{suffix}"))
                        .with_context(|| format!("invalid wildcard on line {}", lineno + 1))?,
                );
                have_globs = true;
            } else if let Some(suffix) = lower.strip_prefix('.') {
                suffixes.push(suffix.to_string());
            } else {
                exact.insert(lower);
            }
        }

        let globs = if have_globs {
            glob_builder.build().context("building wildcard matcher")?
        } else {
            GlobSet::empty()
        };

        Ok(Self {
            patterns: PatternSet {
                exact,
                suffixes,
                globs,
                regexes,
                regex_sources,
            },
            ip_lists,
        })
    }
}

/// Parse `JsonList(url, [key1, key2, ...])` into a `JsonIpListSpec`.
fn parse_json_list(line: &str) -> Result<JsonIpListSpec> {
    let inner = line
        .strip_prefix("JsonList(")
        .and_then(|s| s.strip_suffix(')'))
        .with_context(|| format!("expected `JsonList(url, [keys])`, got: {line}"))?;

    let (url_part, keys_part) = inner
        .split_once(", [")
        .with_context(|| format!("expected `, [` separator in: {line}"))?;

    let keys_str = keys_part
        .strip_suffix(']')
        .with_context(|| format!("expected `]` to close key list in: {line}"))?;

    let url = url_part.trim().to_string();
    if url.is_empty() {
        bail!("empty URL in: {line}");
    }

    let keys: Vec<String> = keys_str
        .split(',')
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
        .collect();
    if keys.is_empty() {
        bail!("empty key list in: {line}");
    }

    Ok(JsonIpListSpec { url, keys })
}

/// A compiled set of allow-list patterns. Matching is `exact -> suffix -> glob -> regex`,
/// cheapest first.
pub struct PatternSet {
    exact: HashSet<String>,
    /// Suffix entries stored without the leading dot, e.g. `sentry.io`.
    suffixes: Vec<String>,
    globs: GlobSet,
    regexes: Vec<Regex>,
    /// Human-readable source of each regex, for logging.
    regex_sources: Vec<String>,
}

impl PatternSet {
    /// Parse a pattern file from disk (patterns only; ignores `JsonList` entries).
    pub fn load(path: &Path) -> Result<Self> {
        Ok(Config::load(path)?.patterns)
    }

    /// Parse pattern lines from a string (patterns only; ignores `JsonList` entries).
    pub fn parse(text: &str) -> Result<Self> {
        Ok(Config::parse(text)?.patterns)
    }

    /// Returns true if `name` (a DNS name, with or without a trailing dot) is allowed.
    pub fn is_allowed(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.').to_ascii_lowercase();

        if self.exact.contains(&name) {
            return true;
        }
        for suffix in &self.suffixes {
            if name == *suffix || name.ends_with(&format!(".{suffix}")) {
                return true;
            }
        }
        if self.globs.is_match(&name) {
            return true;
        }
        for re in &self.regexes {
            if re.is_match(&name) {
                return true;
            }
        }
        false
    }

    /// Total number of patterns loaded, for logging.
    pub fn len(&self) -> usize {
        self.exact.len() + self.suffixes.len() + self.globs.len() + self.regexes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn exact_count(&self) -> usize {
        self.exact.len()
    }
    pub fn suffix_count(&self) -> usize {
        self.suffixes.len()
    }
    pub fn wildcard_count(&self) -> usize {
        self.globs.len()
    }
    pub fn regex_count(&self) -> usize {
        self.regexes.len()
    }

    /// Regex sources, for debug logging.
    pub fn regex_sources(&self) -> &[String] {
        &self.regex_sources
    }
}

/// Force a user-supplied regex to match the entire name: strip any anchors the user
/// already added, then wrap in `^(?:...)$`.
fn anchor_regex(body: &str) -> String {
    let trimmed = body.trim();
    let trimmed = trimmed.strip_prefix('^').unwrap_or(trimmed);
    let trimmed = trimmed.strip_suffix('$').unwrap_or(trimmed);
    format!("^(?:{trimmed})$")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set() -> PatternSet {
        PatternSet::parse(
            "
            # comment
            api.anthropic.com
            .sentry.io
            *.gallery.vsassets.io
            re:^[a-z0-9-]+\\.pkg\\.dev$
            ",
        )
        .unwrap()
    }

    #[test]
    fn exact_match() {
        let s = set();
        assert!(s.is_allowed("api.anthropic.com"));
        assert!(s.is_allowed("API.anthropic.com.")); // case + trailing dot
        assert!(!s.is_allowed("evil.anthropic.com"));
    }

    #[test]
    fn suffix_match() {
        let s = set();
        assert!(s.is_allowed("sentry.io")); // bare apex
        assert!(s.is_allowed("o123.ingest.sentry.io"));
        assert!(!s.is_allowed("notsentry.io"));
        assert!(!s.is_allowed("sentry.io.evil.com"));
    }

    #[test]
    fn wildcard_match() {
        let s = set();
        assert!(s.is_allowed("anthropic.gallery.vsassets.io"));
        assert!(s.is_allowed("a.b.gallery.vsassets.io")); // multi-label
        assert!(!s.is_allowed("gallery.vsassets.io")); // needs a leading label
    }

    #[test]
    fn regex_match() {
        let s = set();
        assert!(s.is_allowed("my-pkg.pkg.dev"));
        assert!(!s.is_allowed("my-pkg.pkg.dev.evil.com"));
        assert!(s.is_allowed("UPPER.pkg.dev")); // lowercased before match
    }

    #[test]
    fn json_list_parsed() {
        let cfg = Config::parse(
            "
            api.anthropic.com
            JsonList(https://api.github.com/meta, [web, api, git])
            .sentry.io
            ",
        )
        .unwrap();
        assert_eq!(cfg.ip_lists.len(), 1);
        assert_eq!(cfg.ip_lists[0].url, "https://api.github.com/meta");
        assert_eq!(cfg.ip_lists[0].keys, ["web", "api", "git"]);
        // JsonList line must not be treated as a domain pattern.
        assert!(!cfg.patterns.is_allowed("jsonlist"));
        assert!(cfg.patterns.is_allowed("api.anthropic.com"));
    }

    #[test]
    fn json_list_ignored_by_pattern_set() {
        // PatternSet::parse must silently skip JsonList lines.
        let s = PatternSet::parse(
            "
            JsonList(https://api.github.com/meta, [web, api, git])
            api.anthropic.com
            ",
        )
        .unwrap();
        assert!(s.is_allowed("api.anthropic.com"));
    }
}
