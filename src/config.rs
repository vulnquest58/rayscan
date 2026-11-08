use std::path::{Path, PathBuf};

use clap::ValueEnum;
use serde::Deserialize;

use crate::error::AppError;
use crate::model::{PortState, StateSet};
use crate::output::OutputFormat;
use crate::theme::Theme;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StateFilter {
    Open,
    Closed,
    Filtered,
    Silent,
    Unreachable,
    Error,
    All,
}

impl StateFilter {
    pub fn to_set(self) -> StateSet {
        match self {
            Self::Open => state_set(&[Self::Open]),
            Self::Closed => state_set(&[Self::Closed]),
            Self::Filtered => state_set(&[Self::Filtered]),
            Self::Silent => state_set(&[Self::Silent]),
            Self::Unreachable => state_set(&[Self::Unreachable]),
            Self::Error => state_set(&[Self::Error]),
            Self::All => StateSet::all(),
        }
    }
}

pub fn state_set(filters: &[StateFilter]) -> StateSet {
    let mut set = StateSet::empty();
    for filter in filters {
        if *filter == StateFilter::All {
            return StateSet::all();
        }
        let state = match filter {
            StateFilter::Open => PortState::Open,
            StateFilter::Closed => PortState::Closed,
            StateFilter::Filtered => PortState::Filtered,
            StateFilter::Silent => PortState::Silent,
            StateFilter::Unreachable => PortState::Unreachable,
            StateFilter::Error => PortState::Error,
            StateFilter::All => unreachable!("handled above"),
        };
        set.insert(state);
    }
    set
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Fast,
    #[default]
    Balanced,
    Careful,
    Stealth,
}

impl Profile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Balanced => "balanced",
            Self::Careful => "careful",
            Self::Stealth => "stealth",
        }
    }

    pub const fn defaults(self) -> ProfileDefaults {
        match self {
            Self::Fast => ProfileDefaults {
                timeout_seconds: 1.0,
                probe_timeout_ms: 150,
                rate: 5_000,
                workers: 0,
                retries: 1,
            },
            Self::Balanced => ProfileDefaults {
                timeout_seconds: 2.0,
                probe_timeout_ms: 300,
                rate: 1_000,
                workers: 0,
                retries: 2,
            },
            Self::Careful => ProfileDefaults {
                timeout_seconds: 5.0,
                probe_timeout_ms: 750,
                rate: 200,
                workers: 128,
                retries: 3,
            },
            Self::Stealth => ProfileDefaults {
                timeout_seconds: 5.0,
                probe_timeout_ms: 1000,
                rate: 20,
                workers: 8,
                retries: 3,
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ProfileDefaults {
    pub timeout_seconds: f64,
    pub probe_timeout_ms: u64,
    pub rate: u64,
    pub workers: usize,
    pub retries: u32,
}

/// Optional TOML configuration. CLI arguments always take precedence.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub profile: Option<Profile>,
    pub timeout: Option<f64>,
    pub probe_timeout_ms: Option<u64>,
    pub rate: Option<u64>,
    pub workers: Option<usize>,
    pub retries: Option<u32>,
    pub randomize: Option<bool>,
    pub connect_only: Option<bool>,
    pub service_detection: Option<bool>,
    pub udp_probe: Option<bool>,
    pub format: Option<OutputFormat>,
    pub show: Option<Vec<StateFilter>>,
    pub theme: Option<Theme>,
    pub plugins: Option<PathBuf>,
    pub jitter_ms: Option<u64>,
}

pub fn load(path: Option<&Path>) -> Result<FileConfig, AppError> {
    let path = match path {
        Some(path) => Some(path.to_path_buf()),
        None => {
            let default = PathBuf::from("rayscan.toml");
            default.is_file().then_some(default)
        }
    };

    let Some(path) = path else {
        return Ok(FileConfig::default());
    };

    let contents = std::fs::read_to_string(&path).map_err(|error| {
        AppError::usage(format!("cannot read config {}: {error}", path.display()))
    })?;
    toml::from_str(&contents)
        .map_err(|error| AppError::usage(format!("invalid config {}: {error}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_complete_config() {
        let config: FileConfig = toml::from_str(
            r#"
profile = "careful"
timeout = 3.5
probe_timeout_ms = 400
rate = 500
workers = 64
retries = 1
randomize = true
connect_only = false
service_detection = true
udp_probe = true
format = "jsonl"
show = ["open", "closed"]
theme = "hacker"
"#,
        )
        .unwrap();

        assert_eq!(config.profile, Some(Profile::Careful));
        assert_eq!(config.timeout, Some(3.5));
        assert_eq!(config.service_detection, Some(true));
        assert_eq!(config.udp_probe, Some(true));
        assert_eq!(config.format, Some(OutputFormat::Jsonl));
        assert_eq!(config.show.unwrap().len(), 2);
        assert_eq!(config.theme, Some(Theme::Hacker));
    }

    #[test]
    fn rejects_unknown_config_keys() {
        let error = toml::from_str::<FileConfig>("typo = 1").unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn profile_defaults_are_ordered_by_caution() {
        let fast = Profile::Fast.defaults();
        let balanced = Profile::Balanced.defaults();
        let careful = Profile::Careful.defaults();
        let stealth = Profile::Stealth.defaults();

        assert!(
            fast.rate > balanced.rate
                && balanced.rate > careful.rate
                && careful.rate > stealth.rate
        );
        assert!(fast.timeout_seconds < balanced.timeout_seconds);
        assert!(balanced.timeout_seconds < careful.timeout_seconds);
        assert!(careful.timeout_seconds <= stealth.timeout_seconds);
    }

    #[test]
    fn state_filters_union_and_all_short_circuits() {
        let set = state_set(&[StateFilter::Open, StateFilter::Closed]);
        assert!(set.contains(PortState::Open));
        assert!(set.contains(PortState::Closed));
        assert!(!set.contains(PortState::Filtered));
        assert_eq!(
            state_set(&[StateFilter::Open, StateFilter::All]),
            StateSet::all()
        );
    }
}
