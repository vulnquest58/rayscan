use clap::ValueEnum;
use comfy_table::{Color, presets};
use serde::Deserialize;

use crate::model::PortState;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    Dark,
    Light,
    Hacker,
    Minimal,
}

impl Theme {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dark => "dark",
            Self::Light => "light",
            Self::Hacker => "hacker",
            Self::Minimal => "minimal",
        }
    }

    pub const fn accent(self) -> Color {
        match self {
            Self::Dark => Color::Cyan,
            Self::Light => Color::Blue,
            Self::Hacker => Color::Green,
            Self::Minimal => Color::Reset,
        }
    }

    pub fn state(self, state: PortState) -> Option<Color> {
        if self == Self::Minimal {
            return None;
        }
        Some(match (self, state) {
            (Self::Hacker, PortState::Open) => Color::Green,
            (Self::Hacker, PortState::Closed) => Color::DarkGreen,
            (Self::Hacker, _) => Color::DarkGrey,
            (Self::Light, PortState::Open) => Color::DarkGreen,
            (Self::Light, PortState::Closed) => Color::DarkRed,
            (Self::Light, PortState::Filtered) => Color::DarkYellow,
            (Self::Light, PortState::Silent) => Color::Grey,
            (_, PortState::Open) => Color::Green,
            (_, PortState::Closed) => Color::Red,
            (_, PortState::Filtered) => Color::Yellow,
            (_, PortState::Silent) => Color::DarkGrey,
            (_, PortState::Unreachable) => Color::Magenta,
            (_, PortState::Error) => Color::Red,
        })
    }

    pub fn table_preset(self) -> &'static str {
        if self == Self::Minimal {
            presets::NOTHING
        } else {
            presets::UTF8_FULL
        }
    }

    pub const fn progress_template(self) -> &'static str {
        match self {
            Self::Dark => {
                "{spinner:.cyan} {bar:40.cyan/blue} {pos}/{len} {per_sec} ETA {eta} | {msg}"
            }
            Self::Light => {
                "{spinner:.blue} {bar:40.blue/white} {pos}/{len} {per_sec} ETA {eta} | {msg}"
            }
            Self::Hacker => {
                "{spinner:.green} {bar:40.green/black} {pos}/{len} {per_sec} ETA {eta} | {msg}"
            }
            Self::Minimal => "{pos}/{len} {per_sec} ETA {eta} | {msg}",
        }
    }
}

pub fn color_enabled(theme: Theme, is_tty: bool) -> bool {
    is_tty && theme != Theme::Minimal && std::env::var_os("NO_COLOR").is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_and_no_color_disable_styling() {
        assert!(!color_enabled(Theme::Minimal, true));
        assert!(color_enabled(Theme::Dark, true));
        assert!(!color_enabled(Theme::Dark, false));
    }

    #[test]
    fn hacker_theme_uses_a_green_palette() {
        assert_eq!(Theme::Hacker.accent(), Color::Green);
        assert_eq!(Theme::Hacker.state(PortState::Open), Some(Color::Green));
    }
}
