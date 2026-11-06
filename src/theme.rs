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
    Cyber,
}

impl Theme {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dark => "dark",
            Self::Light => "light",
            Self::Hacker => "hacker",
            Self::Minimal => "minimal",
            Self::Cyber => "cyber",
        }
    }

    pub const fn accent(self) -> Color {
        match self {
            Self::Dark => Color::Cyan,
            Self::Light => Color::Blue,
            Self::Hacker => Color::Green,
            Self::Minimal => Color::Reset,
            Self::Cyber => Color::Magenta,
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
            (Self::Cyber, PortState::Open) => Color::Cyan,
            (Self::Cyber, PortState::Closed) => Color::Magenta,
            (Self::Cyber, PortState::Filtered) => Color::Blue,
            (Self::Cyber, PortState::Silent) => Color::DarkGrey,
            (Self::Cyber, PortState::Unreachable) => Color::DarkMagenta,
            (Self::Cyber, PortState::Error) => Color::Red,
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
                "{spinner:.cyan} [{bar:24.cyan/blue}] {percent:>3}% {pos}/{len} | {per_sec} | ETA {eta} | {msg}"
            }
            Self::Cyber => {
                "{spinner:.magenta} [{bar:24.magenta/cyan}] {percent:>3}% {pos}/{len} | {per_sec} | ETA {eta} | {msg}"
            }
            Self::Light => {
                "{spinner:.blue} [{bar:24.blue/white}] {percent:>3}% {pos}/{len} | {per_sec} | ETA {eta} | {msg}"
            }
            Self::Hacker => {
                "{spinner:.green} [{bar:24.green/black}] {percent:>3}% {pos}/{len} | {per_sec} | ETA {eta} | {msg}"
            }
            Self::Minimal => "{percent:>3}% {pos}/{len} | {per_sec} | ETA {eta} | {msg}",
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

    #[test]
    fn cyber_theme_uses_cyan_and_magenta_palette() {
        assert_eq!(Theme::Cyber.accent(), Color::Magenta);
        assert_eq!(Theme::Cyber.state(PortState::Open), Some(Color::Cyan));
        assert_eq!(Theme::Cyber.state(PortState::Closed), Some(Color::Magenta));
        assert_eq!(Theme::Cyber.state(PortState::Filtered), Some(Color::Blue));
    }
}
