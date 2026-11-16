//! User settings, persisted as JSON in the platform config dir (`settings.json`).
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// How often the freezer rewrites frozen values.
    pub freeze_interval_ms: u64,
    /// How often the UI refreshes live values (table, results, memory view).
    pub live_update_ms: u64,
    /// First-scan defaults: fast scan + alignment, and the region tri-states (`yes`/`no`/`any`).
    pub fast_scan: bool,
    pub scan_alignment: u32,
    pub scan_writable: String,
    pub scan_executable: String,
    pub scan_copy_on_write: String,
    /// Scan worker threads; 0 = one per core (rayon's pool).
    pub scan_threads: usize,
    /// Wall-clock limit for one Lua run (console, table script, timer tick); 0 = unlimited.
    pub lua_budget_ms: u64,
    /// What to do with a table's Lua script on load: `ask` or `never`.
    pub table_script: String,
    /// Method for new execute breakpoints: `software` or `hardware`.
    pub bp_method: String,
    /// Beep when a hotkey fires.
    pub hotkey_sound: bool,
    /// `system`, `light` or `dark`.
    pub theme: String,
    /// Debugger: signal number -> `pass` / `ignore` / `break` (unlisted: hh-debug's default).
    pub signals: std::collections::BTreeMap<String, String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            freeze_interval_ms: 100,
            live_update_ms: 300,
            fast_scan: true,
            scan_alignment: 4,
            scan_writable: "yes".into(),
            scan_executable: "any".into(),
            scan_copy_on_write: "no".into(),
            scan_threads: 0,
            lua_budget_ms: 30_000,
            table_script: "ask".into(),
            bp_method: "software".into(),
            hotkey_sound: false,
            theme: "system".into(),
            signals: Default::default(),
        }
    }
}

impl Settings {
    /// Clamps numbers and replaces unknown enum strings with the defaults.
    pub fn normalized(mut self) -> Settings {
        let d = Settings::default();
        let pick = |v: &mut String, ok: &[&str], dflt: &str| {
            if !ok.contains(&v.as_str()) {
                *v = dflt.into();
            }
        };
        self.freeze_interval_ms = self.freeze_interval_ms.clamp(1, 60_000);
        self.live_update_ms = self.live_update_ms.clamp(50, 10_000);
        self.scan_alignment = self.scan_alignment.clamp(1, 64);
        self.scan_threads = self.scan_threads.min(256);
        self.lua_budget_ms = self.lua_budget_ms.min(3_600_000);
        let tri = ["yes", "no", "any"];
        pick(&mut self.scan_writable, &tri, &d.scan_writable);
        pick(&mut self.scan_executable, &tri, &d.scan_executable);
        pick(&mut self.scan_copy_on_write, &tri, &d.scan_copy_on_write);
        pick(&mut self.table_script, &["ask", "never"], &d.table_script);
        pick(&mut self.bp_method, &["software", "hardware"], &d.bp_method);
        pick(&mut self.theme, &["system", "light", "dark"], &d.theme);
        self.signals.retain(|k, v| k.parse::<u32>().is_ok() && ["pass", "ignore", "break"].contains(&v.as_str()));
        self
    }

    /// Defaults when the file is missing or unreadable (a broken file must not stop the app).
    pub fn load(path: &Path) -> Settings {
        std::fs::read_to_string(path).ok().and_then(|t| serde_json::from_str::<Settings>(&t).ok()).unwrap_or_default().normalized()
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_and_round_trip() {
        let s = Settings { freeze_interval_ms: 0, theme: "neon".into(), table_script: "always".into(), ..Settings::default() }.normalized();
        assert_eq!((s.freeze_interval_ms, s.theme.as_str(), s.table_script.as_str()), (1, "system", "ask"));
        let dir = std::env::temp_dir().join(format!("hh-settings-{}", std::process::id()));
        let p = dir.join("sub/settings.json");
        let s = Settings { lua_budget_ms: 0, theme: "dark".into(), ..Settings::default() };
        s.save(&p).unwrap();
        assert_eq!(Settings::load(&p), s);
        std::fs::write(&p, "{ not json").unwrap();
        assert_eq!(Settings::load(&p), Settings::default());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
