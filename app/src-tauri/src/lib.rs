//! HeapHook desktop shell: command logic (`commands`, `debug`, `ptr`), the live cheat table
//! (`cheat`) and its files (`table`), the Lua engine (`lua`) and settings (`settings`).
//! The Tauri wiring lives in `main.rs`.
pub mod cheat;
pub mod commands;
pub mod debug;
pub mod inject;
pub mod lua;
pub mod ptr;
pub mod remote;
pub mod settings;
pub mod table;
pub mod tools;
pub mod trainer;
