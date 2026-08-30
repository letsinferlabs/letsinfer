// SPDX-License-Identifier: AGPL-3.0-only

use std::env;
use std::io::{self, IsTerminal, Write};

use crate::li_installer_event::InstallerEvent;

// Stores the one native owner of installation presentation and interaction.
pub struct DisplayManager {
    badge: String,
    blue: String,
    dim: String,
    green: String,
    interactive: bool,
    progress_active: bool,
    red: String,
    reset: String,
    success_mark: &'static str,
    failure_mark: &'static str,
    writer: Box<dyn Write>,
}

impl DisplayManager {
    // Configures presentation from the inherited terminal and locale contract.
    pub fn new(progress_enabled: bool) -> Self {
        let standard_error = io::stderr();
        let interactive = standard_error.is_terminal()
            && !matches!(env::var("TERM").as_deref(), Ok("") | Ok("dumb"));
        let locale = env::var("LC_ALL")
            .or_else(|_| env::var("LC_CTYPE"))
            .or_else(|_| env::var("LANG"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        let unicode = locale.contains("utf-8") || locale.contains("utf8");
        let color = interactive && env::var_os("NO_COLOR").is_none();
        Self::configured(
            progress_enabled,
            interactive,
            unicode,
            color,
            Box::new(standard_error),
        )
    }

    // Creates one presentation owner from explicit terminal facts and an exact writer.
    fn configured(
        progress_enabled: bool,
        interactive: bool,
        unicode: bool,
        color: bool,
        writer: Box<dyn Write>,
    ) -> Self {
        let brand_mark = if unicode { "ϟ" } else { ">" };
        let (reset, blue, green, red, dim, badge) = if color {
            (
                "\x1b[0m".to_string(),
                "\x1b[1;38;2;0;156;223m".to_string(),
                "\x1b[1;38;2;97;187;70m".to_string(),
                "\x1b[1;38;2;226;56;56m".to_string(),
                "\x1b[2m".to_string(),
                format!(
                    "\x1b[1;38;2;30;30;30;48;2;247;247;247m {}  LET'S INFER \x1b[0m",
                    brand_mark
                ),
            )
        } else {
            (
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                format!("{}  LET'S INFER", brand_mark),
            )
        };
        Self {
            badge,
            blue,
            dim,
            green,
            interactive,
            progress_active: interactive && progress_enabled,
            red,
            reset,
            success_mark: if unicode { "✓" } else { "+" },
            failure_mark: if unicode { "✗" } else { "x" },
            writer,
        }
    }

    // Presents one typed lifecycle transition without exposing display mechanics.
    pub fn present(&mut self, event: InstallerEvent) {
        let (percent, message) = event.presentation();
        self.progress(percent, message);
    }

    // Presents one stable native progress row when the terminal supports it.
    pub fn progress(&mut self, percent: u8, message: &str) {
        if !self.progress_active {
            return;
        }
        let _ = write!(
            self.writer,
            "\r\x1b[2K{}  {}INSTALL{}  {}{:>3}%{}  {}",
            self.badge, self.blue, self.reset, self.blue, percent, self.reset, message
        );
        let _ = self.writer.flush();
    }

    // Clears the active progress row before presenting a persistent message.
    pub fn clear_progress(&mut self) {
        if self.progress_active {
            let _ = write!(self.writer, "\r\x1b[2K");
            let _ = self.writer.flush();
        }
    }

    // Presents one native installation notice on its own stable line.
    pub fn notice(&mut self, message: &str) {
        self.clear_progress();
        let _ = writeln!(self.writer, "letsinfer install: {}", message);
    }

    // Requests one explicit mutation approval from the controlling terminal.
    pub fn request_approval(&mut self, description: &str) -> bool {
        self.clear_progress();
        if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
            return false;
        }
        let _ = writeln!(self.writer, "{}", description);
        let _ = write!(self.writer, "Continue? [y/N] ");
        let _ = self.writer.flush();
        let mut answer = String::new();
        if io::stdin().read_line(&mut answer).is_err() {
            return false;
        }
        matches!(answer.trim(), "y" | "Y" | "yes" | "Yes" | "YES")
    }

    // Presents one native failure through the same installation vocabulary.
    pub fn failure(&mut self, reason: &str) {
        self.clear_progress();
        self.progress_active = false;
        if self.interactive {
            let _ = writeln!(
                self.writer,
                "{}  {}INSTALL{}\n\n{}{}  Installation failed{}\n   {}",
                self.badge, self.red, self.reset, self.red, self.failure_mark, self.reset, reason
            );
        } else {
            let _ = writeln!(self.writer, "letsinfer install: {}", reason);
        }
    }

    // Presents the final Core identity, platform, and optional setup details.
    pub fn completion(
        &mut self,
        version: &str,
        platform: &str,
        initialized: bool,
        details: &[(&str, &str)],
    ) {
        if self.progress_active {
            self.progress(100, "Complete");
            let _ = writeln!(self.writer);
            self.progress_active = false;
        }
        let completion = if initialized {
            "installed and initialized"
        } else {
            "installed"
        };
        if self.interactive {
            let _ = writeln!(
                self.writer,
                "{}  {}{}{}  Let's Infer {} {}",
                self.badge, self.green, self.success_mark, self.reset, version, completion
            );
            let _ = writeln!(self.writer, "   {}{}{}", self.dim, platform, self.reset);
        } else {
            let _ = writeln!(
                self.writer,
                "Let's Infer {} {} for {}.",
                version, completion, platform
            );
        }
        for (name, value) in details {
            let _ = writeln!(self.writer, "   {:<9} {}", name, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    // Shares captured presentation bytes with the test without changing writer ownership.
    #[derive(Clone)]
    struct DisplayCapture {
        bytes: Rc<RefCell<Vec<u8>>>,
    }

    impl DisplayCapture {
        // Creates one empty byte capture.
        fn new() -> Self {
            Self {
                bytes: Rc::new(RefCell::new(Vec::new())),
            }
        }

        // Returns the complete captured presentation as UTF-8.
        fn text(&self) -> String {
            String::from_utf8(self.bytes.borrow().clone()).expect("display output should be UTF-8")
        }
    }

    impl Write for DisplayCapture {
        // Appends one exact presentation segment to the shared capture.
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.bytes.borrow_mut().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        // Completes one deterministic in-memory write without external buffering.
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    // Keeps machine-oriented progress silent and completion, details, and failure byte-stable.
    #[test]
    fn machine_presentation_is_quiet_and_byte_stable() {
        let capture = DisplayCapture::new();
        let mut display =
            DisplayManager::configured(true, false, true, false, Box::new(capture.clone()));
        display.present(InstallerEvent::InspectingSystem);
        display.notice("Docker access is ready");
        display.completion(
            "1.2.3",
            "linux-arm64",
            true,
            &[("Node", "Home AI"), ("API", "http://127.0.0.1:8000/v1")],
        );
        display.failure("fixture failure");
        assert_eq!(
            capture.text(),
            concat!(
                "letsinfer install: Docker access is ready\n",
                "Let's Infer 1.2.3 installed and initialized for linux-arm64.\n",
                "   Node      Home AI\n",
                "   API       http://127.0.0.1:8000/v1\n",
                "letsinfer install: fixture failure\n",
            )
        );
    }

    // Keeps interactive progress and completion under one exact native installation language.
    #[test]
    fn interactive_presentation_uses_one_exact_installation_language() {
        let capture = DisplayCapture::new();
        let mut display =
            DisplayManager::configured(true, true, true, false, Box::new(capture.clone()));
        display.present(InstallerEvent::InspectingSystem);
        display.completion("1.2.3", "macos-arm64", false, &[]);
        assert_eq!(
            capture.text(),
            concat!(
                "\r\x1b[2Kϟ  LET'S INFER  INSTALL   50%  Inspecting system",
                "\r\x1b[2Kϟ  LET'S INFER  INSTALL  100%  Complete\n",
                "ϟ  LET'S INFER  ✓  Let's Infer 1.2.3 installed\n",
                "   macos-arm64\n",
            )
        );
    }

    // Keeps the non-Unicode interactive failure vocabulary and fallback marks exact.
    #[test]
    fn interactive_failure_language_has_an_exact_ascii_fallback() {
        let capture = DisplayCapture::new();
        let mut display =
            DisplayManager::configured(true, true, false, false, Box::new(capture.clone()));
        display.failure("fixture failure");
        assert_eq!(
            capture.text(),
            concat!(
                "\r\x1b[2K>  LET'S INFER  INSTALL\n\n",
                "x  Installation failed\n",
                "   fixture failure\n",
            )
        );
    }
}
