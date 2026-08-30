// SPDX-License-Identifier: AGPL-3.0-only

// Represents one meaningful transition in the native installation lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallerEvent {
    InspectingSystem,
    InstallingDependencies,
    VerifyingDependencies,
    DownloadingCore,
    VerifyingCore,
    InstallingCore,
    InitializingServices,
}

impl InstallerEvent {
    // Returns the stable progress position and user-facing lifecycle language.
    pub fn presentation(self) -> (u8, &'static str) {
        match self {
            Self::InspectingSystem => (50, "Inspecting system"),
            Self::InstallingDependencies => (58, "Installing dependencies"),
            Self::VerifyingDependencies => (64, "Verifying dependencies"),
            Self::DownloadingCore => (70, "Downloading Core"),
            Self::VerifyingCore => (78, "Verifying Core"),
            Self::InstallingCore => (84, "Installing Core"),
            Self::InitializingServices => (91, "Initializing services"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Keeps every native lifecycle position and user-facing message exact after handoff.
    #[test]
    fn native_progress_language_is_exact_and_strictly_ordered() {
        let events = [
            InstallerEvent::InspectingSystem,
            InstallerEvent::InstallingDependencies,
            InstallerEvent::VerifyingDependencies,
            InstallerEvent::DownloadingCore,
            InstallerEvent::VerifyingCore,
            InstallerEvent::InstallingCore,
            InstallerEvent::InitializingServices,
        ];
        let presentations = events.map(InstallerEvent::presentation);
        assert_eq!(
            presentations,
            [
                (50, "Inspecting system"),
                (58, "Installing dependencies"),
                (64, "Verifying dependencies"),
                (70, "Downloading Core"),
                (78, "Verifying Core"),
                (84, "Installing Core"),
                (91, "Initializing services"),
            ]
        );
        let values = presentations.map(|presentation| presentation.0);
        assert!(values.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(values[0] >= 50);
        assert!(values[values.len() - 1] < 100);
    }
}
