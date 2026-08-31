//! Shell-completion generation from the canonical clap command tree.

use std::ffi::OsStr;
use std::io::Write;
use std::path::Path;

use clap::CommandFactory;
use clap_complete::{generate, shells};

use crate::args::{Cli, CompletionShell};

/// Resolves a supported shell from an absolute or bare executable name.
#[must_use]
pub fn detect(shell: &OsStr) -> Option<CompletionShell> {
    let name = Path::new(shell).file_name()?.to_str()?;
    match name {
        "bash" => Some(CompletionShell::Bash),
        "zsh" => Some(CompletionShell::Zsh),
        "fish" => Some(CompletionShell::Fish),
        _ => None,
    }
}

/// Writes a completion script derived from [`Cli`].
pub fn write(shell: CompletionShell, output: &mut impl Write) {
    let mut command = Cli::command();
    match shell {
        CompletionShell::Bash => generate(shells::Bash, &mut command, "omarchy-ai-bar", output),
        CompletionShell::Zsh => generate(shells::Zsh, &mut command, "omarchy-ai-bar", output),
        CompletionShell::Fish => generate(shells::Fish, &mut command, "omarchy-ai-bar", output),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_accepts_only_supported_shell_basenames() {
        assert_eq!(
            detect(OsStr::new("/usr/bin/bash")),
            Some(CompletionShell::Bash)
        );
        assert_eq!(detect(OsStr::new("zsh")), Some(CompletionShell::Zsh));
        assert_eq!(detect(OsStr::new("/bin/fish")), Some(CompletionShell::Fish));
        assert_eq!(detect(OsStr::new("/bin/sh")), None);
    }

    #[test]
    fn every_completion_is_nonempty_and_names_the_binary() {
        for shell in [
            CompletionShell::Bash,
            CompletionShell::Zsh,
            CompletionShell::Fish,
        ] {
            let mut output = Vec::new();
            write(shell, &mut output);
            let output = String::from_utf8(output).expect("UTF-8 completion");
            assert!(output.contains("omarchy-ai-bar"));
        }
    }
}
