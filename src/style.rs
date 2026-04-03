use console::{style, Emoji, Term};

pub static CHECK: Emoji<'_, '_> = Emoji("✓ ", "+ ");
pub static CROSS: Emoji<'_, '_> = Emoji("✗ ", "x ");
pub static WARN: Emoji<'_, '_> = Emoji("⚠ ", "! ");

pub fn success(msg: &str) -> String {
    format!("  {} {}", style(CHECK).green(), msg)
}

pub fn failure(msg: &str) -> String {
    format!("  {} {}", style(CROSS).dim(), msg)
}

pub fn warning(msg: &str) -> String {
    format!("  {} {}", style(WARN).yellow(), msg)
}

pub fn header(msg: &str) -> String {
    format!("\n  {}", style(msg).bold())
}

pub fn hint(msg: &str) -> String {
    format!("    {}", style(msg).dim())
}

pub fn error_display(err: &anyhow::Error) {
    let term = Term::stderr();
    let _ = term.write_line(&format!(
        "\n  {} {}",
        style(CROSS).red().bold(),
        style("Error").red().bold()
    ));
    let _ = term.write_line(&format!("  {}", err));
    for cause in err.chain().skip(1) {
        let _ = term.write_line(&format!(
            "  {} {}",
            style("Caused by:").dim(),
            cause
        ));
    }
    let _ = term.write_line("");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_returns_non_empty() {
        let s = success("test message");
        assert!(!s.is_empty());
        assert!(s.contains("test message"));
    }

    #[test]
    fn failure_returns_non_empty() {
        let s = failure("failed thing");
        assert!(!s.is_empty());
        assert!(s.contains("failed thing"));
    }

    #[test]
    fn warning_returns_non_empty() {
        let s = warning("warn thing");
        assert!(!s.is_empty());
        assert!(s.contains("warn thing"));
    }

    #[test]
    fn header_returns_non_empty() {
        let s = header("Header Text");
        assert!(!s.is_empty());
        assert!(s.contains("Header Text"));
    }

    #[test]
    fn hint_returns_non_empty() {
        let s = hint("hint text");
        assert!(!s.is_empty());
        assert!(s.contains("hint text"));
    }
}
