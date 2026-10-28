//! The compiled decision table pushed by the Go control plane.
//!
//! For M1 only file-open decisions are handled locally; the matching is
//! deliberately simple and predictable (exact / prefix / suffix).

use crate::ipc::FileRule;

#[derive(Debug, Default, Clone)]
pub struct Snapshot {
    pub version: u64,
    pub rules: Vec<FileRule>,
}

impl Snapshot {
    pub fn replace(&mut self, version: u64, rules: Vec<FileRule>) {
        self.version = version;
        self.rules = rules;
    }

    /// decide returns the id of the first matching rule and whether it denies.
    pub fn decide(&self, path: &str) -> Option<(String, bool)> {
        for r in &self.rules {
            let matches = (!r.path_exact.is_empty() && r.path_exact == path)
                || (!r.path_prefix.is_empty() && path.starts_with(&r.path_prefix))
                || (!r.path_suffix.is_empty() && path.ends_with(&r.path_suffix));
            if matches {
                return Some((r.id.clone(), r.decision == "block"));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, decision: &str) -> FileRule {
        FileRule {
            id: id.to_string(),
            path_exact: String::new(),
            path_prefix: String::new(),
            path_suffix: String::new(),
            decision: decision.to_string(),
        }
    }

    #[test]
    fn prefix_denies() {
        let mut snap = Snapshot::default();
        let mut r = rule("deny-tmp", "block");
        r.path_prefix = "/tmp/edr-watch/".to_string();
        snap.replace(1, vec![r]);
        let got = snap.decide("/tmp/edr-watch/secret");
        assert_eq!(got, Some(("deny-tmp".to_string(), true)));
        assert_eq!(snap.decide("/etc/passwd"), None);
    }

    #[test]
    fn exact_and_suffix() {
        let mut snap = Snapshot::default();
        let mut e = rule("exact", "block");
        e.path_exact = "/etc/ld.so.preload".to_string();
        let mut s = rule("suffix", "block");
        s.path_suffix = "/authorized_keys".to_string();
        snap.replace(2, vec![e, s]);
        assert!(snap.decide("/etc/ld.so.preload").unwrap().1);
        assert!(snap.decide("/home/u/.ssh/authorized_keys").unwrap().1);
        assert_eq!(snap.decide("/home/u/.ssh/known_hosts"), None);
    }

    #[test]
    fn allow_rule_does_not_deny() {
        let mut snap = Snapshot::default();
        let mut a = rule("allow", "allow");
        a.path_prefix = "/var/log/".to_string();
        snap.replace(3, vec![a]);
        assert_eq!(snap.decide("/var/log/syslog"), Some(("allow".to_string(), false)));
    }
}
