//! The filter DSL (`PLAN.md` §9): a proper boolean expression language with real
//! operator precedence, parentheses, and regex — replacing the prototype's
//! `str.split(' AND ')` hack.
//!
//! Grammar (lowest precedence first):
//!
//! ```text
//! expr     = or_expr
//! or_expr  = and_expr ("OR"  and_expr)*
//! and_expr = not_expr ("AND" not_expr)*
//! not_expr = "NOT" not_expr | primary
//! primary  = "(" expr ")" | comparison
//! comparison = field op value
//! op       = "==" | "!=" | ">=" | "<=" | ">" | "<" | "IN" | "CONTAINS" | "=~"
//! field    = IDENT ("." IDENT)*
//! value    = STRING | NUMBER | "[" (value ("," value)*)? "]"
//! ```
//!
//! Precedence is `NOT > AND > OR` (the conventional ordering). The prototype
//! evaluated AND as the outermost split (AND lowest), but since no rule in
//! `rules.yaml` mixes AND and OR at the same level, both orderings produce
//! identical verdicts on the shipped ruleset — so this proper parser stays
//! backwards-compatible while fixing the semantics.
//!
//! Comparison semantics mirror the prototype closely: a missing field compares as
//! the empty string for `==`/`!=`; numeric operators parse both sides as f64 and
//! yield `false` if either side is non-numeric; `IN`/`CONTAINS` are string
//! membership / substring; `=~` is a regex match (compiled once at parse time).

use std::fmt;

use loghound_core::Event;
use regex::Regex;

/// A parsed, ready-to-evaluate filter expression.
#[derive(Debug, Clone)]
pub enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Cmp(Comparison),
}

/// A single `field op value` comparison.
#[derive(Debug, Clone)]
pub struct Comparison {
    pub field: String,
    pub op: CmpOp,
}

/// The comparison operator plus its right-hand operand.
#[derive(Debug, Clone)]
pub enum CmpOp {
    Eq(String),
    Ne(String),
    Gt(String),
    Lt(String),
    Ge(String),
    Le(String),
    In(Vec<String>),
    Contains(String),
    Regex(Regex),
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("unexpected end of filter")]
    UnexpectedEof,
    #[error("unexpected token {0:?}")]
    Unexpected(String),
    #[error("expected {expected}, found {found}")]
    Expected { expected: String, found: String },
    #[error("invalid regex `{pattern}`: {source}")]
    BadRegex {
        pattern: String,
        #[source]
        source: regex::Error,
    },
    #[error("empty filter")]
    Empty,
}

impl Expr {
    /// Parse a filter string into an expression tree.
    pub fn parse(input: &str) -> Result<Expr, ParseError> {
        let tokens = lex(input)?;
        if tokens.is_empty() {
            return Err(ParseError::Empty);
        }
        let mut p = Parser { tokens, pos: 0 };
        let expr = p.parse_or()?;
        if p.pos != p.tokens.len() {
            return Err(ParseError::Unexpected(format!("{:?}", p.tokens[p.pos])));
        }
        Ok(expr)
    }

    /// Evaluate this expression against an event.
    pub fn eval(&self, ev: &Event) -> bool {
        match self {
            Expr::Or(a, b) => a.eval(ev) || b.eval(ev),
            Expr::And(a, b) => a.eval(ev) && b.eval(ev),
            Expr::Not(e) => !e.eval(ev),
            Expr::Cmp(c) => c.eval(ev),
        }
    }
}

impl Comparison {
    fn eval(&self, ev: &Event) -> bool {
        let lhs = ev.get(&self.field);
        match &self.op {
            CmpOp::Eq(v) => lhs.as_deref().unwrap_or("") == v,
            CmpOp::Ne(v) => lhs.as_deref().unwrap_or("") != v,
            CmpOp::Contains(v) => lhs.map(|s| s.contains(v)).unwrap_or(false),
            CmpOp::In(list) => lhs.map(|s| list.contains(&s)).unwrap_or(false),
            CmpOp::Regex(re) => lhs.map(|s| re.is_match(&s)).unwrap_or(false),
            CmpOp::Gt(v) => num_cmp(lhs, v, |a, b| a > b),
            CmpOp::Lt(v) => num_cmp(lhs, v, |a, b| a < b),
            CmpOp::Ge(v) => num_cmp(lhs, v, |a, b| a >= b),
            CmpOp::Le(v) => num_cmp(lhs, v, |a, b| a <= b),
        }
    }
}

/// Numeric comparison: `false` unless both sides parse as f64 (mirrors the
/// prototype's `float()`-with-`ValueError`→`False` behavior).
fn num_cmp(lhs: Option<String>, rhs: &str, f: impl Fn(f64, f64) -> bool) -> bool {
    match (
        lhs.and_then(|s| s.trim().parse::<f64>().ok()),
        rhs.trim().parse::<f64>().ok(),
    ) {
        (Some(a), Some(b)) => f(a, b),
        _ => false,
    }
}

// ---------------- lexer ----------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String), // field path or a bare (unquoted) value/number
    Str(String),  // quoted string literal (quotes stripped)
    And,
    Or,
    Not,
    Op(OpTok),
    LBracket,
    RBracket,
    LParen,
    RParen,
    Comma,
}

#[derive(Debug, Clone, PartialEq)]
enum OpTok {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    Regex,
    In,
    Contains,
}

impl fmt::Display for Tok {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

fn lex(input: &str) -> Result<Vec<Tok>, ParseError> {
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '\'' | '"' => {
                let quote = c;
                i += 1;
                let start = i;
                while i < chars.len() && chars[i] != quote {
                    i += 1;
                }
                if i >= chars.len() {
                    return Err(ParseError::Unexpected("unterminated string".into()));
                }
                let s: String = chars[start..i].iter().collect();
                out.push(Tok::Str(s));
                i += 1; // closing quote
            }
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            '[' => {
                out.push(Tok::LBracket);
                i += 1;
            }
            ']' => {
                out.push(Tok::RBracket);
                i += 1;
            }
            ',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            '=' | '!' | '<' | '>' => {
                let next = chars.get(i + 1).copied();
                let (tok, len) = match (c, next) {
                    ('=', Some('=')) => (Tok::Op(OpTok::Eq), 2),
                    ('!', Some('=')) => (Tok::Op(OpTok::Ne), 2),
                    ('>', Some('=')) => (Tok::Op(OpTok::Ge), 2),
                    ('<', Some('=')) => (Tok::Op(OpTok::Le), 2),
                    ('=', Some('~')) => (Tok::Op(OpTok::Regex), 2),
                    ('>', _) => (Tok::Op(OpTok::Gt), 1),
                    ('<', _) => (Tok::Op(OpTok::Lt), 1),
                    _ => return Err(ParseError::Unexpected(format!("stray `{c}`"))),
                };
                out.push(tok);
                i += len;
            }
            _ => {
                // A bareword: field path or unquoted value. Runs until a
                // delimiter (whitespace, operator char, bracket, comma, quote).
                let start = i;
                while i < chars.len() {
                    let ch = chars[i];
                    if ch.is_whitespace()
                        || matches!(
                            ch,
                            '=' | '!' | '<' | '>' | '(' | ')' | '[' | ']' | ',' | '\'' | '"'
                        )
                    {
                        break;
                    }
                    i += 1;
                }
                let w: String = chars[start..i].iter().collect();
                out.push(classify_word(w));
            }
        }
    }
    Ok(out)
}

/// Classify a bareword as a keyword or a plain word. Keywords are case-sensitive
/// uppercase (as in the prototype), so a lowercase field named e.g. `in` is safe.
fn classify_word(w: String) -> Tok {
    match w.as_str() {
        "AND" => Tok::And,
        "OR" => Tok::Or,
        "NOT" => Tok::Not,
        "IN" => Tok::Op(OpTok::In),
        "CONTAINS" => Tok::Op(OpTok::Contains),
        _ => Tok::Word(w),
    }
}

// ---------------- parser ----------------

struct Parser {
    tokens: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn parse_or(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Tok::Or)) {
            self.pos += 1;
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_not()?;
        while matches!(self.peek(), Some(Tok::And)) {
            self.pos += 1;
            let right = self.parse_not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr, ParseError> {
        if matches!(self.peek(), Some(Tok::Not)) {
            self.pos += 1;
            let inner = self.parse_not()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        match self.peek() {
            Some(Tok::LParen) => {
                self.pos += 1;
                let e = self.parse_or()?;
                match self.next() {
                    Some(Tok::RParen) => Ok(e),
                    other => Err(ParseError::Expected {
                        expected: ")".into(),
                        found: describe(other.as_ref()),
                    }),
                }
            }
            Some(Tok::Word(_)) => self.parse_comparison(),
            other => Err(ParseError::Expected {
                expected: "field or (".into(),
                found: describe(other),
            }),
        }
    }

    fn parse_comparison(&mut self) -> Result<Expr, ParseError> {
        let field = match self.next() {
            Some(Tok::Word(w)) => w,
            other => {
                return Err(ParseError::Expected {
                    expected: "field".into(),
                    found: describe(other.as_ref()),
                })
            }
        };
        let op = match self.next() {
            Some(Tok::Op(op)) => op,
            other => {
                return Err(ParseError::Expected {
                    expected: "operator".into(),
                    found: describe(other.as_ref()),
                })
            }
        };
        let cmp = match op {
            OpTok::In => CmpOp::In(self.parse_list()?),
            OpTok::Regex => {
                let pat = self.parse_scalar()?;
                let re = Regex::new(&pat).map_err(|source| ParseError::BadRegex {
                    pattern: pat.clone(),
                    source,
                })?;
                CmpOp::Regex(re)
            }
            OpTok::Eq => CmpOp::Eq(self.parse_scalar()?),
            OpTok::Ne => CmpOp::Ne(self.parse_scalar()?),
            OpTok::Gt => CmpOp::Gt(self.parse_scalar()?),
            OpTok::Lt => CmpOp::Lt(self.parse_scalar()?),
            OpTok::Ge => CmpOp::Ge(self.parse_scalar()?),
            OpTok::Le => CmpOp::Le(self.parse_scalar()?),
            OpTok::Contains => CmpOp::Contains(self.parse_scalar()?),
        };
        Ok(Expr::Cmp(Comparison { field, op: cmp }))
    }

    /// A scalar value: a quoted string or a bareword (number/token).
    fn parse_scalar(&mut self) -> Result<String, ParseError> {
        match self.next() {
            Some(Tok::Str(s)) => Ok(s),
            Some(Tok::Word(w)) => Ok(w),
            other => Err(ParseError::Expected {
                expected: "value".into(),
                found: describe(other.as_ref()),
            }),
        }
    }

    /// A bracketed list `['a', 'b', ...]` of scalar values.
    fn parse_list(&mut self) -> Result<Vec<String>, ParseError> {
        match self.next() {
            Some(Tok::LBracket) => {}
            other => {
                return Err(ParseError::Expected {
                    expected: "[".into(),
                    found: describe(other.as_ref()),
                })
            }
        }
        let mut items = Vec::new();
        if matches!(self.peek(), Some(Tok::RBracket)) {
            self.pos += 1;
            return Ok(items);
        }
        loop {
            items.push(self.parse_scalar()?);
            match self.next() {
                Some(Tok::Comma) => continue,
                Some(Tok::RBracket) => break,
                other => {
                    return Err(ParseError::Expected {
                        expected: ", or ]".into(),
                        found: describe(other.as_ref()),
                    })
                }
            }
        }
        Ok(items)
    }
}

fn describe(t: Option<&Tok>) -> String {
    match t {
        Some(t) => format!("{t}"),
        None => "end of input".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loghound_core::event::class;
    use loghound_core::Timestamp;

    fn ev() -> Event {
        let mut e = Event::new(class::PROCESS_ACTIVITY, Timestamp(1000));
        e.process_name = Some("powershell.exe".into());
        e.set_field("process.cmd_line", "powershell -enc AAA net user");
        e.set_field("status", "Failure");
        e.activity_id = Some(3);
        e.set_field("group.name", "Domain Admins");
        e
    }

    fn matches(filter: &str, e: &Event) -> bool {
        Expr::parse(filter).expect("parses").eval(e)
    }

    #[test]
    fn equality_and_inequality() {
        let e = ev();
        assert!(matches("process.name == 'powershell.exe'", &e));
        assert!(!matches("process.name == 'cmd.exe'", &e));
        assert!(matches("process.name != 'cmd.exe'", &e));
        // Missing field compares as empty string.
        assert!(matches("missing.field != 'x'", &e));
        assert!(!matches("missing.field == 'x'", &e));
    }

    #[test]
    fn numeric_ops_parse_both_sides() {
        let e = ev();
        assert!(matches("activity_id == 3", &e)); // string-eq of "3"
        assert!(matches("activity_id >= 3", &e));
        assert!(matches("activity_id > 2", &e));
        assert!(!matches("activity_id > 3", &e));
        // Non-numeric field vs numeric op => false.
        assert!(!matches("process.name > 5", &e));
    }

    #[test]
    fn contains_and_in() {
        let e = ev();
        assert!(matches("process.cmd_line CONTAINS 'net user'", &e));
        assert!(!matches("process.cmd_line CONTAINS 'mimikatz'", &e));
        assert!(matches("process.name IN ['cmd.exe', 'powershell.exe']", &e));
        assert!(!matches("process.name IN ['cmd.exe', 'wmic.exe']", &e));
        assert!(matches(
            "group.name IN ['Administrators', 'Domain Admins']",
            &e
        ));
    }

    #[test]
    fn boolean_precedence_and_parens() {
        let e = ev();
        // AND binds tighter than OR.
        assert!(matches(
            "process.name == 'cmd.exe' OR process.name == 'powershell.exe' AND status == 'Failure'",
            &e
        ));
        // NOT binds tightest.
        assert!(matches("NOT process.name == 'cmd.exe'", &e));
        assert!(!matches("NOT process.name == 'powershell.exe'", &e));
        // Parens override precedence.
        assert!(!matches(
            "(process.name == 'cmd.exe' OR process.name == 'powershell.exe') AND status == 'Success'",
            &e
        ));
    }

    #[test]
    fn regex_operator() {
        let e = ev();
        assert!(matches(r"process.name =~ 'power.*\.exe'", &e));
        assert!(!matches(r"process.name =~ '^cmd'", &e));
    }

    #[test]
    fn real_rules_from_yaml_parse() {
        // A sampling of the exact filter strings shipped in rules.yaml.
        for f in [
            "status == 'Failure'",
            "activity_id == 3 AND status == 'Failure'",
            "process.name IN ['cmd.exe', 'powershell.exe', 'wmic.exe', 'psexec.exe']",
            "process.cmd_line CONTAINS 'net user' OR process.cmd_line CONTAINS 'whoami'",
            "process.name == 'rundll32.exe' AND process.cmd_line CONTAINS 'javascript:'",
            "activity_id == 2 AND group.name IN ['Administrators', 'Domain Admins', 'Enterprise Admins']",
        ] {
            Expr::parse(f).unwrap_or_else(|e| panic!("failed to parse {f:?}: {e}"));
        }
    }

    #[test]
    fn errors_are_reported() {
        assert!(matches!(Expr::parse(""), Err(ParseError::Empty)));
        assert!(Expr::parse("process.name ==").is_err());
        assert!(Expr::parse("(process.name == 'x'").is_err());
        assert!(Expr::parse("process.name =~ '('").is_err()); // bad regex
    }
}
