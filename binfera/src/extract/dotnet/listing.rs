//! A readable IL listing for every managed method: the view a `.NET` file gets in the viewer
//! (IDA lists every method of a managed file by its metadata name and shows its IL; there is no
//! native code to decompile).
//!
//! Operands are resolved from the metadata the file carries: `MethodDef`, `MemberRef`, `TypeDef`,
//! `TypeRef` and `Field` tokens print as `Namespace.Class::Member`, user strings as quoted
//! literals, branch targets as `IL_xxxx` labels. A token the metadata cannot resolve prints as
//! its hexadecimal value so nothing is silently dropped.

use std::collections::HashMap;
use std::fmt::Write;

use dnfile::lang::cil::enums::OperandType;
use dnfile::lang::cil::instruction::{Instruction, Operand};
use dnfile::DnPe;

use super::function::{managed_method_bodies, DnFunction};
use super::types::DnType;
use super::{fields, managed_imports, managed_methods, types};
use crate::extract::ExtractError;
use crate::features::Access;

/// One IL instruction of a method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IlRow {
    /// Offset from the first opcode byte, the `IL_xxxx` label of the instruction.
    pub offset: u32,
    pub bytes: String,
    pub text: String,
}

/// A managed method and its IL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodListing {
    pub token: u32,
    /// `Namespace.Class::Method`, from the metadata.
    pub name: String,
    pub rows: Vec<IlRow>,
    /// The method as text: header comment, then one line per instruction.
    pub text: String,
}

/// Names for every token an operand can reference.
struct Names {
    by_token: HashMap<u32, String>,
}

impl Names {
    fn build(pe: &DnPe<'_>) -> Result<Self, ExtractError> {
        let mut by_token = HashMap::new();
        let accessor = |t: &DnType| {
            // The name model strips `get_`/`set_` for rule matching; the listing wants the
            // method as written.
            let member = match t.access {
                Some(Access::Read) => format!("get_{}", t.member),
                Some(Access::Write) => format!("set_{}", t.member),
                // The name model drops the leading dot of `.ctor`/`.cctor` for rule matching.
                None if matches!(t.member.as_str(), "ctor" | "cctor") => format!(".{}", t.member),
                None => t.member.clone(),
            };
            DnType::format_name(&t.class, &t.namespace, &member)
        };
        for t in types(pe)? {
            by_token.insert(t.token, t.to_string());
        }
        for t in fields(pe)? {
            by_token.insert(t.token, t.to_string());
        }
        for t in managed_imports(pe)? {
            by_token.insert(t.token, accessor(&t));
        }
        for t in managed_methods(pe)? {
            by_token.insert(t.token, accessor(&t));
        }
        Ok(Self { by_token })
    }

    fn token(&self, token: u32) -> String {
        self.by_token
            .get(&token)
            .cloned()
            .unwrap_or_else(|| format!("0x{token:08x}"))
    }
}

/// Every managed method with a body, in `MethodDef` table order.
pub fn method_listings(pe: &DnPe<'_>) -> Result<Vec<MethodListing>, ExtractError> {
    let names = Names::build(pe)?;
    let net = pe.net().map_err(|e| ExtractError::Parse(e.to_string()))?;
    managed_method_bodies(pe)?
        .iter()
        .map(|function| Ok(listing(function, &names, |rid| net.get_us(rid).ok())))
        .collect()
}

fn listing(
    function: &DnFunction<'_>,
    names: &Names,
    user_string: impl Fn(usize) -> Option<String>,
) -> MethodListing {
    let code_start = function.body.offset + function.body.header_size();
    let label = |target: i64| format!("IL_{:04x}", target.saturating_sub(code_start as i64));
    let rows: Vec<IlRow> = function
        .body
        .instructions
        .iter()
        .map(|insn| IlRow {
            offset: insn.offset.saturating_sub(code_start) as u32,
            bytes: insn.opcode_bytes.iter().chain(&insn.operand_bytes).fold(
                String::new(),
                |mut s, b| {
                    let _ = write!(s, "{b:02x}");
                    s
                },
            ),
            text: instruction_text(insn, names, &user_string, &label),
        })
        .collect();
    let name = names.token(function.token);
    // Exception regions are already relative to the first opcode byte.
    let il = |offset: i64| format!("IL_{offset:04x}");
    let mut text = format!(
        "// {name}\n// token 0x{:08x}, max stack {}, {} instructions\n",
        function.token,
        function.body.max_stack(),
        rows.len()
    );
    for handler in function.body.exception_handlers() {
        let _ = writeln!(
            text,
            "// {} try {}..{} handler {}..{}",
            match handler.exception_type {
                0 => "catch",
                1 => "filter",
                2 => "finally",
                _ => "fault",
            },
            il(handler.try_start),
            il(handler.try_end),
            il(handler.handler_start),
            il(handler.handler_end),
        );
    }
    for row in &rows {
        let _ = writeln!(text, "IL_{:04x}: {}", row.offset, row.text);
    }
    MethodListing {
        token: function.token,
        name,
        rows,
        text,
    }
}

fn instruction_text(
    insn: &Instruction,
    names: &Names,
    user_string: &impl Fn(usize) -> Option<String>,
    label: &impl Fn(i64) -> String,
) -> String {
    let mnemonic = insn.opcode.name;
    let operand = match (&insn.opcode.operand_type, &insn.operand) {
        (OperandType::InlineNone, _) | (_, Operand::None) => return mnemonic.to_owned(),
        (_, Operand::StringToken(token)) => user_string(token.rid()).map_or_else(
            || format!("0x{:08x}", token.value),
            |s| format!("\"{}\"", escape(&s)),
        ),
        (_, Operand::Token(token)) => names.token(token.value as u32),
        (OperandType::InlineBrTarget | OperandType::ShortInlineBrTarget, Operand::Int(target)) => {
            label(*target)
        }
        (_, Operand::Arguments(targets)) => targets
            .iter()
            .map(|t| match t {
                Operand::Int(target) => label(*target),
                _ => "?".to_owned(),
            })
            .collect::<Vec<_>>()
            .join(", "),
        (_, Operand::Int(value)) => value.to_string(),
        (_, Operand::Float(value)) => value.to_string(),
        (_, Operand::Local(local)) => local.index().to_string(),
        (_, Operand::Argument(argument)) => argument.index().to_string(),
    };
    format!("{mnemonic} {operand}")
}

/// A C-style literal body: the escapes C# and the viewer's other languages share.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_what_would_break_a_literal() {
        assert_eq!(escape("a\"b\\c\n\u{1}"), "a\\\"b\\\\c\\n\\u0001");
    }
}
