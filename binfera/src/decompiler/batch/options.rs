//! Options shared by batch and individual decompilation callers.
use super::*;
use crate::api::Format;
use crate::decompiler::ResourceLimits;

/// Whether resource-limited functions are retried after the ordinary queue settles.
#[derive(Debug, Clone, Default)]
pub enum RetryPolicy {
    #[default]
    Deferred,
    Skip,
    Only(Vec<u64>),
}

#[derive(Debug, Clone, Default)]
pub struct BatchOptions {
    pub retry: RetryPolicy,
    /// Limits for ordinary attempts; deferred retries use `ResourceLimits::retry()`.
    pub limits: ResourceLimits,
    pub format: Format,
    pub arch: Option<String>,
    pub os: Option<String>,
    /// Zero-based shard index and shard count. Every shard announces the full function set.
    pub shard: Option<(usize, usize)>,
}

impl BatchOptions {
    pub(super) fn validate(&self) -> Result<(), DecompileError> {
        if self
            .shard
            .is_some_and(|(index, count)| count == 0 || index >= count)
        {
            return Err(DecompileError::Request(
                "shard index must be less than a nonzero count".into(),
            ));
        }
        Ok(())
    }

    /// Recover the input and create its native session, applying explicit raw-code options.
    pub fn open(&self, bytes: &[u8]) -> Result<(DecompilerSession, Analysis), DecompileError> {
        self.open_recovered(bytes, None, Jobs::SERIAL)
    }

    pub(super) fn open_recovered(
        &self,
        bytes: &[u8],
        recovered: Option<Analysis>,
        signature_jobs: Jobs,
    ) -> Result<(DecompilerSession, Analysis), DecompileError> {
        use crate::decompiler::{CallingConvention as C, DecompilerSession};
        let convention = match (self.format, self.os.as_deref().unwrap_or("auto")) {
            (Format::Sc32, "auto" | "windows") => Some(C::WindowsX86),
            (Format::Sc64, "auto" | "windows") => Some(C::WindowsX64),
            (Format::Sc32, "linux") => Some(C::SystemVX86),
            (Format::Sc64, "linux") => Some(C::SystemVX64),
            (Format::Sc32 | Format::Sc64, _) => {
                return Err(crate::decompiler::DecompileError::Request(
                    "raw code supports --os windows or linux".into(),
                ))
            }
            _ => None,
        };
        if let Some(convention) = convention {
            let compatible = match self.format {
                Format::Sc32 => matches!(self.arch.as_deref().unwrap_or("auto"), "auto" | "i386"),
                Format::Sc64 => matches!(
                    self.arch.as_deref().unwrap_or("auto"),
                    "auto" | "amd64" | "x86_64"
                ),
                _ => true,
            };
            if !compatible {
                return Err(crate::decompiler::DecompileError::Request(
                    "raw-code format conflicts with --arch".into(),
                ));
            }
            if let Some(analysis) = recovered {
                let session =
                    DecompilerSession::from_analysis(&analysis, &Default::default(), convention)?;
                Ok((session, analysis))
            } else {
                DecompilerSession::from_shellcode_with_analysis(bytes, convention)
            }
        } else {
            match recovered {
                Some(analysis) => {
                    DecompilerSession::from_recovered(bytes, self.arch.as_deref(), analysis)
                }
                None => DecompilerSession::open_bytes(bytes, self.arch.as_deref(), signature_jobs),
            }
        }
    }
}
