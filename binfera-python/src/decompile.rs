//! Native decompilation: a reusable `Decompiler` session and a whole-image `decompile_all`.
//!
//! Both call the library the CLI calls (`DecompilerSession` and `decompile_all`), so a result
//! here is the one `binfera --decompile-function -j` and `--decompile-all` print from the same
//! bytes. Without the `decompiler` cargo feature the names still exist and raise `CapaError`.

#[cfg(feature = "decompiler")]
mod enabled {
    use binfera::api::Format;
    use binfera::decompiler::{
        decompile_all as run_all, BatchEvent, BatchOptions, DecompileError, DecompilerSession,
        ResourceLimits,
    };
    use pyo3::prelude::*;

    use crate::analyze::{json_to_py, parse_format, read_input};
    use crate::error::{CapaError, CorruptFileError, UnsupportedFormatError};

    fn error(e: DecompileError) -> PyErr {
        let message = e.to_string();
        match e {
            DecompileError::Unsupported(_) => UnsupportedFormatError::new_err(message),
            DecompileError::Request(_) => CapaError::new_err(message),
            _ => CorruptFileError::new_err(message),
        }
    }

    fn options(
        format: Option<&str>,
        arch: Option<String>,
        os: Option<String>,
        shard: Option<(usize, usize)>,
    ) -> PyResult<BatchOptions> {
        let format: Format = parse_format(format)?;
        Ok(BatchOptions {
            format,
            arch,
            os,
            shard,
            ..Default::default()
        })
    }

    fn serialize<T: serde::Serialize>(value: &T) -> PyResult<serde_json::Value> {
        serde_json::to_value(value)
            .map_err(|e| CorruptFileError::new_err(format!("serializing decompilation: {e}")))
    }

    /// An opened image ready to decompile any of its functions. Opening recovers the image's
    /// functions once; each `decompile` call then reuses that work.
    ///
    /// A session is tied to the thread that created it and holds the GIL while it works.
    #[pyclass(unsendable, module = "binfera")]
    pub struct Decompiler {
        session: DecompilerSession,
        functions: Vec<u64>,
    }

    #[pymethods]
    impl Decompiler {
        #[new]
        #[pyo3(signature = (data_or_path, *, format=None, arch=None, os=None))]
        fn new(
            data_or_path: &Bound<'_, PyAny>,
            format: Option<String>,
            arch: Option<String>,
            os: Option<String>,
        ) -> PyResult<Self> {
            let (bytes, _) = read_input(data_or_path)?;
            let bytes =
                binfera::extract::elf::without_corrupt_section_headers(&bytes).unwrap_or(bytes);
            let (session, analysis) = options(format.as_deref(), arch, os, None)?
                .open(&bytes)
                .map_err(error)?;
            let functions = analysis.functions.keys().copied().collect();
            Ok(Self { session, functions })
        }

        /// Addresses of the functions recovery found, in ascending order.
        #[getter]
        fn functions(&self) -> Vec<u64> {
            self.functions.clone()
        }

        /// File-wide diagnostics gathered while opening the image.
        #[getter]
        fn warnings(&self) -> Vec<String> {
            self.session.warnings().to_vec()
        }

        /// Replace the resource limits for later calls. Omitted values keep the defaults
        /// (10 000 ms, 10 000 instructions, 20 000 000 work units).
        #[pyo3(signature = (*, timeout_ms=None, max_instructions=None, max_work=None))]
        fn set_limits(
            &mut self,
            timeout_ms: Option<u32>,
            max_instructions: Option<u32>,
            max_work: Option<u32>,
        ) -> PyResult<()> {
            let default = ResourceLimits::default();
            self.session
                .set_limits(ResourceLimits {
                    timeout_ms: timeout_ms.unwrap_or(default.timeout_ms),
                    max_instructions: max_instructions.unwrap_or(default.max_instructions),
                    max_work: max_work.unwrap_or(default.max_work),
                })
                .map_err(error)
        }

        /// Decompile the function at `address` and return a `dict`: `text`, `name`,
        /// `calling_convention`, `warnings`, `notes`, `incomplete`, `unknown_callees`, `lines`
        /// (the instruction addresses behind each line of `text`), `frame` (stack symbols),
        /// `timings` and `file_warnings`.
        fn decompile(&mut self, py: Python<'_>, address: u64) -> PyResult<Py<PyAny>> {
            let result = self.session.decompile_function(address).map_err(error)?;
            let mut json = serialize(&result)?;
            json["lines"] = serde_json::json!(result.line_addresses);
            json["frame"] = serialize(&result.frame)?;
            json["file_warnings"] = serde_json::json!(self.session.warnings());
            json_to_py(py, json.to_string())
        }

        /// Decompile functions into one self-contained C translation unit and return a `dict`
        /// with `text`, `functions`, `guesses` and `unresolved_types`. A function that fails
        /// fails the unit.
        fn unit(&mut self, py: Python<'_>, addresses: Vec<u64>) -> PyResult<Py<PyAny>> {
            let unit = self.session.decompile_unit(&addresses).map_err(error)?;
            let mut json = serialize(&unit)?;
            json["file_warnings"] = serde_json::json!(self.session.warnings());
            json_to_py(py, json.to_string())
        }
    }

    /// Decompile every recovered function and return the event stream as a list of `dict`s: one
    /// `{"type": "start", "functions": [...]}`, a `{"type": "function", ...}` per function with
    /// text, assembly, control-flow graph, calls and data references. `start.names` supplies names
    /// before decompilation. `{"type": "settled"}` marks completion of ordinary attempts;
    /// retries replace `retry_pending` records before `{"type": "done"}`.
    /// These are the same records `binfera --decompile-all` prints, one per line.
    ///
    /// With `on_event`, each event is passed to it as it completes and the call returns `None`,
    /// so a large image does not accumulate in memory. An exception from the callback stops the
    /// run and propagates. `shard=(index, count)` decompiles one round-robin share.
    #[pyfunction]
    #[pyo3(signature = (data_or_path, *, format=None, arch=None, os=None, shard=None, on_event=None))]
    pub fn decompile_all(
        py: Python<'_>,
        data_or_path: &Bound<'_, PyAny>,
        format: Option<String>,
        arch: Option<String>,
        os: Option<String>,
        shard: Option<(usize, usize)>,
        on_event: Option<Py<PyAny>>,
    ) -> PyResult<Option<Py<PyAny>>> {
        let (bytes, _) = read_input(data_or_path)?;
        let options = options(format.as_deref(), arch, os, shard)?;
        let streaming = on_event.is_some();
        let outcome = py.detach(move || {
            let mut collected: Vec<String> = Vec::new();
            let mut failure: Option<PyErr> = None;
            let result = run_all(&bytes, &options, |event: BatchEvent| {
                let json = serde_json::to_string(&event)
                    .map_err(|e| DecompileError::Output(e.to_string()))?;
                let Some(callback) = &on_event else {
                    collected.push(json);
                    return Ok(());
                };
                Python::attach(|py| {
                    let call = json_to_py(py, json)
                        .and_then(|value| callback.call1(py, (value,)).map(|_| ()));
                    let call = call.and_then(|()| py.check_signals());
                    call.map_err(|e| {
                        let stop = DecompileError::Output(e.to_string());
                        failure = Some(e);
                        stop
                    })
                })
            });
            (result, failure, collected)
        });
        let (result, failure, collected) = outcome;
        if let Some(failure) = failure {
            return Err(failure);
        }
        result.map_err(error)?;
        if streaming {
            return Ok(None);
        }
        json_to_py(py, format!("[{}]", collected.join(","))).map(Some)
    }
}

#[cfg(not(feature = "decompiler"))]
mod enabled {
    use pyo3::prelude::*;

    use crate::error::CapaError;

    fn disabled() -> PyErr {
        CapaError::new_err(
            "native decompilation is not in this build; install a wheel built with the decompiler \
             or rebuild with --features decompiler",
        )
    }

    /// Present so the module has one shape in every build; it always raises `CapaError`.
    #[pyclass(module = "binfera")]
    pub struct Decompiler;

    #[pymethods]
    impl Decompiler {
        #[new]
        #[pyo3(signature = (data_or_path, *, format=None, arch=None, os=None))]
        fn new(
            data_or_path: &Bound<'_, PyAny>,
            format: Option<String>,
            arch: Option<String>,
            os: Option<String>,
        ) -> PyResult<Self> {
            let _ = (data_or_path, format, arch, os);
            Err(disabled())
        }
    }

    #[pyfunction]
    #[pyo3(signature = (data_or_path, *, format=None, arch=None, os=None, shard=None, on_event=None))]
    pub fn decompile_all(
        data_or_path: &Bound<'_, PyAny>,
        format: Option<String>,
        arch: Option<String>,
        os: Option<String>,
        shard: Option<(usize, usize)>,
        on_event: Option<Py<PyAny>>,
    ) -> PyResult<Option<Py<PyAny>>> {
        let _ = (data_or_path, format, arch, os, shard, on_event);
        Err(disabled())
    }
}

pub use enabled::{decompile_all, Decompiler};
