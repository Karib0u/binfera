#[cfg(feature = "native")]
mod native {
    use std::{env, fs, path::PathBuf, process::Command};

    const CORE: &str = "xml marshal space float address pcoderaw translate opcodes globalcontext";
    const SLEIGH: &str = "sleigh pcodeparse pcodecompile sleighbase slghsymbol slghpatexpress slghpattern semantics context slaformat compression filemanage";
    const DECOMP: &str = "capability architecture options graph cover block cast typeop database cpool comment stringmanage modelrules fspec action loadimage grammar varnode op type variable varmap jumptable emulate emulateutil flow userop expression multiprecision funcdata funcdata_block funcdata_op funcdata_varnode unionresolve pcodeinject heritage prefersplit rangeutil ruleaction subflow blockaction merge double transform constseq bitfield coreaction condexe override dynamic crc32 prettyprint printlanguage printc printjava memstate opbehavior paramid signature sleigh_arch inject_sleigh";

    /// What Ghidra's own Windows build defines: `_WINDOWS` selects its Windows code paths, and the
    /// others keep the C runtime's and windows.h's macros out of the way.
    const WINDOWS_DEFINES: [&str; 3] = ["/D_WINDOWS", "/D_CRT_SECURE_NO_WARNINGS", "/DNOMINMAX"];

    fn run(command: &mut Command) {
        let status = command.status().expect("launch native build command");
        assert!(status.success(), "native build command failed: {command:?}");
    }

    fn prototype(path: &std::path::Path, name: &str) -> String {
        let xml = fs::read_to_string(path).expect("compiler specification");
        let start = xml
            .find(&format!("<prototype name=\"{name}\""))
            .expect("pinned prototype");
        let end = start
            + xml[start..].find("</prototype>").expect("prototype end")
            + "</prototype>".len();
        xml[start..end].to_owned()
    }

    pub fn build() {
        println!("cargo:rerun-if-changed=native");
        println!("cargo:rerun-if-changed=src/lib.rs");
        println!("cargo:rerun-if-changed=../third_party/ghidra/cpp");
        println!("cargo:rerun-if-changed=../third_party/ghidra/specs");
        if env::var_os("CARGO_FEATURE_NATIVE").is_none() {
            return;
        }
        let host = env::var("HOST").unwrap();
        let target = env::var("TARGET").unwrap();
        // WebAssembly builds are cross-compiled with Emscripten (C++ exceptions and zlib
        // included); the SLEIGH compiler below always runs on the build host.
        let wasm = target.ends_with("-emscripten");
        // Windows builds with Visual C++ (cl.exe), which also needs its own zlib: the `libz-sys`
        // crate builds one and hands over its include folder and library through `DEP_Z_*`.
        let msvc = target.contains("windows-msvc");
        assert!(
            wasm || (host == target && (target.contains("linux") || target.contains("apple") || msvc)),
            "native decompiler requires a native Linux, macOS or Windows (MSVC) build, or the wasm32-unknown-emscripten target"
        );
        let zlib_include = env::var_os("DEP_Z_INCLUDE").map(PathBuf::from);
        let zlib_library =
            env::var_os("DEP_Z_ROOT").map(|root| PathBuf::from(root).join("lib").join("z.lib"));
        let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
        let source = PathBuf::from("../third_party/ghidra/cpp");
        let specs = PathBuf::from("../third_party/ghidra/specs");
        let mut compiler = cc::Build::new();
        compiler
            .cpp(true)
            .std("c++11")
            .opt_level(2)
            .warnings(false)
            .cargo_metadata(false)
            .include(&source);
        if wasm {
            // Build the compiler for the machine running the build script, not for wasm.
            compiler.target(&host).host(&host);
        }
        let sources: Vec<PathBuf> = format!("{CORE} {SLEIGH} slgh_compile slghparse slghscan")
            .split_whitespace()
            .map(|name| source.join(format!("{name}.cc")))
            .collect();
        let executable = out.join(if msvc {
            "sleigh-compile.exe"
        } else {
            "sleigh-compile"
        });
        if msvc {
            // One cl.exe invocation compiles and links the tool. cc finds Visual C++ and sets up
            // its environment; the object files go in their own folder under the build directory.
            let objects = out.join("sleigh-objects");
            fs::create_dir_all(&objects).expect("object folder");
            let mut command = compiler.get_compiler().to_command();
            command
                .args(["/nologo", "/EHsc", "/O2", "/std:c++14", "/bigobj"])
                .args(WINDOWS_DEFINES)
                .arg(format!("/I{}", source.display()))
                .arg(format!("/Fo{}\\", objects.display()))
                .arg(format!("/Fe{}", executable.display()));
            if let Some(include) = &zlib_include {
                command.arg(format!("/I{}", include.display()));
            }
            command.args(&sources);
            command.arg("/link");
            command.arg(
                zlib_library
                    .as_ref()
                    .expect("libz-sys provides zlib on Windows"),
            );
            run(&mut command);
        } else {
            for file in &sources {
                compiler.file(file);
            }
            compiler.compile("sleigh_compiler");
            run(compiler
                .get_compiler()
                .to_command()
                .arg(out.join("libsleigh_compiler.a"))
                .arg("-lz")
                .arg("-o")
                .arg(&executable));
        }
        let mut embedded = String::new();
        for (arch, slaspec, pspec, cspec) in [
            ("x64", "x86-64.slaspec", "x86-64.pspec", "x86-64-win.cspec"),
            ("x86", "x86.slaspec", "x86.pspec", "x86win.cspec"),
            (
                "arm32",
                "arm/ARM7_le.slaspec",
                "arm/ARMt.pspec",
                "arm/ARM.cspec",
            ),
            (
                "mipsle",
                "mips/mips32le.slaspec",
                "mips/mips32.pspec",
                "mips/mips32le.cspec",
            ),
            (
                "mipsbe",
                "mips/mips32be.slaspec",
                "mips/mips32.pspec",
                "mips/mips32be.cspec",
            ),
            (
                "arm64",
                "aarch64/AARCH64.slaspec",
                "aarch64/AARCH64.pspec",
                "aarch64/AARCH64.cspec",
            ),
        ] {
            let sla = out.join(format!("{arch}.sla"));
            run(Command::new(&executable).arg(specs.join(slaspec)).arg(&sla));
            let pack = PathBuf::from(format!(
                "data/winapi{}.pack",
                if arch == "x86" { "32" } else { "64" }
            ));
            println!("cargo:rerun-if-changed={}", pack.display());
            for (name, path) in [
                ("sla", sla),
                ("pspec", specs.join(pspec)),
                ("cspec", specs.join(cspec)),
                ("pack", pack),
            ] {
                if matches!(arch, "arm64" | "arm32" | "mipsle" | "mipsbe") && name == "pack" {
                    continue; // Platform archives are selected by the bridge, never duplicated here.
                }
                // The browser build does not embed the Windows API archives (4 MB each, over the
                // deploy size limit); the bridge gets them at runtime and sees an empty one until then.
                let bytes = if name == "pack"
                    && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("emscripten")
                {
                    b"CXPROTO1\0\0\0\0".to_vec()
                } else {
                    fs::read(path).unwrap()
                };
                if arch == "arm64" && name == "sla" {
                    assert!(
                        bytes.len() <= 2 * 1024 * 1024,
                        "AArch64 SLA exceeds the 2 MiB embedded budget"
                    );
                    println!("cargo:warning=AArch64 SLA: {} bytes", bytes.len());
                }
                embedded.push_str(&format!(
                    "static const unsigned char {name}_{arch}_bytes[] = {{"
                ));
                for byte in bytes {
                    embedded.push_str(&format!("{byte},"));
                }
                embedded.push_str("};\n");
            }
        }
        // The other compilers share an SLA and processor context above; each adds its own
        // compiler specification. System V also has its own C library archive, while Delphi and
        // Borland C++ call the same Win32 imports as Visual C and reuse its archive. Go adds its
        // own pack of standard library signatures (scripts/decompiler_types/pack_go_snapshots.py).
        for (name, path) in [
            ("cspec_arm32win", specs.join("arm/ARM_win.cspec")),
            ("rust_probe", specs.join("rust/probe_fixup.xml")),
            ("rust_try_unix64", specs.join("rust/unix64_try_fixup.xml")),
            ("rust_try_unix32", specs.join("rust/unix32_try_fixup.xml")),
            (
                "rust_try_windows64",
                specs.join("rust/windows64_try_fixup.xml"),
            ),
            (
                "rust_try_windows32",
                specs.join("rust/windows32_try_fixup.xml"),
            ),
            ("cspec_arm64go", specs.join("aarch64/AARCH64_golang.cspec")),
            (
                "cspec_arm64gowin",
                specs.join("aarch64/AARCH64_golang.cspec"),
            ),
            (
                "cspec_arm64goapple",
                specs.join("aarch64/AARCH64_golang.cspec"),
            ),
            ("cspec_arm64win", specs.join("aarch64/AARCH64_win.cspec")),
            (
                "cspec_arm64apple",
                specs.join("aarch64/AARCH64_apple.cspec"),
            ),
            ("cspec_x64gcc", specs.join("x86-64-gcc.cspec")),
            ("cspec_x86gcc", specs.join("x86gcc.cspec")),
            ("cspec_x86delphi", specs.join("x86delphi.cspec")),
            ("cspec_x86borland", specs.join("x86borland.cspec")),
            ("cspec_x64go", specs.join("x86-64-golang.cspec")),
            ("cspec_x86go", specs.join("x86-32-golang.cspec")),
            ("pack_go64", PathBuf::from("data/golang64.pack")),
            ("pack_go32", PathBuf::from("data/golang32.pack")),
            ("pack_sysv64", PathBuf::from("data/sysv64.pack")),
            ("pack_macos64", PathBuf::from("data/macos64.pack")),
            ("syscalls_x64", PathBuf::from("data/linux64_syscalls.txt")),
            ("syscalls_x86", PathBuf::from("data/linux32_syscalls.txt")),
            ("pack_sysv32", PathBuf::from("data/sysv32.pack")),
        ] {
            println!("cargo:rerun-if-changed={}", path.display());
            embedded.push_str(&format!("static const unsigned char {name}_bytes[] = {{"));
            let mut bytes = fs::read(path).unwrap();
            let additions = match name {
                "cspec_x64gcc" => {
                    let path = specs.join("x86-64-swift.cspec");
                    format!(
                        "{}\n{}",
                        prototype(&path, "__swiftcall"),
                        prototype(&path, "__thiscall").replacen(
                            "name=\"__thiscall\"",
                            "name=\"__swiftself\"",
                            1
                        )
                    )
                }
                "cspec_arm64go" => prototype(&specs.join("aarch64/AARCH64.cspec"), "__cdecl"),
                "cspec_arm64gowin" => {
                    prototype(&specs.join("aarch64/AARCH64_win.cspec"), "__cdecl")
                }
                "cspec_arm64goapple" => {
                    prototype(&specs.join("aarch64/AARCH64_apple.cspec"), "__cdecl")
                }
                _ => String::new(),
            };
            if name.starts_with("cspec_arm64go") {
                // runtime/duff_arm64.s `duffzero` stores pairs through x20 only, yet the pinned
                // model leaves x0-x15 unknown, so every caller prints them as `extraout_x*`. And
                // `runtime.spillArgs` (asm_arm64.s) stores the argument registers through x20,
                // changing none of them.
                let mut xml = String::from_utf8(bytes).unwrap();
                let preserved: String = (0..16)
                    .map(|i| format!("\t\t\t<register name=\"x{i}\"/>\n"))
                    .collect();
                replace(
                    &mut xml,
                    "\t\t\t<register name=\"x20\"/>\n\t\t</killedbycall>\n\t\t<unaffected>\n\t\t\t<register name=\"x16\"/>\n\t\t\t<register name=\"x17\"/>\n\t\t\t<register name=\"sp\"/>\n\t\t</unaffected>",
                    &format!("\t\t\t<register name=\"x20\"/>\n\t\t</killedbycall>\n\t\t<unaffected>\n{preserved}\t\t\t<register name=\"x16\"/>\n\t\t\t<register name=\"x17\"/>\n\t\t\t<register name=\"sp\"/>\n\t\t</unaffected>"),
                );
                let spill = format!(
                    "\t<prototype name=\"spillargs\" extrapop=\"8\" stackshift=\"8\">\n\t\t<input>\n\t\t\t<pentry minsize=\"1\" maxsize=\"8\">\n\t\t\t\t<register name=\"x20\"/>\n\t\t\t</pentry>\n\t\t</input>\n\t\t<output></output>\n\t\t<unaffected>\n{preserved}\t\t\t<register name=\"x16\"/>\n\t\t\t<register name=\"x17\"/>\n\t\t\t<register name=\"x20\"/>\n\t\t\t<register name=\"sp\"/>\n\t\t</unaffected>\n\t</prototype>\n"
                );
                xml = xml.replace("</compiler_spec>", &format!("{spill}</compiler_spec>"));
                bytes = xml.into_bytes();
            }
            if !additions.is_empty() {
                let xml = String::from_utf8(bytes).unwrap();
                assert_eq!(xml.matches("</compiler_spec>").count(), 1);
                bytes = xml
                    .replace(
                        "</compiler_spec>",
                        &format!("{additions}\n</compiler_spec>"),
                    )
                    .into_bytes();
            }
            for byte in bytes {
                embedded.push_str(&format!("{byte},"));
            }
            embedded.push_str("};\n");
        }
        fs::write(out.join("specs.hh"), embedded).unwrap();

        // Keep vendored sources byte-identical. Apply the documented integration
        // hooks only to build-directory copies, failing if the pinned text drifts.
        let mut native = cxx_build::bridge("src/lib.rs");
        native
            .cpp(true)
            .std("c++14")
            .opt_level(2)
            .warnings(false)
            .include(&source)
            .include("native")
            .include(&out)
            .file("native/bridge.cc");
        if msvc {
            // The embedded specifications make bridge.cc a very large translation unit.
            native.flag("/bigobj");
            // Ghidra reports errors with C++ exceptions, and cc does not turn exception handling on
            // for MSVC: without /EHsc a thrown exception is not caught and escapes into Rust.
            native.flag("/EHsc");
            // bridge.cc uses structured bindings, which GCC and Clang accept in C++14 mode as an
            // extension and MSVC only accepts as C++17.
            native.std("c++17");
            for define in WINDOWS_DEFINES {
                native.flag(define);
            }
            if let Some(include) = &zlib_include {
                native.include(include);
            }
        }
        if wasm {
            // Ghidra reports errors with C++ exceptions, which Emscripten leaves off by default; Rust's emscripten target unwinds with the wasm exception-handling proposal, so use the same.
            native.flag("-fwasm-exceptions").flag("--use-port=zlib");
        }
        for name in format!("{CORE} {SLEIGH} {DECOMP}").split_whitespace() {
            let path = source.join(format!("{name}.cc"));
            // The hooks below match LF text; a Windows checkout may have converted the files to CRLF.
            let mut code = fs::read_to_string(&path).unwrap().replace("\r\n", "\n");
            let original = code.clone();
            if name == "sleigh" {
                replace(&mut code,
                "    ifstream s(el->getContent(), std::ios_base::binary);\n    if (!s)\n      throw LowlevelError(\"Could not open .sla file: \" + el->getContent());\n    decoder.ingestStream(s);\n    s.close();",
                "    std::istringstream s(binfera_sla());\n    decoder.ingestStream(s);");
            }
            if name == "fspec" {
                // Two candidate registers for one argument slot (an integer and a float register
                // that a thunk saves alike) belong to one group and tie. Upstream breaks the tie by
                // comparing the ParamEntry pointers, and the entries are separate list nodes, so the
                // order, and with it which register a parameter is reported in, followed the heap
                // layout and changed from run to run. Order them by space and offset instead; the
                // higher offset first puts the float register ahead of the integer one, which is the
                // order the cspec lists them in and what the pointers gave in nearly every run.
                replace(
                    &mut code,
                    "  if (entry != b.entry)\t\t// Compare entry pointers directly\n    return (entry < b.entry);",
                    "  if (entry != b.entry) {\t\t// Compare entries by where they are, not by heap address\n    if (entry->getSpace() != b.entry->getSpace())\n      return (entry->getSpace()->getIndex() < b.entry->getSpace()->getIndex());\n    if (entry->getBase() != b.entry->getBase())\n      return (entry->getBase() > b.entry->getBase());\n    return (entry < b.entry);\n  }",
                );
            }
            if name == "varnode" {
                // Walks the descendant list with no end check; an op that is not in it (a
                // stale list after an inconsistent rewrite) loops forever through the list's
                // sentinel. Fail the request instead.
                replace(
                    &mut code,
                    "  iter = descend.begin();\n  while (*iter != op)\t\t// Find this op in list of vn's descendants\n    iter++;\n",
                    "  iter = descend.begin();\n  while (iter != descend.end() && *iter != op)\t\t// Find this op in list of vn's descendants\n    iter++;\n  if (iter == descend.end())\n    throw LowlevelError(\"Descendant missing from its varnode\");\n",
                );
            }
            if name == "funcdata_op" {
                // ConditionalExecution detaches inputs inside the block it
                // removes. Unreachable-edge cleanup can remove one of those
                // already empty phi slots before the dead block is destroyed.
                replace(
                    &mut code,
                    "  opUnsetInput(op,slot);\n  op->removeInput(slot);",
                    "  if (slot < 0 || slot >= op->numInput())\n    throw LowlevelError(\"Invalid input slot during edge removal\");\n  if (op->getIn(slot) != (Varnode *)0)\n    opUnsetInput(op,slot);\n  op->removeInput(slot);",
                );
            }
            if name == "subflow" {
                // A split field can have its own smaller register join. Extending that
                // join to concatenate subsequent fields exceeds its range. Derive every
                // intermediate concatenation from the original aggregate's storage.
                replace(
                    &mut code,
                    "      Address addr = outVarnodes[i]->getAddr();\n      addr.renormalize(sz);",
                    "      Address addr = baseAddr + dataTypePieces[i].offset;\n      addr.renormalize(sz);",
                );
            }
            if name == "dynamic" {
                // SIMD lowering can produce more than eight otherwise identical locals
                // at one instruction. Extend the collision index into unused hash bits,
                // preserving the existing encoding for the first eight entries.
                assert_eq!(code.matches("uint4 maxduplicates = 8;").count(), 2);
                replace_all(
                    &mut code,
                    "uint4 maxduplicates = 8;",
                    "uint4 maxduplicates = 128;",
                );
                assert_eq!(
                    code.matches("hash = tmphash | ((uint8)pos << 49);").count(),
                    2
                );
                replace_all(
                    &mut code,
                    "hash = tmphash | ((uint8)pos << 49);",
                    "hash = tmphash | ((uint8)(pos & 7) << 49) | ((uint8)(pos >> 3) << 55);",
                );
                assert_eq!(code.matches("hash |= ((uint8)total << 52);").count(), 2);
                replace_all(
                    &mut code,
                    "hash |= ((uint8)total << 52);",
                    "hash |= ((uint8)(total & 7) << 52) | ((uint8)(total >> 3) << 59);",
                );
                replace(
                    &mut code,
                    "return (uint4)((h>>49)&7);",
                    "return (uint4)(((h>>49)&7) | (((h>>55)&15)<<3));",
                );
                replace(
                    &mut code,
                    "return ((uint4)((h>>52)&7)+1);",
                    "return (uint4)(((h>>52)&7) | (((h>>59)&15)<<3)) + 1;",
                );
                replace(&mut code, "uint8 val = 0x3f;", "uint8 val = 0x3fff;");
                // Keep the hash belonging to the winning collision list, not the
                // last method tried when none of the methods is collision-free.
                replace_all(
                    &mut code,
                    "  Address tmpaddr;\n",
                    "  Address tmpaddr;\n  uint8 championhash = 0;\n  Address championaddr;\n",
                );
                replace(&mut code, "champion = vnlist2;", "champion = vnlist2;\n        championhash = tmphash;\n        championaddr = tmpaddr;");
                replace(&mut code, "champion = oplist2;", "champion = oplist2;\n        championhash = tmphash;\n        championaddr = tmpaddr;");
                replace_all(&mut code, "hash = tmphash |", "hash = championhash |");
                replace_all(
                    &mut code,
                    "addrresult = tmpaddr;",
                    "addrresult = championaddr;",
                );
            }
            if name == "condexe" {
                // A COPY of a value defined outside the removed block keeps that
                // dominating value, just like a COPY of an input or constant.
                replace(
                    &mut code,
                    "      if (defOp->code() == CPUI_MULTIEQUAL && defOp->getParent() == iblock)\n\top = defOp;\n",
                    "      if (defOp->code() == CPUI_MULTIEQUAL && defOp->getParent() == iblock)\n\top = defOp;\n      else if (defOp->getParent() != iblock)\n        return vn;\n",
                );
            }
            if name == "heritage" {
                // The reader of a free joined varnode is assumed to be unique; when it is not,
                // the next line dereferences a null op. Fail the request instead of the process.
                // The same line opens both splitJoinRead and its sibling.
                assert_eq!(
                    code.matches("  PcodeOp *op = vn->loneDescend(); // vn isFree, so loneDescend must be non-null\n").count(),
                    2,
                    "pinned Ghidra hook changed: heritage.cc loneDescend"
                );
                // `clear` forgets the load-guard COPY ops queued for `handleNewLoadCopies`. A
                // limit that aborts heritage between queueing one and handling it leaves the
                // list pointing at ops `Funcdata::clear` frees, for the function's next analysis
                // to walk.
                replace(
                    &mut code,
                    "  storeGuard.clear();\n  maxdepth = -1;",
                    "  storeGuard.clear();\n  loadCopyOps.clear();\n  maxdepth = -1;",
                );
                replace_all(
                    &mut code,
                    "  PcodeOp *op = vn->loneDescend(); // vn isFree, so loneDescend must be non-null\n",
                    "  PcodeOp *op = vn->loneDescend(); // vn isFree, so loneDescend must be non-null\n  if (op == (PcodeOp *)0)\n    throw LowlevelError(\"Free joined varnode has no unique reader\");\n",
                );
            }
            if name == "jumptable" {
                // Case labels are cosmetic. A model that cannot name the unnormalized variable
                // ("Backward normalization not implemented") must not fail the whole function:
                // warn and label the table by its raw addresses, as for a model-less table.
                replace(&mut code,
                    "void JumpTable::recoverLabels(Funcdata *fd)\n\n{\n  if (jmodel != (JumpModel *)0) {\n",
                    "void JumpTable::recoverLabels(Funcdata *fd)\n\n{\n  if (jmodel != (JumpModel *)0) try {\n");
                replace(&mut code,
                    "      jmodel->buildLabels(fd,addresstable,label,origmodel);\n    }\n  }\n  else {\n    jmodel = new JumpModelTrivial(this);",
                    "      jmodel->buildLabels(fd,addresstable,label,origmodel);\n    }\n  }\n  catch(LowlevelError &err) {\n    fd->warning(err.explain,opaddress);\n    clearSavedModel();\n    delete jmodel;\n    jmodel = (JumpModel *)0;\n    label.clear();\n  }\n  if (jmodel == (JumpModel *)0) {\n    jmodel = new JumpModelTrivial(this);");
                // The final analysis must reconstruct the same low range as the
                // flow pass. Require every emulated address to match the saved
                // table before accepting the smaller normalized range.
                replace(&mut code,
                    "  findNormalized(fd,indop->getParent(),-1,matchsize,maxtablesize);\n  if (jrange->getSize() > maxtablesize)",
                    "  findNormalized(fd,indop->getParent(),-1,matchsize,maxtablesize);\n  if (matchsize > 0 && matchsize < 256 && jrange->contains(0) && jrange->contains(1) &&\n      jrange->contains(255) && jrange->getStartVarnode()->getNZMask() == 255 && jrange->initializeForReading()) {\n    uintb first = jrange->getValue();\n    uintb count = jrange->getSize();\n    if (first > 0 && first < 256 && count <= 256 && first + count == 256 + matchsize) {\n      jrange->setRange(CircleRange(0,matchsize,1,1));\n      vector<Address> candidate;\n      buildAddresses(fd,indop,candidate,(vector<LoadTable> *)0,(vector<int4> *)0);\n      bool matches = candidate.size() == matchsize && jumptable->numEntries() == matchsize;\n      for(uint4 i=0;matches && i<matchsize;++i)\n        matches = candidate[i] == jumptable->getAddressByIndex(i);\n      if (!matches) jrange->setRange(CircleRange(first,matchsize,1,1));\n    }\n  }\n  if (jrange->getSize() > maxtablesize)");
                // Excluding a byte value yields a wrapping range (for example
                // 7..255,0..5). If its high segment starts in a foreign unwind
                // range, try the finite low segment before rejecting the table.
                // Validate every low target; the normal truncation warning stays.
                replace(&mut code,
                    "  Address addr = addresstable[0];\n  i = 0;",
                    "  Address addr = addresstable[0];\n  if (!binfera_jump_target_valid(fd->getArch()->loader,fd->getAddress().getOffset(),addr.getOffset()) &&\n      dynamic_cast<JumpValuesRangeDefault *>(jrange) == (JumpValuesRangeDefault *)0 &&\n      jrange->contains(0) && jrange->contains(1) && jrange->contains(255) && jrange->getStartVarnode()->getNZMask() == 255 &&\n      jrange->initializeForReading()) {\n    uintb first = jrange->getValue();\n    uintb count = jrange->getSize();\n    if (first > 0 && first < 256 && count <= 256 && first + count > 256) {\n      uintb end = first + count - 256;\n      vector<Address> low;\n      vector<LoadTable> lowloads;\n      vector<int4> lowcounts;\n      jrange->setRange(CircleRange(0,end,1,1));\n      buildAddresses(fd,indop,low,loadcounts ? &lowloads : (vector<LoadTable> *)0,loadcounts ? &lowcounts : (vector<int4> *)0);\n      bool valid = !low.empty();\n      for(const Address &target : low)\n        valid = valid && binfera_jump_target_valid(fd->getArch()->loader,fd->getAddress().getOffset(),target.getOffset());\n      if (valid) {\n        addresstable.swap(low);\n        if (loadcounts) { loadpoints.swap(lowloads); loadcounts->swap(lowcounts); }\n        addr = addresstable[0];\n      } else {\n        jrange->setRange(CircleRange(first,end,1,1));\n      }\n    }\n  }\n  i = 0;");
                // An unbounded Rust enum index can consume the next table and
                // recursively absorb neighboring functions. Unwind metadata
                // rejects foreign interior targets, retaining the truncation warning.
                replace(&mut code,
                    "  if (addr.getOffset() != 0) {\n    for(i=1;i<addresstable.size();++i) {\n      if (addresstable[i].getOffset() == 0) break;",
                    "  if (addr.getOffset() != 0 && binfera_jump_target_valid(fd->getArch()->loader,fd->getAddress().getOffset(),addr.getOffset())) {\n    for(i=1;i<addresstable.size();++i) {\n      if (addresstable[i].getOffset() == 0 || !binfera_jump_target_valid(fd->getArch()->loader,fd->getAddress().getOffset(),addresstable[i].getOffset())) break;");
                // Enumerates every path from a switch's address to its inputs without memoizing
                // shared subexpressions, so a dense switch computation can run for minutes inside
                // one jump table recovery (a 700 KB LockBit 5.0 build never finished).
                replace(
                    &mut code,
                    "  do {\t// Traverse through tree of inputs to final address\n",
                    "  do {\t// Traverse through tree of inputs to final address\n    binfera_check();\n",
                );
            }
            if name == "coreaction" {
                // A register loaded from an import slot and called through (`mov esi,[slot]` ...
                // `call esi`) is a MULTIEQUAL once a loop reloads it, so the CALLIND never sees the
                // slot itself and keeps no name or prototype. Look through the merge.
                replace(
                    &mut code,
                    "      vn = vn->getDef()->getIn(0);\n    if (vn->isPersist() && vn->isExternalRef()) { // Check for possible external reference",
                    "      vn = vn->getDef()->getIn(0);\n    vn = binfera_extern_slot(vn);\n    if (vn->isPersist() && vn->isExternalRef()) { // Check for possible external reference",
                );
                // A verified tail call or modeled syscall can define the ABI return value.
                replace(
                    &mut code,
                    "\tif (ancestorReal.execute(op,slot,&trial,false))\n\t  if (data.ancestorOpUse(maxancestor,vn,op,trial,0,0))\n\t    trial.markActive();",
                    "\tif ((ancestorReal.execute(op,slot,&trial,false) && data.ancestorOpUse(maxancestor,vn,op,trial,0,0))\n\t    || binfera_forwarded_return(data,*op,slot))\n\t  trial.markActive();",
                );
                // Justifying a small stack input to an ABI slot can overlap an
                // input that starts later and extends beyond that slot. The
                // upstream walk only extends the container to the left.
                replace(&mut code,
                    "      if (!overlaps) break;\t// Found no additional overlaps, go with current justified container",
                    "      VarnodeDefSet::const_iterator forward = iter;\n      while (forward != enditer) {\n        Varnode *next = *forward++;\n        if (next->getSpace() != vdata.space) continue;\n        uintb last = vdata.offset + vdata.size - 1;\n        if (next->getOffset() > last) break;\n        uintb nextlast = next->getOffset() + next->getSize() - 1;\n        if (nextlast > last) {\n          vdata.size = nextlast - vdata.offset + 1;\n          overlaps = true;\n        }\n      }\n      if (!overlaps) break;\t// Found no additional overlaps, go with current justified container");
                // With an unknown stack cleanup (Delphi and Borland register conventions), the
                // stack-pointer solver rewrites a stack pointer's MULTIEQUAL into an INT_ADD in
                // place, ahead of the block's other MULTIEQUALs. Code that walks a block's leading
                // markers then stops early: ConditionalJoin left a MULTIEQUAL with an input for an
                // edge it had removed, and Cover followed that input past the block's in-edges
                // into a freed block. Move the rewritten op after the markers, as
                // ConditionalJoin::cutDownMultiequals does when it turns one into a COPY.
                replace(
                    &mut code,
                    "    data.opSetOpcode(op,CPUI_INT_ADD);\n    data.opSetAllInput(op,paramlist);\n",
                    "    BlockBasic *parent = op->code() == CPUI_MULTIEQUAL ? op->getParent() : (BlockBasic *)0;\n    if (parent != (BlockBasic *)0) data.opUninsert(op);\n    data.opSetOpcode(op,CPUI_INT_ADD);\n    data.opSetAllInput(op,paramlist);\n    if (parent != (BlockBasic *)0) data.opInsertBegin(op,parent);\n",
                );
            }
            if name == "action" {
                replace(
                    &mut code,
                    "  do {\n    switch(status)",
                    "  do {\n    binfera_check();\n    switch(status)",
                );
                replace(
                    &mut code,
                    "int4 ActionPool::processOp(PcodeOp *op,Funcdata &data)\n\n{",
                    "int4 ActionPool::processOp(PcodeOp *op,Funcdata &data)\n\n{\n  binfera_check();",
                );
            }
            for (file, signature) in [
                (
                    "op",
                    "PcodeOp *PcodeOpBank::create(int4 inputs,const SeqNum &sq)",
                ),
                (
                    "varnode",
                    "Varnode *VarnodeBank::create(int4 s,const Address &m,Datatype *ct)",
                ),
                (
                    "sleigh",
                    "int4 Sleigh::oneInstruction(PcodeEmit &emit,const Address &baseaddr) const",
                ),
                // Called once per op by dead-code removal, which can run for minutes inside a
                // single action when a function has a very large number of ops.
                ("funcdata_op", "void Funcdata::opDestroy(PcodeOp *op)"),
                // Follows an add tree without memoizing shared subexpressions, so a long
                // chain of obfuscated arithmetic can run for minutes inside one action.
                ("varmap", "uintb AliasChecker::gatherOffset(Varnode *vn)"),
            ] {
                if name == file {
                    let needle = format!("{signature}\n\n{{");
                    replace(&mut code, &needle, &format!("{needle}\n  binfera_check();"));
                }
            }
            if code != original {
                let patched = out.join(format!("{name}.cc"));
                fs::write(&patched, format!("#include \"hooks.hh\"\n{code}")).unwrap();
                native.file(patched);
            } else {
                native.file(path);
            }
        }
        native.compile("capa_ghidra");
        // On Windows libz-sys links the zlib it built; elsewhere the system zlib is used.
        if !wasm && !msvc {
            println!("cargo:rustc-link-lib=z");
        }
    }
    fn replace_all(text: &mut String, from: &str, to: &str) {
        *text = text.replace(from, to);
    }
    fn replace(text: &mut String, from: &str, to: &str) {
        assert_eq!(
            text.matches(from).count(),
            1,
            "pinned Ghidra hook changed: {from}"
        );
        *text = text.replace(from, to);
    }
}
fn main() {
    #[cfg(feature = "native")]
    native::build();
}
