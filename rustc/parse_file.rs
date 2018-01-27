#![no_main]
#![feature(rustc_private)]

extern crate getopts;
extern crate rustc;
extern crate rustc_driver;
extern crate rustc_errors;
extern crate rustc_trans_utils;
extern crate syntax;

#[macro_use] extern crate libfuzzer_sys;

use rustc::middle::cstore::CrateStore;
use rustc::session::Session;
use rustc::session::config::{self, Input, ErrorOutputType};
use rustc_driver::{Compilation, CompilerCalls, RustcDefaultCalls};
use rustc_driver::driver::{CompileController};
use std::path::PathBuf;
use syntax::ast::{self};

struct MyCompilerCalls(RustcDefaultCalls);

impl<'a> CompilerCalls<'a> for MyCompilerCalls {
    fn early_callback(
        &mut self,
        matches: &getopts::Matches,
        sopts: &config::Options,
        cfg: &ast::CrateConfig,
        descriptions: &rustc_errors::registry::Registry,
        output: ErrorOutputType
    ) -> Compilation {
        self.0.early_callback(matches, sopts, cfg, descriptions, output)
    }
    fn no_input(
        &mut self,
        matches: &getopts::Matches,
        sopts: &config::Options,
        cfg: &ast::CrateConfig,
        odir: &Option<PathBuf>,
        ofile: &Option<PathBuf>,
        descriptions: &rustc_errors::registry::Registry
    ) -> Option<(Input, Option<PathBuf>)> {
        self.0.no_input(matches, sopts, cfg, odir, ofile, descriptions)
    }
    fn late_callback(
        &mut self,
        trans: &::rustc_trans_utils::trans_crate::TransCrate,
        matches: &getopts::Matches,
        sess: &Session,
        cstore: &CrateStore,
        input: &Input,
        odir: &Option<PathBuf>,
        ofile: &Option<PathBuf>
    ) -> Compilation {
        self.0.late_callback(trans, matches, sess, cstore, input, odir, ofile)
    }

    fn build_controller(&mut self, sess: &Session, matches: &getopts::Matches) -> CompileController<'a> {
        let mut control = self.0.build_controller(sess, matches);
        control.after_analysis.stop = Compilation::Stop;
        control
    }
}

fn find_sysroot() -> String {
    // Taken from https://github.com/Manishearth/rust-clippy/pull/911.
    let home = option_env!("RUSTUP_HOME").or(option_env!("MULTIRUST_HOME"));
    let toolchain = option_env!("RUSTUP_TOOLCHAIN").or(option_env!("MULTIRUST_TOOLCHAIN"));
    match (home, toolchain) {
        (Some(home), Some(toolchain)) => format!("{}/toolchains/{}", home, toolchain),
        _ => option_env!("RUST_SYSROOT")
            .expect("need to specify RUST_SYSROOT env var or use rustup or multirust")
            .to_owned(),
    }
}

fn write_file(data: &[u8]) -> ::std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create("/tmp/test.rs")?;
    f.write_all(data)?;
    Ok(())
}

fuzz_target!(|data| {
    for b in data {
        if *b > 127 {
            // avoid 'assertion failed: bpos.to_usize() >= mbc.pos.to_usize() + mbc.bytes', libsyntax/codemap.rs:644:17
            return;
        }
    }
    if let Ok(()) = write_file(data) {
        let mut args = vec!["rustc".to_string(), "/tmp/test.rs".to_string()];


        let sysroot_flag = String::from("--sysroot");
        if !args.contains(&sysroot_flag) {
            args.push(sysroot_flag);
            args.push(find_sysroot());
        }

        let result = ::std::panic::catch_unwind(move || {
            rustc_driver::run_compiler(&args, &mut MyCompilerCalls(RustcDefaultCalls),
                                       None, None);
        });

        if let Err(value) = result {
            if !value.is::<rustc_errors::FatalErrorMarker>() {
                panic!("ICE");
            }
        }
    }
});
