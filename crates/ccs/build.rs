use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=CCS_BUILD_COMMIT");
    let commit = env::var("CCS_BUILD_COMMIT").expect(
        "set CCS_BUILD_COMMIT to the full source commit (CCS_BUILD_COMMIT=$(git rev-parse HEAD))",
    );
    assert!(
        commit.len() == 40
            && commit
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "CCS_BUILD_COMMIT must be 40 lowercase hex characters"
    );
    println!("cargo:rustc-env=CCS_BUILD_COMMIT={commit}");
    println!(
        "cargo:rustc-env=CCS_BUILD_TARGET={}",
        env::var("TARGET").unwrap()
    );
}
