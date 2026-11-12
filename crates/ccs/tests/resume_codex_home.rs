use std::path::PathBuf;
use std::process::Command;

#[test]
fn home_child() {
    if let Some(expected) = std::env::var_os("CCS_EXPECT_HOME") {
        assert_eq!(ccs::codex::home(), PathBuf::from(expected));
    }
}

#[test]
fn expanduser_forms() {
    let mut storage = vec![0_u8; 65536];
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut found = std::ptr::null_mut();
    // SAFETY: all buffers remain live, and only a successful result is read.
    let status = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            pwd.as_mut_ptr(),
            storage.as_mut_ptr().cast(),
            storage.len(),
            &mut found,
        )
    };
    assert_eq!(status, 0);
    assert!(!found.is_null());
    let pwd = unsafe { pwd.assume_init() };
    let user = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }
        .to_str()
        .unwrap();
    let user_home = PathBuf::from(
        unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) }
            .to_str()
            .unwrap(),
    );
    let fake_home = std::env::temp_dir().join(format!("ccs-home-{}", std::process::id()));
    let unknown = format!("~ccs-no-such-user-{}", std::process::id());
    let current = std::env::current_dir().unwrap();
    let cases = [
        ("~".to_owned(), fake_home.clone()),
        ("~/sessions".into(), fake_home.join("sessions")),
        (format!("~{user}"), user_home.clone()),
        (format!("~{user}/sessions"), user_home.join("sessions")),
        (unknown.clone(), current.join(&unknown)),
        (
            format!("{unknown}/sessions"),
            current.join(&unknown).join("sessions"),
        ),
        ("".into(), fake_home.join(".codex")),
    ];
    let mut failures = Vec::new();
    for (input, expected) in cases {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "home_child", "--nocapture"])
            .env("CODEX_HOME", &input)
            .env("HOME", &fake_home)
            .env("CCS_EXPECT_HOME", &expected)
            .output()
            .unwrap();
        if !output.status.success() {
            failures.push(format!(
                "{input:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
