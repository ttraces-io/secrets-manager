//! Integration tests entrypoint for `cargo test -p traces-sm-devtest`.

use traces_sm_devtest::DevTestRunner;

#[tokio::test]
async fn test_full_system_verification_suite() {
    let runner = DevTestRunner::new();
    let report = runner.run_all().await;

    for suite in &report.suites {
        for test in &suite.tests {
            if let Some(ref err) = test.error {
                eprintln!("Suite '{}' failed: {}", suite.name, err);
            }
        }
        assert!(suite.passed, "DevTest Suite '{}' failed!", suite.name);
    }

    assert_eq!(
        report.failed_suites, 0,
        "Expected 0 failed suites, found {}",
        report.failed_suites
    );
}
