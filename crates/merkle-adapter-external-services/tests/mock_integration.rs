//! Integration tests for `MockExternalServices` — verifies that pre-loaded
//! responses are returned in FIFO order for both SSH exec and HTTP request.

use merkle_adapter_external_services::MockExternalServices;
use merkle_ports::{ExternalError, ExternalServices, HttpAuth, HttpRequestSpec, HttpResponse, SshExecOutput};

#[tokio::test]
async fn mock_ssh_exec_returns_preloaded_output() {
    let expected = SshExecOutput {
        stdout: b"uptime output".to_vec(),
        stderr: vec![],
        exit_code: 0,
    };

    let mock = MockExternalServices::new().with_ssh_response(SshExecOutput {
        stdout: b"uptime output".to_vec(),
        stderr: vec![],
        exit_code: 0,
    });

    let result = mock
        .ssh_exec("user@host", b"fake-key-material", "uptime")
        .await
        .expect("mock ssh_exec should succeed");

    assert_eq!(result.stdout, expected.stdout);
    assert_eq!(result.stderr, expected.stderr);
    assert_eq!(result.exit_code, expected.exit_code);
}

#[tokio::test]
async fn mock_ssh_exec_returns_preloaded_error() {
    let mock = MockExternalServices::new()
        .with_ssh_error(ExternalError::ConnectFailed("host unreachable".to_owned()));

    let err = mock
        .ssh_exec("user@host", b"fake-key-material", "uptime")
        .await
        .expect_err("mock should return error");

    assert!(
        matches!(err, ExternalError::ConnectFailed(ref msg) if msg.contains("unreachable")),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn mock_http_request_returns_preloaded_response() {
    let expected_body = b"hello world".to_vec();

    let mock = MockExternalServices::new().with_http_response(HttpResponse {
        status: 200,
        headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
        body: b"hello world".to_vec(),
    });

    let spec = HttpRequestSpec {
        method: "GET".to_owned(),
        url: "https://example.com/".to_owned(),
        headers: vec![],
        body: None,
    };

    let result = mock
        .http_request(spec, HttpAuth::None)
        .await
        .expect("mock http_request should succeed");

    assert_eq!(result.status, 200);
    assert_eq!(result.body, expected_body);
    assert_eq!(
        result.headers,
        vec![("content-type".to_owned(), "text/plain".to_owned())]
    );
}

#[tokio::test]
async fn mock_http_request_returns_preloaded_error() {
    let mock = MockExternalServices::new()
        .with_http_error(ExternalError::AuthFailed);

    let spec = HttpRequestSpec {
        method: "GET".to_owned(),
        url: "https://example.com/secure".to_owned(),
        headers: vec![],
        body: None,
    };

    let err = mock
        .http_request(spec, HttpAuth::Bearer("bad-token".to_owned()))
        .await
        .expect_err("mock should return error");

    assert!(matches!(err, ExternalError::AuthFailed));
}

#[tokio::test]
async fn mock_ssh_exec_multiple_responses_fifo_order() {
    let mock = MockExternalServices::new()
        .with_ssh_response(SshExecOutput {
            stdout: b"first".to_vec(),
            stderr: vec![],
            exit_code: 0,
        })
        .with_ssh_response(SshExecOutput {
            stdout: b"second".to_vec(),
            stderr: vec![],
            exit_code: 1,
        });

    let first = mock
        .ssh_exec("host", b"key", "cmd1")
        .await
        .expect("first call");
    let second = mock
        .ssh_exec("host", b"key", "cmd2")
        .await
        .expect("second call");

    assert_eq!(first.stdout, b"first");
    assert_eq!(second.stdout, b"second");
    assert_eq!(second.exit_code, 1);
}
