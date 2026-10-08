from agent.dpi.redaction import hash_text, redact_url, sanitize_text_snippet


def test_redact_url_preserves_youtube_video_id_but_strips_sensitive_query_values():
    redacted = redact_url(
        "https://www.youtube.com/watch?v=abc123&list=PL1&token=secret&feature=share"
    )

    assert "v=abc123" in redacted
    assert "list=PL1" in redacted
    assert "token=%5BREDACTED%5D" in redacted
    assert "feature" not in redacted


def test_sanitize_text_snippet_and_hash():
    snippet = sanitize_text_snippet("hello\x00world", max_bytes=5)

    assert snippet == "hello"
    assert hash_text(snippet)
