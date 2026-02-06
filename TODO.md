# TODO

## Known Issues

- [ ] AI sometimes returns malformed JSON, causes "needs review" fallback
- [ ] Large files (>1MB) might be slow to process
- [ ] Windows paths with spaces might cause issues with Semgrep (haven't tested fully)
- [ ] No rate limiting for Gemini API - could hit quota on large scans

## Future Improvements

- [ ] Add unit tests for core modules
- [ ] Cache AI responses to avoid duplicate API calls
- [ ] Add HTML report output option
- [ ] Support for more vulnerability types (SSRF, path traversal, etc.)
- [ ] Better progress bar for batch AI analysis
- [ ] Config file support (yaml or toml)

## Nice to Have

- [ ] Web UI with Flask or FastAPI
- [ ] GitHub Actions integration example
- [ ] Export to SARIF format for IDE integration
- [ ] Severity filtering (--min-severity flag)
