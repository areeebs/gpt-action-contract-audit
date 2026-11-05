# GPT Action Contract Audit

Review OpenAPI action contracts for unsafe transport, missing operation security, and unapproved write paths.

A static audit for the API contracts used by ChatGPT Actions and structured model tool calls. It examines HTTPS servers, declared host allowlists, operation authentication, destructive HTTP verbs, request schemas, and approval annotations. It accepts OpenAPI documents encoded as JSON so it needs no third-party parser.

The tool audits a contract; it does not make requests, validate a live endpoint, or prove that a server enforces the contract.

## Install and run

Requires Python 3.11 or newer. The tool uses only the standard library.

~~~sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
gpt-action-audit examples/input.json
~~~

Run the regression suite:

~~~sh
python -m unittest discover -s tests -v
~~~

## Design constraints

This project is a local, deterministic analysis component. It does not call a model, contact a provider, or make changes to external systems. Findings are evidence for review, not a guarantee that an application is safe.

## References

- [OpenAI function calling guide](https://developers.openai.com/api/docs/guides/function-calling)
- [OpenAI safety in building agents](https://developers.openai.com/api/docs/guides/agents)

## License

MIT. See LICENSE.
