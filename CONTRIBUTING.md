# Contributing

Open an issue with a reproducible example (target URL, command, Python version, and expected versus observed status). **Never include private keys, API tokens, internal hostnames or personal data.** Redact sensitive certificate names before posting logs.

For changes, add a failing `unittest` first, implement the smallest fix, then run:

```console
python -m unittest discover -s tests -v
```

Use a pull request to describe the behavior change and test result. The project is new; priorities and maintenance capacity are not yet proven.
