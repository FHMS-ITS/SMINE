# Certificate Chain Verifier

The Certificate Chain Verifier is a tool for reconstructing and validating certificate chains.
This project includes tests for validating the functionality of the certificate chain verification scripts.


## Quick Start
Make sure Redis is running before running the tests.

```shell 
docker run --name redis -p 6379:6379 -d redis
python tests/run_all_tests.py
```

## Project Structure

- `smime_chain_verifier/`: Core logic
- `tests/`: Unit and integration tests
