# Certificate Chain Verifier

The Certificate Chain Verifier is a tool for reconstructing and validating certificate chains.
This project includes tests for validating the functionality of the certificate chain verification scripts.


## Quick Start
Make sure the **test-specific Redis instance** (container name: `redis-test`) is running before executing the tests.  

```shell 
docker ps
python tests/run_all_tests.py
```

## Project Structure

- `smime_chain_verifier/`: Core logic
- `tests/`: Unit and integration tests
