# Certificate Chain Verifier

The Certificate Chain Verifier is a tool for reconstructing and validating certificate chains.
This project includes tests for validating the functionality of the certificate chain verification scripts.


## Quick Start
Make sure the **test-specific Redis instance** is running before executing the tests.  

```shell 
docker run --name redis -p 16379:16379 -d redis
python tests/run_all_tests.py
```

## Project Structure

- `smime_chain_verifier/`: Core logic
- `tests/`: Unit and integration tests
