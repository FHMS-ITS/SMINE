import unittest
import os
import sys


def run_all_tests(test_directory):
    # Discover and load all the test files from the specified directory
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=test_directory, pattern="test_*.py")

    # Run the tests and report results
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Check if any tests failed or had errors
    if not result.wasSuccessful():
        print("\nSome tests failed or had errors.")
        sys.exit(1)
    else:
        print("\nAll tests passed successfully.")
        sys.exit(0)


if __name__ == "__main__":
    # Specify the test folder, can be customized or passed as a command line argument
    test_folder = os.path.join(os.getcwd(), "tests")
    if len(sys.argv) > 1:
        test_folder = sys.argv[1]

    if not os.path.exists(test_folder):
        print(f"Error: Test folder '{test_folder}' does not exist.")
        sys.exit(1)

    run_all_tests(test_folder)
