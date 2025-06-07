import json
import logging
import sys
from importlib import import_module
from json import JSONDecodeError

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

certificates_tasks = [
    {
        "field": None,
        "script": "parse_cert_task.py",
        "allow_error": False,
    },
    {
        "field": "is_smime",
        "script": "is_smime_task.py",
        "allow_error": True,
    },
    {
        "field": "badkeys",
        "script": "badkeys_task.py",
        "allow_error": True,
    },
    {
        "output_collection": "pkilint",
        "field": "pkilint",
        "script": "lint_smime_cert_task.py",
        "allow_error": True,
    },
    {
        "output_collection": "chain",
        "field": "chain",
        "script": "cert_chains_task.py",
        "allow_error": True,
    },
    {
        "field": "is_ca",
        "script": "is_ca_task.py",
        "allow_error": True,
    },
    {
        "field": "pwnedkeys",
        "script": "pwnedkeys_task.py",
        "allow_error": True,
    },
    {
        "field": "factordb",
        "script": "factordb_task.py",
        "allow_error": True,
    },
]
hosts_tasks = [
    {
        "field": "geoip",
        "script": "geoip_task.py",
        "allow_error": True,
    },
]

BASE_PATH = "processing.tasks"


def run_tasks(tasks: list[dict], input_document: dict) -> dict:
    """
    Sequentially run all given tasks on a document.

    Args:
        input_document (dict): The document to process.
    """
    logger.debug(f"Input document: \n{json.dumps(input_document, indent=4)}")
    full_result = {
        "final_document": {},
        "task_results": (task_results := {}),
    }

    doc = input_document.copy()
    for task in tasks:
        logger.info(f"Starting task: {task['script']}")

        # load module
        try:
            full_script_path: str = f"{BASE_PATH}.{task['script']}".replace(".py", "")
            task_module = import_module(full_script_path)
            if "pre_check" in task_module.__dict__:
                task_module.pre_check()
        except Exception as ex:
            logger.error(f"Import failed: {ex!r}")
            task_results[task["script"]] = {"error": repr(ex), "result": None}
            if task.get("allow_error"):
                continue
            raise

        # execute task
        try:
            result = task_module.run(doc)
            task_results[task["script"]] = {"error": None, "result": result}
            logger.info(f"Task {task['script']} completed.")
            logger.debug(f"{json.dumps(result, indent=4)}")
            if result and not task.get("output_collection"):
                if task.get("field"):
                    doc[task["field"]] = result
                else:
                    doc.update(result)
                    full_result["final_document"] = doc.copy()
        except Exception as ex:
            logger.error(f"Task {task['script']} failed: {ex!r}")
            task_results[task["script"]] = {"error": repr(ex), "result": None}
            if task.get("allow_error"):
                continue
            raise
    return full_result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} (certs|hosts)")
        sys.exit(1)
    cmd = sys.argv[1].lower()
    if "cert" in cmd.lower():  # cert, certs, certificates
        tasks = certificates_tasks
    elif "host" in cmd.lower():
        tasks = hosts_tasks
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

    in_str = sys.stdin.read().strip()
    try:
        input_document = json.loads(in_str)
    except JSONDecodeError:
        if tasks == certificates_tasks:
            logger.info("Invalid JSON input. Assuming raw certificate data.")
            input_document = {"cert_data": in_str}
        else:
            logger.info("Invalid JSON input. Assuming IP address.")
            input_document = {"ip": in_str, "port": 389}

    print(json.dumps(run_tasks(tasks, input_document), indent=4))
