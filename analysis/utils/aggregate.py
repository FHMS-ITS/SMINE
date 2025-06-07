import functools
import logging
import os
import timeit
from collections.abc import Generator
from multiprocessing import Pool
from typing import Any

import ujson as json
from pathlib import Path
from bson import ObjectId
from pymongo import MongoClient
from pymongo.collection import Collection

logger = logging.getLogger(__name__)
logging.getLogger("pymongo").setLevel(logging.WARNING)

PROCESSES = int(os.getenv("BATCHWISE_PROCS", "20"))
BATCH_SIZE = int(os.getenv("BATCHWISE_SIZE", "100000"))

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "27017"))
DB_NAME = os.getenv("DB_NAME", "certdb")


def aggregate(collection_name: str, pipeline: list[dict]) -> list:
    with MongoClient(
        DB_HOST,
        DB_PORT,
        connectTimeoutMS=3000,
        serverSelectionTimeoutMS=3000,
    ) as client:
        db = client[DB_NAME]
        return list(db[collection_name].aggregate(pipeline, allowDiskUse=True))


def aggregate_certs(pipeline: list[dict]) -> list:
    return aggregate("certificates", pipeline=pipeline)


def get_batch_ids(
    collection_name: str,
    batch_size: int,
) -> Generator[tuple[int, ObjectId, ObjectId | None], None, None]:
    """Get start and end IDs for batches."""
    with MongoClient(
        DB_HOST,
        DB_PORT,
        connectTimeoutMS=3000,
        serverSelectionTimeoutMS=3000,
    ) as client:
        db = client[DB_NAME]
        coll: Collection = db[collection_name]

        i = 0
        start_id = next(
            coll.aggregate(
                [
                    {"$sort": {"_id": 1}},
                    {"$project": {"_id": 1}},
                    {"$limit": 1},
                ]
            )
        )["_id"]
        while True:
            try:
                end_id = next(
                    coll.aggregate(
                        [
                            {"$sort": {"_id": 1}},
                            {"$match": {"_id": {"$gt": start_id}}},
                            {"$project": {"_id": 1}},
                            {"$skip": batch_size - 1},
                            {"$limit": 1},
                        ]
                    )
                )["_id"]
            except StopIteration:
                end_id = None

            logger.debug(
                f"fetched batch {i} with start_id {start_id} and end_id {end_id}"
            )
            yield i, start_id, end_id

            if end_id is None:
                break
            start_id = end_id
            i += 1


def aggregate_batch(
    batch_num: int,
    id_start: ObjectId,
    id_end: ObjectId | None,
    *,
    collection_name: str,
    pipeline: list[dict],
):
    start = timeit.default_timer()
    logger.debug(f"starting batch {batch_num} ({id_start} - {id_end})")

    with MongoClient(
        DB_HOST,
        DB_PORT,
        connectTimeoutMS=3000,
        serverSelectionTimeoutMS=3000,
    ) as client:
        db = client[DB_NAME]
        coll: Collection = db[collection_name]
        try:
            return list(
                coll.aggregate(
                    [
                        {"$sort": {"_id": 1}},
                        {
                            "$match": {
                                "_id": {
                                    "$gte": id_start,
                                    **({"$lt": id_end} if id_end else {}),
                                },
                            },
                        },
                        *pipeline,
                    ]
                )
            )
        except Exception as e:
            logger.error(f"Error running batch {batch_num}: {e!r}")
            raise
        finally:
            logger.info(
                f"Batch {batch_num} done in {timeit.default_timer() - start:.2f}s"
            )


def aggregate_batchwise(
    collection_name: str,
    pipeline: list,
    *,
    batch_size: int = BATCH_SIZE,
    processes: int = PROCESSES,
) -> list:
    logger.info(
        f"starting batchwise aggregation on {collection_name} with {processes} processes and batch size {batch_size}"
    )
    with MongoClient(
        DB_HOST,
        DB_PORT,
        connectTimeoutMS=3000,
        serverSelectionTimeoutMS=3000,
    ) as client:
        db = client[DB_NAME]
        total_docs = db[collection_name].estimated_document_count()

    n_batches = total_docs // batch_size + 1
    logger.info(
        f"Estimated {n_batches} batches with batch size {batch_size} ({total_docs} total documents)"
    )
    batches = get_batch_ids(collection_name=collection_name, batch_size=batch_size)
    aggregate_func = functools.partial(
        aggregate_batch, collection_name=collection_name, pipeline=pipeline
    )
    start = timeit.default_timer()
    with Pool(processes) as pool:
        results = [r for r_list in pool.starmap(aggregate_func, batches) for r in r_list]
    logger.info(f"Done in {timeit.default_timer() - start:.2f}s")
    return results


def aggregate_certs_batchwise(
    pipeline: list, *, batch_size: int = BATCH_SIZE, processes: int = PROCESSES
) -> list:
    return aggregate_batchwise(
        "certificates", pipeline=pipeline, batch_size=batch_size, processes=processes
    )


def reduce_groups(
    results: list[dict[str, Any]], group_by: tuple[str, ...]
) -> list[dict[str, Any]]:
    """
    Reduce a list of dictionaries by grouping them based on specified keys and adding their other values together.

    Args:
        results: List of dictionaries to be reduced.
        group_by: Keys to group by.
    """
    if isinstance(group_by, str):
        group_by = (group_by,)
    try:
        unique_groups: dict[str, dict] = {}
        for res in results:
            group_by_values = json.dumps(
                {k: v for k, v in res.items() if k in group_by}, sort_keys=True
            )
            data_values = {key: val for key, val in res.items() if key not in group_by}
            if group_by_values not in unique_groups:
                unique_groups[group_by_values] = data_values
            else:
                for k, v in data_values.items():
                    if k not in unique_groups[group_by_values]:
                        unique_groups[group_by_values][k] = v
                    else:
                        unique_groups[group_by_values][k] += v
        return [
            {**json.loads(group_vals), **data_vals}
            for group_vals, data_vals in unique_groups.items()
        ]
    except Exception:
        savefile = Path("reduce_error_save.json")
        savefile.write_text(json.dumps(results, indent=4))
        logger.error(f"Error reducing groups, dumped results to {savefile}")
        raise
