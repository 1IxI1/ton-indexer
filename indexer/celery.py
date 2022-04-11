import os
from celery import Celery

RABBITMQ_HOST = os.getenv("RABBITMQ_HOST")
RABBITMQ_PORT = os.getenv("RABBITMQ_PORT")

CELERY_BROKER_URL = f"amqp://{RABBITMQ_HOST}:{RABBITMQ_PORT}"
CELERY_BACKEND_URL = f"rpc://{RABBITMQ_HOST}:{RABBITMQ_PORT}"

app = Celery('indexer',
             broker=CELERY_BROKER_URL,
             backend=CELERY_BACKEND_URL,
             include=['indexer.tasks'])

# Optional configuration, see the application user guide.
app.conf.update(
    result_expires=3600, # what is it?
)

app.conf.beat_schedule = {
    "update_validation_cycle": {
        "task": "indexer.tasks.get_block",
        "schedule": 60.0
    }
}