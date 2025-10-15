from celery import Celery
import os

celery = Celery(
    __name__,
    broker=os.environ.get('CELERY_BROKER_URL', 'redis://redis-recon:6379/0'),
    backend=os.environ.get('CELERY_RESULT_BACKEND', 'redis://redis-recon:6379/0')
)

celery.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)
