"""
Job Scheduler - Schedule collection tasks
"""

import logging
from typing import Callable
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)


class JobScheduler:
    """
    Background job scheduler using APScheduler

    Schedules collection tasks to run at intervals.

    NOTE: Only accepts SYNCHRONOUS functions.
    If you have async functions, wrap them with asyncio.run()
    BEFORE passing to this scheduler.
    """

    def __init__(self):
        """Initialize scheduler"""
        self.scheduler = BackgroundScheduler()
        self.jobs = {}

    def add_job(
            self,
            func: Callable,
            job_id: str,
            interval_minutes: int,
            start_now: bool = False
    ):
        """
        Add a job to scheduler

        Args:
            func: Synchronous function to execute
            job_id: Unique job ID
            interval_minutes: Run every N minutes
            start_now: Run immediately?
        """
        try:
            # Add job to APScheduler
            self.scheduler.add_job(
                func=func,
                trigger=IntervalTrigger(minutes=interval_minutes),
                id=job_id,
                name=f"Job: {job_id}",
                replace_existing=True,
                misfire_grace_time=60
            )

            self.jobs[job_id] = {
                "interval_minutes": interval_minutes,
                "created_at": datetime.utcnow(),
                "next_run": None
            }

            logger.info(f"Added job '{job_id}' (runs every {interval_minutes} minutes)")

            # Run immediately if requested
            if start_now:
                logger.info(f"Starting job '{job_id}' immediately...")
                try:
                    func()  # ✓ Just call it directly (must be synchronous)
                except Exception as e:
                    logger.error(f"Error running job immediately: {e}")

        except Exception as e:
            logger.error(f"Error adding job '{job_id}': {e}")

    def start(self):
        """Start the scheduler"""
        if not self.scheduler.running:
            self.scheduler.start()
            logger.info("Scheduler started")
            self._print_jobs()

    def stop(self):
        """Stop the scheduler"""
        if self.scheduler.running:
            self.scheduler.shutdown()
            logger.info("Scheduler stopped")

    def _print_jobs(self):
        """Print scheduled jobs"""
        jobs = self.scheduler.get_jobs()
        logger.info(f"Scheduled jobs ({len(jobs)}):")
        for job in jobs:
            logger.info(f"  - {job.id}: {job.trigger}")

    def get_status(self) -> dict:
        """Get scheduler status"""
        jobs = self.scheduler.get_jobs()

        return {
            "running": self.scheduler.running,
            "job_count": len(jobs),
            "jobs": [
                {
                    "id": job.id,
                    "trigger": str(job.trigger),
                    "next_run_time": job.next_run_time
                }
                for job in jobs
            ]
        }
