"""Run the MoneyLog advertising scheduler as one explicit process."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apscheduler.schedulers.blocking import BlockingScheduler  # noqa: E402
from apscheduler.triggers.cron import CronTrigger  # noqa: E402

from app import run_daily_meta_fetch  # noqa: E402


def main():
    scheduler = BlockingScheduler(timezone="Asia/Seoul")
    scheduler.add_job(
        run_daily_meta_fetch,
        CronTrigger(hour=2, minute=0),
        id="daily-meta-fetch",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
    )
    print("MoneyLog scheduler started (daily-meta-fetch at 02:00 Asia/Seoul)")
    scheduler.start()


if __name__ == "__main__":
    main()
