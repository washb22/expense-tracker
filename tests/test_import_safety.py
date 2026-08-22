import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ImportSafetyTest(unittest.TestCase):
    def test_import_does_not_create_database_or_start_scheduler(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "import-must-not-create.db"
            finance_path = Path(temp_dir) / "finance-import-must-not-create.db"
            script = """
import threading
import app
import db_init
import scripts.run_scheduler
assert not any('APScheduler' in thread.name for thread in threading.enumerate())
print('safe-import')
"""
            environment = os.environ.copy()
            environment["DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
            environment["SBROCOR_FINANCE_DB_PATH"] = str(finance_path)
            result = subprocess.run(
                [sys.executable, "-c", script],
                cwd=PROJECT_ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("safe-import", result.stdout)
            self.assertFalse(database_path.exists())
            self.assertFalse(finance_path.exists())

    def test_migration_command_requires_explicit_confirmation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "migration-must-not-create.db"
            environment = os.environ.copy()
            environment["DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
            result = subprocess.run(
                [sys.executable, "scripts/migrate_moneylog.py"],
                cwd=PROJECT_ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("--confirm", result.stderr)
            self.assertFalse(database_path.exists())

    def test_finance_init_requires_confirmation_and_refuses_existing_database(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            finance_path = Path(temp_dir) / "finance.db"
            environment = os.environ.copy()
            environment["SBROCOR_FINANCE_DB_PATH"] = str(finance_path)
            environment["DATABASE_URL"] = f"sqlite:///{(Path(temp_dir) / 'legacy.db').as_posix()}"
            unconfirmed = subprocess.run(
                [sys.executable, "scripts/init_sbrocor_finance.py"],
                cwd=PROJECT_ROOT, env=environment, text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(unconfirmed.returncode, 0)
            self.assertFalse(finance_path.exists())
            confirmed = subprocess.run(
                [sys.executable, "scripts/init_sbrocor_finance.py", "--confirm", "CREATE SBROCOR FINANCE DB"],
                cwd=PROJECT_ROOT, env=environment, text=True, capture_output=True, check=False,
            )
            self.assertEqual(confirmed.returncode, 0, confirmed.stderr)
            self.assertTrue(finance_path.exists())
            second = subprocess.run(
                [sys.executable, "scripts/init_sbrocor_finance.py", "--confirm", "CREATE SBROCOR FINANCE DB"],
                cwd=PROJECT_ROOT, env=environment, text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(second.returncode, 0)

    def test_guarded_online_backup_and_read_only_verification(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source.db"
            backup = Path(temp_dir) / "backup.db"
            report = Path(temp_dir) / "verification.json"
            connection = sqlite3.connect(source)
            connection.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY, value TEXT)")
            connection.execute("INSERT INTO sample(value) VALUES ('fixture')")
            connection.commit()
            connection.close()

            preview = subprocess.run(
                [
                    sys.executable,
                    "scripts/backup_sqlite.py",
                    "--source",
                    str(source),
                    "--destination",
                    str(backup),
                ],
                cwd=PROJECT_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(preview.returncode, 0, preview.stderr)
            self.assertIn("BACKUP_NOT_CREATED", preview.stdout)
            self.assertFalse(backup.exists())

            created = subprocess.run(
                [
                    sys.executable,
                    "scripts/backup_sqlite.py",
                    "--source",
                    str(source),
                    "--destination",
                    str(backup),
                    "--execute",
                    "--confirmation",
                    "CREATE MONEYLOG SQLITE BACKUP",
                ],
                cwd=PROJECT_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            self.assertTrue(backup.exists())

            verified = subprocess.run(
                [
                    sys.executable,
                    "scripts/verify_sqlite_backup.py",
                    "--source",
                    str(source),
                    "--backup",
                    str(backup),
                    "--output",
                    str(report),
                ],
                cwd=PROJECT_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn('"status": "PASS"', verified.stdout)
            self.assertTrue(report.exists())


if __name__ == "__main__":
    unittest.main()
