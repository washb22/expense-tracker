import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path


_TEMP_DIR = tempfile.TemporaryDirectory()
_DATABASE_PATH = Path(_TEMP_DIR.name) / "moneylog-fixture.db"
os.environ["DATABASE_URL"] = f"sqlite:///{_DATABASE_PATH.as_posix()}"

from app import (  # noqa: E402
    MenuPermission,
    Platform,
    Product,
    Rule,
    Sale,
    Transaction,
    User,
    Workspace,
    WorkspaceMember,
    app,
    db,
)


class MoneyLogRegressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        with app.app_context():
            db.create_all()
            owner = User(username="owner", email="owner@example.com")
            owner.set_password("password")
            member = User(username="member", email="member@example.com")
            member.set_password("password")
            workspace = Workspace(name="Fixture Workspace")
            db.session.add_all([owner, member, workspace])
            db.session.flush()
            db.session.add_all(
                [
                    WorkspaceMember(
                        user_id=owner.id, workspace_id=workspace.id, role="owner"
                    ),
                    WorkspaceMember(
                        user_id=member.id, workspace_id=workspace.id, role="member"
                    ),
                    MenuPermission(
                        user_id=member.id,
                        workspace_id=workspace.id,
                        menu_name="dashboard",
                    ),
                    Transaction(
                        date=datetime(2026, 8, 1),
                        merchant="Fixture Merchant",
                        amount=10000,
                        category="광고비",
                        workspace_id=workspace.id,
                    ),
                    Rule(
                        keyword="fixture",
                        category="광고비",
                        workspace_id=workspace.id,
                    ),
                ]
            )
            product = Product(
                name="Fixture Product",
                sku="FIX-1",
                cost_price=3000,
                workspace_id=workspace.id,
            )
            platform = Platform(
                name="Fixture Platform",
                commission_rate=10,
                workspace_id=workspace.id,
            )
            db.session.add_all([product, platform])
            db.session.flush()
            db.session.add(
                Sale(
                    date=datetime(2026, 8, 2),
                    product_id=product.id,
                    platform_id=platform.id,
                    selling_price=10000,
                    quantity=1,
                    total_selling_amount=10000,
                    total_cost_amount=3000,
                    commission_amount=1000,
                    net_profit=6000,
                    workspace_id=workspace.id,
                )
            )
            db.session.commit()
            cls.workspace_id = workspace.id
            cls.member_id = member.id

    @classmethod
    def tearDownClass(cls):
        with app.app_context():
            db.session.remove()
            db.drop_all()
            db.engine.dispose()
        _TEMP_DIR.cleanup()

    def setUp(self):
        self.client = app.test_client()

    def login(self, username="owner"):
        response = self.client.post(
            "/login",
            data={"username": username, "password": "password"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)

    def test_login_and_workspace_selection(self):
        self.assertEqual(self.client.get("/login").status_code, 200)
        self.login()
        response = self.client.get(f"/workspace/select/{self.workspace_id}")
        self.assertEqual(response.status_code, 302)

    def test_owner_core_pages_render_from_fixture_database(self):
        self.login()
        pages = {
            "expense dashboard": "/",
            "transaction classification": "/classify",
            "category rules": "/rules",
            "business dashboard": "/business/dashboard",
            "sales": "/business/sales",
            "products and platforms": "/business/products",
            "advertising dashboard": "/business/ads/dashboard",
            "workspace management": "/workspace",
            "member menu permissions": (
                f"/workspace/{self.workspace_id}/permissions/{self.member_id}"
            ),
        }
        for label, path in pages.items():
            with self.subTest(page=label):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200, response.data[:500])

    def test_member_menu_permission_blocks_ungranted_page(self):
        self.login("member")
        allowed = self.client.get("/")
        denied = self.client.get("/business/sales", follow_redirects=False)
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(denied.status_code, 302)
        self.assertTrue(denied.headers["Location"].endswith("/"))


if __name__ == "__main__":
    unittest.main()
