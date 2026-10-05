import contextlib
import io
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import lab_support
import setup_lab

SUB = "22222222-2222-4222-8222-222222222222"
TENANT = "11111111-1111-4111-8111-111111111111"
LAB = "33333333-3333-4333-8333-333333333333"


class OperatorSafetyTests(unittest.TestCase):
    def test_rejects_noncanonical_subscription(self):
        with self.assertRaises(ValueError):
            lab_support.guid("../../subscriptions/prod")

    def test_private_path_cannot_escape(self):
        with self.assertRaises(ValueError):
            lab_support.private_path(str(ROOT / "private" / ".." / "config" / "manifest.json"))

    def test_context_tenant_mismatch(self):
        with patch.object(lab_support, "az", return_value={"id": SUB, "tenantId": SUB}):
            with self.assertRaisesRegex(RuntimeError, "Tenant context"):
                lab_support.assert_context(SUB, TENANT)

    def test_missing_live_ownership_tag(self):
        manifest = {"subscription_id": SUB, "tenant_id": TENANT, "lab_id": LAB, "resource_group": "nls-storm3168-12345678"}
        group = {"id": lab_support.rg_id(manifest), "tags": {"purpose": "looks-like-a-lab"}}
        with patch.object(lab_support, "assert_context"), patch.object(lab_support, "az", return_value=group):
            with self.assertRaisesRegex(RuntimeError, "ownership tag"):
                lab_support.assert_owned(manifest, SUB)

    def test_different_server_resource_identity(self):
        manifest = {"subscription_id": SUB, "tenant_id": TENANT, "lab_id": LAB, "resource_group": "nls-storm3168-12345678"}
        group = {"id": lab_support.rg_id(manifest) + "-other", "tags": {"storm3168LabId": LAB}}
        with patch.object(lab_support, "assert_context"), patch.object(lab_support, "az", return_value=group):
            with self.assertRaisesRegex(RuntimeError, "identity mismatch"):
                lab_support.assert_owned(manifest, SUB)

    def test_setup_plan_does_not_create_resources_or_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / "manifest.json"
            argv = ["setup_lab.py", "--subscription", SUB, "--budget-usd", "10"]
            with patch.object(sys, "argv", argv), patch.object(setup_lab, "private_path", return_value=target), \
                 patch.object(setup_lab, "assert_context", return_value={"tenantId": TENANT}), \
                 patch.object(setup_lab, "az") as azure, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(setup_lab.main(), 0)
                azure.assert_not_called()
                self.assertFalse(target.exists())

    def test_setup_refuses_existing_group_before_manifest_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / "manifest.json"
            argv = ["setup_lab.py", "--subscription", SUB, "--budget-usd", "10", "--execute"]
            with patch.object(sys, "argv", argv), patch.object(setup_lab, "private_path", return_value=target), \
                 patch.object(setup_lab, "assert_context", return_value={"tenantId": TENANT}), \
                 patch.object(setup_lab, "az", return_value=True) as azure, contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, "refusing adoption"):
                    setup_lab.main()
                self.assertEqual(azure.call_count, 1)
                self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
