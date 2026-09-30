import importlib.util
import json
import pathlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("cpa_release", pathlib.Path(__file__).with_name("cpa-release.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def status(owner=False, active=False, requests=0):
    return {"refresh": {"owner": owner, "in_flight": 0}, "admitting": active, "http_active": requests, "plugin_active": 0,"upstream_active":0, "safe_to_stop": not owner and not active and not requests}


class ReleaseTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = pathlib.Path(self.directory.name)
        self.route = root / "route.conf"
        self.route.write_text("upstream mmc_cpa_active { server old:8317; }\n")
        self.cfg = {"state_file": str(root / "state.json"), "upstream_file": str(self.route), "initial_active": "a", "nginx_container": "entry", "instances": {"a": {"upstream": "old:8317", "container": "old"}, "b": {"upstream": "new:8317", "container": "new"}}}
        self.instances = {"a": status(True, True, 1), "b": status()}
        self.events = []
        self.release = module.Release(self.cfg, self.request, self.command)

    def request(self, name, action):
        self.events.append((name, action))
        old = self.instances[name]
        if action == "quiesce":
            self.instances[name] = status(requests=old["http_active"])
        if action == "activate":
            if any(s["refresh"]["owner"] for n, s in self.instances.items() if n != name):
                raise module.ControlError("two owners")
            self.instances[name] = status(True, True)
        return self.instances[name]

    def command(self, args):
        self.events.append(tuple(args))

    def test_switch_preserves_old_stream_and_stop_waits(self):
        self.release.switch("b")
        self.assertLess(self.events.index(("a", "quiesce")), self.events.index(("b", "activate")))
        self.assertEqual(self.release.state["active"], "b")
        self.assertIn("new:8317", self.route.read_text())
        with self.assertRaises(module.ControlError):
            self.release.stop_old()
        self.instances["a"] = status()
        self.release.stop_old()
        self.assertEqual(self.events[-1], ("docker", "stop", "old"))

    def test_route_failure_is_recoverable_same_target(self):
        def fail(args):
            raise module.ControlError("nginx test failed")
        self.release.command = fail
        with self.assertRaises(module.ControlError):
            self.release.switch("b")
        self.assertIn("old:8317", self.route.read_text())
        self.assertIsNotNone(json.loads(pathlib.Path(self.cfg["state_file"]).read_text())["pending"])
        with self.assertRaises(module.ControlError):
            self.release.stop_old()
        self.release.command = self.command
        self.release.switch("b")
        self.assertIsNone(self.release.state["pending"])

    def test_rollback_transfers_owner_back(self):
        self.release.switch("b")
        self.instances["a"] = status()
        self.release.rollback()
        self.assertEqual(self.release.state["active"], "a")
        self.assertIn("old:8317", self.route.read_text())


if __name__ == "__main__":
    unittest.main()
