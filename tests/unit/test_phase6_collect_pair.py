import json
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts.phase6_collect_pair import check_group, port_free, ready, simulator_instance, stop_owned


class PairCollectorTest(unittest.TestCase):
    def test_group_name_cannot_escape_root(self):
        with TemporaryDirectory() as d:
            for group in ("..", ".", "../outside", "group space"):
                with self.subTest(group=group), self.assertRaises(ValueError):
                    check_group(Path(d), group, "fingerprint")

    def test_reusing_simulator_instance_or_group_is_rejected(self):
        with TemporaryDirectory() as d:
            root=Path(d);(root/"first").mkdir()
            (root/"first/session_manifest.json").write_text(json.dumps(dict(simulator_instance_fingerprint="same")))
            with self.assertRaises(ValueError):check_group(root,"first","different")
            with self.assertRaises(ValueError):check_group(root,"second","same")
            check_group(root,"second","different")

    def test_process_fingerprint_changes_on_restart(self):
        with TemporaryDirectory() as d:
            root=Path(d);(root/"sys/kernel/random").mkdir(parents=True)
            (root/"sys/kernel/random/boot_id").write_text("boot")
            process=root/"123";process.mkdir()
            (process/"cmdline").write_bytes(b"/home/test/ardupilot/build/sitl/bin/arducopter\0--model\0quad\0")
            stat=process/"stat"
            stat.write_text("123 (arducopter) " + " ".join(["S"]+["0"]*18+["100"]))
            one=simulator_instance(root)
            self.assertEqual(one,simulator_instance(root))
            stat.write_text("123 (arducopter) " + " ".join(["S"]+["0"]*18+["200"]))
            self.assertNotEqual(one,simulator_instance(root))

    def test_readiness_requires_owned_process_alive(self):
        with TemporaryDirectory() as d:
            log=Path(d)/"server.log";log.write_text("gcs_listening port=18443\n")
            process=Mock();process.poll.return_value=1
            with self.assertRaises(RuntimeError):ready(process,log)
            process.poll.return_value=None
            ready(process,log)

    def test_occupied_udp_receiver_is_rejected(self):
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as receiver:
            receiver.bind(("127.0.0.1",0))
            with self.assertRaises(OSError):port_free(receiver.getsockname()[1],socket.SOCK_DGRAM)

    def test_cleanup_only_targets_owned_process(self):
        process=Mock();process.poll.return_value=None
        stop_owned(process)
        process.send_signal.assert_called_once()
        process.wait.assert_called_once_with(timeout=15)
        process.terminate.assert_not_called()
