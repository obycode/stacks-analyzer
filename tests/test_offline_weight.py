import unittest

from stacks_analyzer.detector import Detector, DetectorConfig
from stacks_analyzer.events import LogParser

PREFIX = (
    "Oct 02 11:00:00 host stacks-signer[123]: INFO [%.6f] [stacks-signer/src/v0/signer.rs:2501] [signer_runloop:30000] "
    "Cycle #144 Dry-Run signer: "
)
START = 1790950000.0
HASH = "a1799f461546b38e1e7a54461692d6a2bdd1f0fb70ffe34e8fc4a790368d7df4"

BIG = "02fcf9e4c4bf998223095d849dcda17de147c4b50ab3751164c670aea956eba68d"
SMALL = "024f164c6e73df283d34d7d9cc86553a82dce76045ba7dfbf4de0004f89eabb8e0"
REST = "0209130bec93e83b23d3366adfcbe0a1641057b9c48102572d892fe8f78de2bee7"
WEIGHTS = {BIG: 766, SMALL: 9, REST: 3225}  # sums to the 4000 total


def acceptance_line(ts, pubkey):
    return (PREFIX % ts) + (
        "Received block acceptance, signer_pubkey: %s, signer_signature_hash: %s, "
        "consensus_hash: 99e92921e6d59b67ee9c050c7dfc595e0cbac4ea, "
        "block_height: 9107767, signer_weight: %d" % (pubkey, HASH, WEIGHTS[pubkey])
    )


def total_weight_line(ts):
    return (PREFIX % ts) + (
        "Received block acceptance, but have not yet reached the acceptance "
        "threshold., signer_signature_hash: %s, signature_weight: 9, "
        "consensus_hash: 99e92921e6d59b67ee9c050c7dfc595e0cbac4ea, "
        "block_height: 9107767, total_weight_approved: 9, total_weight: 4000, "
        "percent_approved: 0.225" % HASH
    )


def state_update_line(ts, pubkey):
    return (PREFIX % ts) + (
        "Received state machine update from signer %s: StateMachineUpdate { "
        "active_protocol: 2, local_supported_protocol: 2, content: V2 { "
        "burn_block: 6a96499c2221cd0b308015bf9ce742e6df534bf2, "
        "burn_block_height: 969610, current_miner: ActiveMiner { "
        "current_miner_pkh: 1131862efa44fecf362bd79ae1c1c437129c0e40, "
        "tenure_id: 6a96499c2221cd0b308015bf9ce742e6df534bf2, "
        "parent_tenure_id: 99e92921e6d59b67ee9c050c7dfc595e0cbac4ea, "
        "parent_tenure_last_block: 2f4d618b66a5287ef16cbf06c7564c4c33dc2b40df58ba9060ea993ab5788fd7, "
        "parent_tenure_last_block_height: 9107788 }, replay_tx_count: 0 } }" % pubkey
    )


class TestOfflineSigningWeight(unittest.TestCase):
    def setUp(self):
        self.parser = LogParser()
        self.detector = Detector(DetectorConfig())
        self.alerts = []

    def feed(self, line):
        for event in self.parser.parse_line("signer", line):
            self.alerts.extend(self.detector.process_event(event))

    def run_minutes(self, start, minutes, live):
        """One round of messages per minute from the `live` signers, ticking after each."""
        for minute in range(minutes):
            ts = start + minute * 60.0
            self.feed(total_weight_line(ts))
            for pubkey in live:
                self.feed(acceptance_line(ts + 1, pubkey))
            alerts, _ = self.detector.tick(ts + 2)
            self.alerts.extend(alerts)
        return start + minutes * 60.0

    def keys(self):
        return [alert.key for alert in self.alerts]

    def test_state_machine_update_names_its_sender(self):
        events = self.parser.parse_line("signer", state_update_line(START, BIG))
        self.assertEqual(events[0].kind, "signer_state_machine_update")
        self.assertEqual(events[0].fields["signer_pubkey"], BIG)

    def test_alerts_after_an_hour_offline_then_resolves(self):
        ts = self.run_minutes(START, 15, [BIG, SMALL, REST])
        # BIG (19%) goes dark. It is flagged after the 10 min liveness window, but
        # the run is dated from when it went quiet, so the alert lands at ~1h.
        ts = self.run_minutes(ts, 55, [SMALL, REST])
        self.assertNotIn("signing-power-offline", self.keys())
        ts = self.run_minutes(ts, 7, [SMALL, REST])
        offline = [a for a in self.alerts if a.key == "signing-power-offline"]
        self.assertEqual(len(offline), 1)
        self.assertEqual(offline[0].severity, "critical")
        self.assertIn("19.1%", offline[0].message)
        self.assertIn("02fcf9e4", offline[0].message)

        # Stays dark: no repeat alert.
        ts = self.run_minutes(ts, 30, [SMALL, REST])
        self.assertEqual(self.keys().count("signing-power-offline"), 1)

        self.run_minutes(ts, 2, [BIG, SMALL, REST])
        self.assertEqual(self.keys().count("signing-power-offline-recovered"), 1)

    def test_small_signer_offline_does_not_alert(self):
        ts = self.run_minutes(START, 15, [BIG, SMALL, REST])
        self.run_minutes(ts, 120, [BIG, REST])
        self.assertNotIn("signing-power-offline", self.keys())

    def test_state_machine_updates_keep_a_signer_live(self):
        ts = self.run_minutes(START, 15, [BIG, SMALL, REST])
        for minute in range(90):
            t = ts + minute * 60.0
            if minute % 5 == 0:
                self.feed(state_update_line(t, BIG))
            self.run_minutes(t, 1, [SMALL, REST])
        self.assertNotIn("signing-power-offline", self.keys())

    def test_network_wide_silence_is_not_offline_weight(self):
        ts = self.run_minutes(START, 15, [BIG, SMALL, REST])
        # Nobody says anything for two hours (e.g. a chain stall).
        for minute in range(120):
            alerts, _ = self.detector.tick(ts + minute * 60.0)
            self.alerts.extend(alerts)
        self.assertNotIn("signing-power-offline", self.keys())


if __name__ == "__main__":
    unittest.main()
