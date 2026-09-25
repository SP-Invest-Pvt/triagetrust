import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.helpers import FakeProvider, Oracle, finding
from triagetrust import gate, policy
from triagetrust.evaluate import majority, run_eval, stratified_sample
from triagetrust.ingest import checkmarx, sarif
from triagetrust.models import FP, TP, UNSURE, Finding, Verdict
from triagetrust.stats import wilson
from triagetrust.triagers.llm import LLMTriager
from triagetrust.triagers.rules import RuleTriager

FIX = Path(__file__).parent / "fixtures"


class Stats(unittest.TestCase):
    def test_wilson_zero_errors_is_not_zero(self):
        lo, hi = wilson(0, 100)
        self.assertEqual(lo, 0.0)
        self.assertAlmostEqual(hi, 0.037, places=3)

    def test_wilson_empty(self):
        self.assertEqual(wilson(0, 0), (0.0, 1.0))


class Rules(unittest.TestCase):
    def v(self, cat, code, config=None):
        f = Finding("x", "r", cat, None, "a", 1, code=code, label=None, extra={"config": config or {}})
        return RuleTriager().triage(f).verdict

    def test_hash(self):
        self.assertEqual(self.v("hash", 'MessageDigest.getInstance("MD5")'), TP)
        self.assertEqual(self.v("hash", 'MessageDigest.getInstance("SHA-256")'), FP)
        code = 'String algorithm = benchmarkprops.getProperty("hashAlg2", "SHA512");\nMessageDigest.getInstance(algorithm)'
        self.assertEqual(self.v("hash", code, {"hashAlg2": "SHA-256"}), FP)
        self.assertEqual(self.v("hash", code, {"hashAlg2": "MD5"}), TP)

    def test_crypto(self):
        self.assertEqual(self.v("crypto", 'Cipher.getInstance("DES/CBC/PKCS5Padding")'), TP)
        self.assertEqual(self.v("crypto", 'Cipher.getInstance("AES/GCM/NoPadding")'), FP)

    def test_random_and_cookie(self):
        self.assertEqual(self.v("weakrand", "double d = new java.util.Random().nextDouble();"), TP)
        self.assertEqual(self.v("weakrand", "java.security.SecureRandom r;"), FP)
        self.assertEqual(self.v("securecookie", "c.setSecure(false);"), TP)
        self.assertEqual(self.v("securecookie", "c.setSecure(true);"), FP)

    def test_abstains_on_dataflow(self):
        self.assertEqual(self.v("sqli", "executeQuery(sql)"), UNSURE)


class Evaluate(unittest.TestCase):
    def test_metrics_and_consistency(self):
        fs = [finding(i, label=i % 2 == 0) for i in range(20)]
        tri = Oracle(wrong={"f0"}, noisy={"f3", "f5"}, abstain={"f7"})
        with tempfile.TemporaryDirectory() as d:
            res = run_eval(fs, tri, d, runs=3, progress=False)
            m = res["overall"]
            self.assertEqual(m["n"], 20)
            self.assertEqual(m["dismissed_real"], 1)          # f0 real, dismissed
            self.assertEqual(m["uncertain_fp"], 1)            # f7 abstained
            self.assertAlmostEqual(m["consistency"], 18 / 20)  # f3, f5 flip between runs
            self.assertTrue((Path(d) / "verdicts.jsonl").exists())

    def test_majority_tie_is_uncertain(self):
        self.assertEqual(majority([TP, FP]), UNSURE)
        self.assertEqual(majority([TP, TP, FP]), TP)

    def test_stratified_sample_keeps_mix(self):
        fs = [finding(i, cat="sqli" if i < 50 else "xss", label=i % 3 == 0) for i in range(100)]
        s = stratified_sample(fs, 20, seed=1)
        self.assertEqual(len(s), 20)
        self.assertEqual({f.category for f in s}, {"sqli", "xss"})


class Policy(unittest.TestCase):
    def evidence(self, **kw):
        m = {"n": 200, "n_real": 100, "n_false_positive": 100, "dismissed_real": 0, "false_dismissal_rate": 0.0,
             "false_dismissal_upper95": 0.037, "noise_reduction": 0.8, "abstention_rate": 0.1,
             "decided_accuracy": 0.97, "consistency": 0.99}
        m.update(kw)
        return m

    def test_modes(self):
        t = policy.Thresholds()
        self.assertEqual(policy.decide(self.evidence(), t)[0], "auto_dismiss")
        self.assertEqual(policy.decide(self.evidence(false_dismissal_upper95=0.09), t)[0], "assist")
        self.assertEqual(policy.decide(self.evidence(n_real=10), t)[0], "assist")
        self.assertEqual(policy.decide(self.evidence(decided_accuracy=0.5), t)[0], "blocked")
        self.assertEqual(policy.decide(self.evidence(consistency=0.7), t)[0], "blocked")
        self.assertEqual(policy.decide(self.evidence(n_false_positive=0), t)[0], "assist")


class Gate(unittest.TestCase):
    def make_policy(self, days=30):
        now = datetime.now(timezone.utc)
        return {"triager": "llm:gemini", "model": "m1", "expires_at": (now + timedelta(days=days)).isoformat(),
                "thresholds": {"min_confidence": 0.8}, "default_mode": "assist",
                "categories": {"crypto": {"mode": "auto_dismiss"}, "sqli": {"mode": "assist"}, "xss": {"mode": "blocked"}}}

    def test_actions_and_chain(self):
        pol = self.make_policy()
        fs = {"a": finding("a", "crypto"), "b": finding("b", "crypto"), "c": finding("c", "sqli"),
              "d": finding("d", "xss"), "e": finding("e", "crypto")}
        fs = {k: Finding(k, "r", v.category, None, "f", 1) for k, v in fs.items()}
        vs = [Verdict("a", FP, 0.95, triager="llm:gemini", model="m1"), Verdict("b", FP, 0.5, triager="llm:gemini", model="m1"),
              Verdict("c", FP, 0.99, triager="llm:gemini", model="m1"), Verdict("d", FP, 0.99, triager="llm:gemini", model="m1"),
              Verdict("e", TP, 0.9, triager="llm:gemini", model="m1")]
        recs, counts = gate.apply(pol, fs, vs)
        self.assertEqual([r["action"] for r in recs], ["auto_dismiss", "human_review", "human_review", "human_review", "fix_queue"])
        self.assertEqual(recs[1]["prev"], recs[0]["hash"])

    def test_refuses_expired_or_mismatched(self):
        with self.assertRaises(gate.GateError):
            gate.check_policy(self.make_policy(days=-1), "llm:gemini", "m1")
        with self.assertRaises(gate.GateError):
            gate.check_policy(self.make_policy(), "llm:gemini", "m2")
        gate.check_policy(self.make_policy(), "llm:gemini", "m1")


class Ingest(unittest.TestCase):
    def test_checkmarx(self):
        fs = checkmarx.load(FIX / "checkmarx_results.json", FIX / "src")
        self.assertEqual(len(fs), 2)
        self.assertEqual(fs[0].category, "sqli")
        self.assertTrue(fs[0].label)
        self.assertIsNone(fs[1].label)
        self.assertIn("executeQuery", fs[0].code)

    def test_sarif(self):
        fs = sarif.load(FIX / "results.sarif", FIX / "src")
        self.assertEqual([f.category for f in fs], ["sqli", "sqli"])
        self.assertEqual(fs[0].cwe, 89)
        self.assertIsNone(fs[0].label)
        self.assertFalse(fs[1].label)


class LLM(unittest.TestCase):
    def test_parses_and_caches(self):
        with tempfile.TemporaryDirectory() as d:
            p = FakeProvider(['```json\n{"verdict":"false_positive","confidence":0.9,"reasoning":"constant"}\n```'], cache_dir=d)
            t = LLMTriager(p)
            v = t.triage(finding(1))
            self.assertEqual((v.verdict, v.confidence), (FP, 0.9))
            t.triage(finding(1))
            self.assertEqual(p.calls, 1)  # second call served from cache

    def test_malformed_output_becomes_uncertain(self):
        with tempfile.TemporaryDirectory() as d:
            v = LLMTriager(FakeProvider(["I think it is fine"], cache_dir=d)).triage(finding(1))
            self.assertEqual(v.verdict, UNSURE)
            self.assertIn("parse error", v.error)


if __name__ == "__main__":
    unittest.main()
