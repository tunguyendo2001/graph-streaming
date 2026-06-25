import math
import unittest

from baselines import (
    domain_novelty,
    email_fanout_deviation,
    logon_hour_anomaly,
    robust_deviation,
    score_uc1,
    score_uc2,
    social_neighborhood_novelty,
    time_decay,
    usb_deviation,
)


class BaselineFormulaTest(unittest.TestCase):
    def test_robust_deviation_caps_at_one(self):
        self.assertEqual(robust_deviation(100, [1, 1, 2, 2, 3]), 1.0)
        self.assertEqual(robust_deviation(2, [1, 1, 2, 2, 3]), 0.0)

    def test_unseen_logon_hour_is_more_anomalous(self):
        counts = {8: 20, 9: 10}
        self.assertGreater(logon_hour_anomaly(2, counts), logon_hour_anomaly(8, counts))

    def test_new_usb_is_maximally_novel(self):
        self.assertEqual(usb_deviation(1, [], seen_before=False), 1.0)

    def test_domain_novelty_decays_with_prior_visits(self):
        self.assertEqual(domain_novelty(0), 1.0)
        self.assertAlmostEqual(domain_novelty(3), 0.5)

    def test_social_neighborhood_novelty_is_set_difference_ratio(self):
        self.assertEqual(
            social_neighborhood_novelty({"a", "b", "c"}, {"a"}),
            2 / 3,
        )

    def test_time_decay_uses_exponential_decay(self):
        self.assertAlmostEqual(time_decay(8 * 3600, 8 * 3600), math.exp(-1))

    def test_weighted_scores_match_approved_formulas(self):
        self.assertAlmostEqual(score_uc1(A=1, U=1, F=1, D=1, C1=1), 1.0)
        self.assertAlmostEqual(score_uc2(M=1, K=1, E=1, R=1, C2=1), 1.0)
