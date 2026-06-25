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
    temporal_order,
    time_decay,
    usb_deviation,
    weighted_coverage,
)


class BaselineFormulaTest(unittest.TestCase):
    def test_robust_deviation_caps_at_one_and_uses_zero_for_center(self):
        history = [1, 1, 2, 2, 3]
        self.assertEqual(robust_deviation(100, history), 1.0)
        self.assertEqual(robust_deviation(2, history), 0.0)

    def test_unseen_logon_hour_is_more_anomalous_than_common_hour(self):
        counts = {8: 20, 9: 10}
        self.assertGreater(logon_hour_anomaly(2, counts), logon_hour_anomaly(8, counts))

    def test_new_usb_is_maximally_novel_without_history(self):
        self.assertEqual(usb_deviation(1, [], seen_before=False), 1.0)

    def test_domain_novelty_decays_with_prior_visits(self):
        self.assertEqual(domain_novelty(0), 1.0)
        self.assertAlmostEqual(domain_novelty(3), 0.5)

    def test_social_neighborhood_novelty_is_set_difference_ratio(self):
        self.assertEqual(
            social_neighborhood_novelty({"a", "b", "c"}, {"a"}),
            2 / 3,
        )

    def test_email_fanout_deviation_uses_the_larger_signal(self):
        self.assertEqual(
            email_fanout_deviation(
                current_email_count=25,
                current_window_count=4,
                per_email_history=[2, 2, 3, 3, 4],
                window_history=[4, 4, 4, 4],
            ),
            1.0,
        )
        self.assertEqual(
            email_fanout_deviation(
                current_email_count=3,
                current_window_count=20,
                per_email_history=[3, 3, 3],
                window_history=[1, 1, 2, 2, 3],
            ),
            1.0,
        )

    def test_weighted_coverage_requires_weights_for_every_stage(self):
        self.assertAlmostEqual(
            weighted_coverage(
                {"after_hours": True, "usb": False, "file_copy": True},
                {"after_hours": 0.2, "usb": 0.25, "file_copy": 0.25},
            ),
            0.45,
        )
        with self.assertRaises(ValueError):
            weighted_coverage(
                {"after_hours": True, "usb": False},
                {"after_hours": 0.2},
            )

    def test_temporal_order_ignores_none_pairs_and_handles_missing_comparisons(self):
        self.assertAlmostEqual(
            temporal_order([(1, 2), (5, 4), (None, 3), (7, None)]),
            0.5,
        )
        self.assertEqual(temporal_order([(None, 1), (2, None)]), 0.0)

    def test_time_decay_uses_exponential_decay(self):
        self.assertAlmostEqual(time_decay(8 * 3600, 8 * 3600), math.exp(-1))

    def test_time_decay_rejects_nonpositive_horizon(self):
        with self.assertRaises(ValueError):
            time_decay(1, 0)
        with self.assertRaises(ValueError):
            time_decay(1, -1)

    def test_weighted_scores_match_approved_formulas(self):
        self.assertAlmostEqual(score_uc1(A=1, U=1, F=1, D=1, C1=1), 1.0)
        self.assertAlmostEqual(score_uc2(M=1, K=1, E=1, R=1, C2=1), 1.0)


if __name__ == "__main__":
    unittest.main()
