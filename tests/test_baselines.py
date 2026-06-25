import math
import unittest

from baselines import (
    clip,
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
    def test_clip_bounds_values_to_zero_one_interval(self):
        self.assertEqual(clip(-0.25), 0.0)
        self.assertEqual(clip(0.4), 0.4)
        self.assertEqual(clip(1.25), 1.0)

    def test_robust_deviation_empty_history_returns_zero(self):
        self.assertEqual(robust_deviation(10, []), 0.0)

    def test_robust_deviation_matches_approved_median_mad_formula(self):
        history = [1, 2, 4, 7]
        center = 3.0
        mad = 1.5
        denominator = max(1.0, 1.4826 * mad)
        expected = min(1.0, max(0.0, (5 - center) / denominator) / 4.0)
        self.assertAlmostEqual(robust_deviation(5, history), expected)

    def test_robust_deviation_caps_at_one_and_uses_zero_below_center(self):
        history = [1, 1, 2, 2, 3]
        self.assertEqual(robust_deviation(100, history), 1.0)
        self.assertEqual(robust_deviation(0, history), 0.0)

    def test_logon_hour_anomaly_matches_exact_laplace_smoothed_value(self):
        counts = {8: 20, 9: 10}
        total = 30
        common_probability = (20 + 1) / (total + 24)
        unseen_probability = (0 + 1) / (total + 24)
        expected_unseen = 1.0 - unseen_probability / common_probability
        self.assertAlmostEqual(logon_hour_anomaly(2, counts), expected_unseen)

    def test_unseen_logon_hour_is_more_anomalous_than_common_hour(self):
        counts = {8: 20, 9: 10}
        self.assertGreater(logon_hour_anomaly(2, counts), logon_hour_anomaly(8, counts))

    def test_new_usb_is_maximally_novel_without_history(self):
        self.assertEqual(usb_deviation(1, [], seen_before=False), 1.0)

    def test_seen_usb_uses_robust_deviation_when_it_is_larger(self):
        history = [1, 1, 2, 2, 3]
        center = 2
        mad = 1
        denominator = max(1.0, 1.4826 * mad)
        expected = min(1.0, max(0.0, (6 - center) / denominator) / 4.0)
        self.assertAlmostEqual(
            usb_deviation(6, history, seen_before=True),
            expected,
        )

    def test_domain_novelty_decays_with_prior_visits(self):
        self.assertEqual(domain_novelty(0), 1.0)
        self.assertAlmostEqual(domain_novelty(3), 0.5)

    def test_social_neighborhood_novelty_is_set_difference_ratio(self):
        self.assertEqual(
            social_neighborhood_novelty({"a", "b", "c"}, {"a"}),
            2 / 3,
        )

    def test_social_neighborhood_novelty_is_zero_for_empty_current_set(self):
        self.assertEqual(social_neighborhood_novelty(set(), {"a"}), 0.0)

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

    def test_score_uc1_matches_exact_non_saturated_coefficients(self):
        expected = 0.20 * 0.5 + 0.25 * 0.6 + 0.25 * 0.4 + 0.15 * 0.2 + 0.15 * 0.8
        self.assertAlmostEqual(
            score_uc1(A=0.5, U=0.6, F=0.4, D=0.2, C1=0.8),
            expected,
        )

    def test_score_uc2_matches_exact_non_saturated_coefficients(self):
        expected = 0.25 * 0.4 + 0.25 * 0.3 + 0.20 * 0.6 + 0.15 * 0.5 + 0.15 * 0.7
        self.assertAlmostEqual(
            score_uc2(M=0.4, K=0.3, E=0.6, R=0.5, C2=0.7),
            expected,
        )

    def test_weighted_scores_clip_when_public_inputs_exceed_one(self):
        self.assertEqual(score_uc1(A=2, U=2, F=2, D=2, C1=2), 1.0)
        self.assertEqual(score_uc2(M=2, K=2, E=2, R=2, C2=2), 1.0)


if __name__ == "__main__":
    unittest.main()
