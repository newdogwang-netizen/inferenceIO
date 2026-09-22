import unittest
from decimal import Decimal
from summarize_tb4_sourcemap import usage_metrics


class UsageMetricsTests(unittest.TestCase):
    def test_disjoint_buckets_and_reasoning_subset(self):
        values, cost = usage_metrics(dict(input_tokens=100, output_tokens=20,
            input_tokens_details=dict(cached_tokens=60, cache_write_tokens=30),
            output_tokens_details=dict(reasoning_tokens=8)))
        self.assertEqual(values['ordinary_input_tokens'], 10)
        self.assertEqual(values['output_tokens'], 20)
        self.assertEqual(values['reasoning_tokens'], 8)
        self.assertEqual(cost, Decimal('0.000614'))

    def test_context_threshold_is_per_request(self):
        _, short = usage_metrics(dict(input_tokens=272000, output_tokens=1))
        metrics, long = usage_metrics(dict(input_tokens=272001, output_tokens=1))
        self.assertEqual(short, Decimal('1.08802'))
        self.assertEqual(long, Decimal('2.176038'))
        self.assertEqual(metrics['long_context_requests'], 1)

    def test_invalid_buckets_fail_closed(self):
        for usage in [dict(input_tokens=1, output_tokens=0, input_tokens_details=dict(cached_tokens=2)),
                      dict(input_tokens=-1, output_tokens=0), dict(input_tokens=True, output_tokens=0),
                      dict(input_tokens=1, output_tokens=-2)]:
            with self.assertRaises(ValueError):
                usage_metrics(usage)


if __name__ == '__main__':
    unittest.main()
