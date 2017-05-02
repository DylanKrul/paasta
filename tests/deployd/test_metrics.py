from __future__ import absolute_import
from __future__ import unicode_literals

import unittest

import mock
from py.test import raises

from paasta_tools.deployd import metrics


class TestNoMetrics(unittest.TestCase):

    def setUp(self):
        self.metrics = metrics.NoMetrics()

    def test_timer(self):
        timer = self.metrics.create_timer('name', dimension='thing')
        timer.start()
        timer.stop()

    def test_gauge(self):
        gauge = self.metrics.create_gauge('name', dimension='thing')
        gauge.set(1212)


class TestMeteoriteMetrics(unittest.TestCase):
    def setUp(self):
        self.mock_meteorite = mock.Mock()
        metrics.yelp_meteorite = self.mock_meteorite
        self.metrics = metrics.MeteoriteMetrics()

    def test_init(self):
        metrics.yelp_meteorite = None
        with raises(ImportError):
            metrics.MeteoriteMetrics()

    def test_init_no_error(self):
        metrics.MeteoriteMetrics()

    def test_create_timer(self):
        self.metrics.create_timer('name', dimension='thing')
        self.mock_meteorite.create_timer.assert_called_with('paasta.deployd.name', {'dimension': 'thing'})

    def test_create_gauge(self):
        self.metrics.create_gauge('name', dimension='thing')
        self.mock_meteorite.create_gauge.assert_called_with('paasta.deployd.name', {'dimension': 'thing'})

    def tearDown(self):
        metrics.yelp_meteorite = None


class TestQueueMetrics(unittest.TestCase):
    def setUp(self):
        mock_metrics_provider = mock.Mock()
        self.mock_gauge = mock.Mock()
        self.mock_inbox_q = mock.Mock()
        self.mock_bounce_q = mock.Mock()
        mock_create_gauge = mock.Mock(return_value=self.mock_gauge)
        mock_metrics_provider.create_gauge = mock_create_gauge
        self.q_metrics = metrics.QueueMetrics(self.mock_inbox_q, self.mock_bounce_q, mock_metrics_provider)

    def test_run(self):
        with mock.patch('time.sleep', autospec=True, side_effect=LoopBreak):
            with raises(LoopBreak):
                self.q_metrics.run()
            assert self.mock_gauge.set.call_count == 2


class LoopBreak(Exception):
    pass