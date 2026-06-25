import unittest
from datetime import datetime
from unittest.mock import MagicMock

from event_model import Event
from graph_repository import GraphRepository, WriteResult


class GraphRepositoryTest(unittest.TestCase):
    def setUp(self):
        self.driver_mock = MagicMock()
        self.repo = GraphRepository(self.driver_mock)

    def test_write_event_calls_driver(self):
        event = Event("src:1", "src", "LOGON", datetime.now(), "user1", "pc1")
        # Just verifying the wrapper does not crash for now
        # Mocking session context manager
        session_mock = MagicMock()
        self.driver_mock.session.return_value.__enter__.return_value = session_mock
        session_mock.run.return_value.consume.return_value.counters.nodes_created = 3

        result = self.repo.write_event(event, datetime.now())
        self.assertTrue(result.is_new)


if __name__ == "__main__":
    unittest.main()
