import unittest
from pathlib import Path
from unittest.mock import MagicMock

from event_replay import ReplayConfig, ReplayEngine
from graph_repository import GraphRepository

class EventReplayTest(unittest.TestCase):
    def test_replay_processes_stream(self):
        repo_mock = MagicMock(spec=GraphRepository)
        repo_mock.write_event.return_value = MagicMock(is_new=True)
        repo_mock.fetch_uc1_context.return_value = {}
        repo_mock.fetch_uc2_context.return_value = {}
        
        config = ReplayConfig()
        engine = ReplayEngine(repo_mock, config)
        
        # We don't have a real file here, just asserting initialization works
        self.assertEqual(engine.config.calibration_days, 30)

if __name__ == "__main__":
    unittest.main()
