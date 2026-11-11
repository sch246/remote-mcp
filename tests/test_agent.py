#!/usr/bin/env python3
"""Focused regressions for the standalone remote agent."""

import os
import sys
import unittest
from unittest.mock import patch


os.environ.setdefault("REMOTE_AGENT_TOKEN", "test-token")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import agent  # noqa: E402


class AgentHandlerTest(unittest.TestCase):
    def test_log_message_without_console_stderr(self):
        handler = object.__new__(agent.Handler)
        handler.client_address = ("127.0.0.1", 12345)

        with patch.object(agent.sys, "stderr", None):
            handler.log_message("%s", "GET /ping")


if __name__ == "__main__":
    unittest.main()
