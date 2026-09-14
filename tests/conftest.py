"""Test-session setup: keep the suite offline and deterministic.

Must run before `sentinelx.config` is imported, which is why it lives in conftest.
"""
import os

# A real key in .env would otherwise make every end-to-end test call the LLM.
os.environ["SENTINELX_LLM_PROVIDER"] = "none"
