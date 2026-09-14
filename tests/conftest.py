"""Test-session setup: keep the suite offline and deterministic.

Must run before `sentinelx.config` is imported, which is why it lives in conftest.
"""
import os

# A real key in .env would otherwise make every end-to-end test call the LLM.
os.environ["SENTINELX_LLM_PROVIDER"] = "none"
# No test may ever execute a sample: the suite runs sandbox-free, and tests that
# need a dynamic block ask for the `mock` backend explicitly.
os.environ["SENTINELX_DYNAMIC_BACKEND"] = "none"
