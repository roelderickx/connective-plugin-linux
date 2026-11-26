"""Tests for opt-in, redacted diagnostic logging.

Run from the repository root with: python3 -m unittest discover -s test -v
"""

import json
import os
import sys
import unittest
from unittest.mock import patch

# The module under test lives one directory above the test suite.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safe_logging import (  # noqa: E402
    OMITTED,
    REDACTED,
    SENSITIVE_KEYS,
    debug_enabled,
    redact_native_message,
)


class DebugEnabledTests(unittest.TestCase):
    @patch.dict(os.environ, {}, clear=True)
    def test_disabled_by_default(self):
        self.assertFalse(debug_enabled())

    def test_explicit_opt_in_values(self):
        for value in ('1', 'true', 'YES', ' on '):
            with self.subTest(value=value), patch.dict(os.environ, {'CONNECTIVE_DEBUG': value}):
                self.assertTrue(debug_enabled())

    def test_other_values_stay_off(self):
        for value in ('', '0', 'false', 'maybe'):
            with self.subTest(value=value), patch.dict(os.environ, {'CONNECTIVE_DEBUG': value}):
                self.assertFalse(debug_enabled())


class RedactionTests(unittest.TestCase):
    def test_request_secrets_are_masked_but_structure_survives(self):
        payload = json.dumps({
            'cmd': 'COMPUTE_AUTHENTICATION',
            'reader': 'Alcor Micro AU9540 00 00',
            'activationToken': 'one-time-secret',
            'hash': 'deadbeef',
        })
        result = json.loads(redact_native_message(payload))
        self.assertEqual(result['cmd'], 'COMPUTE_AUTHENTICATION')
        self.assertIn('Alcor', result['reader'])
        self.assertEqual(result['activationToken'], REDACTED)
        self.assertEqual(result['hash'], REDACTED)

    def test_identity_and_signature_data_are_masked(self):
        payload = json.dumps({
            'data': '0123456789abcdef',
            'signature': 'cafebabe',
            'valid': True,
            'pinValid': True,
            'pinRemainingAttempts': 2,
        })
        result = json.loads(redact_native_message(payload))
        self.assertEqual(result['data'], REDACTED)
        self.assertEqual(result['signature'], REDACTED)
        self.assertTrue(result['valid'])
        self.assertTrue(result['pinValid'])
        self.assertEqual(result['pinRemainingAttempts'], 2)

    def test_nested_and_listed_values_are_redacted(self):
        payload = json.dumps({
            'items': [{'token': 'abc', 'label': 'ok'}, {'hash': 'xyz'}],
            'nested': {'PIN': '1234', 'available': True},
        })
        result = json.loads(redact_native_message(payload))
        self.assertEqual(result['items'][0]['token'], REDACTED)
        self.assertEqual(result['items'][0]['label'], 'ok')
        self.assertEqual(result['items'][1]['hash'], REDACTED)
        self.assertEqual(result['nested']['PIN'], REDACTED)
        self.assertTrue(result['nested']['available'])

    def test_unparseable_payload_is_not_echoed(self):
        self.assertEqual(redact_native_message('truncated-secret-payload'), OMITTED)
        self.assertNotIn('secret', redact_native_message('truncated-secret-payload'))

    def test_every_sensitive_key_is_covered_case_insensitively(self):
        payload = json.dumps({key: 'value' for key in SENSITIVE_KEYS})
        result = json.loads(redact_native_message(payload))
        self.assertTrue(all(value == REDACTED for value in result.values()))

    def test_no_sensitive_value_survives_in_serialized_output(self):
        payload = json.dumps({'cmd': 'READ_FILE', 'data': 'FACEFEED', 'activationToken': 's3cr3t'})
        output = redact_native_message(payload)
        self.assertNotIn('FACEFEED', output)
        self.assertNotIn('s3cr3t', output)


if __name__ == '__main__':
    unittest.main()
