import os, unittest
from unittest.mock import patch
try:
    from fastapi import HTTPException
    from integrations.unified_ai_hub_adapter import _config, hub_search, SearchInput
except ImportError:
    from unified_ai_hub_adapter import _config, hub_search, SearchInput
class AdapterTests(unittest.TestCase):
    def test_missing_token_fails_closed(self):
        with patch.dict(os.environ,{"UNIFIEDAIHUB_API_TOKEN":""},clear=False):
            with self.assertRaises(HTTPException) as e: _config()
            self.assertEqual(e.exception.status_code,503)
    def test_search_response_shape(self):
        with patch("integrations.unified_ai_hub_adapter._request",return_value={"results":[{"title":"fixture"}]}):
            self.assertEqual(hub_search(SearchInput(query="fixture"))["count"],1)
if __name__=="__main__": unittest.main()
