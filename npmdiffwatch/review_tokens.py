"""Explicit OpenAI-family tokenizer estimate for the isolated complete-source path.

This is a pinned o200k_base estimate, not discovered provider context or billing.
Protocol headroom remains separately reserved by ReviewBudget. No byte-per-token
shortcut is used to declare that readable source exceeds a 128k token context.
"""
from functools import lru_cache
import json


TOKENIZER = "tiktoken/o200k_base;16384-character-chunks"


@lru_cache(maxsize=1)
def _encoding():
    import tiktoken
    return tiktoken.get_encoding("o200k_base")


def request_tokens(system, user, schema):
    encoding = _encoding()
    # Long homogeneous attacker text can exhaust tiktoken's regex stack. Chunking
    # bounds that work; split-boundary overhead is retained conservatively.
    return sum(len(encoding.encode(text[start:start + 16384], disallowed_special=()))
               for text in (system, user, json.dumps(schema, ensure_ascii=False, separators=(",", ":")))
               for start in range(0, len(text), 16384))
