"""Strip <think>...</think> reasoning blocks from non-streamed OpenAI-provider replies.

MiniMax-M3 puts its reasoning in the reply text. Flowsint's template generator parses the whole
reply as YAML, so the block makes every generation fail. Fails the build loudly if upstream
changes the line this patches.
"""
import pathlib

p = pathlib.Path("/app/flowsint-core/src/flowsint_core/core/llm/providers/openai.py")
s = p.read_text()
old = "        return response.choices[0].message.content\n"
assert s.count(old) == 1, "upstream openai.py changed; review this patch"
new = (
    "        import re as _re\n"
    "        _text = response.choices[0].message.content or \"\"\n"
    "        return _re.sub(r\"<think>.*?</think>\s*\", \"\", _text, flags=_re.S).strip()\n"
)
p.write_text(s.replace(old, new))
print("patched", p)
