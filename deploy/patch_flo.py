"""Route Flo's chat through the tool-calling agent when FLO_TOOLS=1.

Patches app/api/routes/chat.py: one call inserted before the StreamingResponse, plus a helper appended at the end.
With FLO_TOOLS unset, or on any error in the agent, the original plain-chat provider is used unchanged.
Fails the build loudly if upstream's route changes shape.
"""
import pathlib

p = pathlib.Path("/app/flowsint-api/app/api/routes/chat.py")
s = p.read_text()
assert "_flo_tools" not in s, "already patched"
anchor = "    return StreamingResponse(\n        service.stream_response(chat_id, llm_messages, provider),\n"
assert s.count(anchor) == 1, "upstream chat.py changed; review this patch"
s = s.replace(anchor, "    provider = await _flo_tools(db, current_user, chat, llm_messages, provider)\n" + anchor)
s += '''

async def _flo_tools(db, user, chat, llm_messages, provider):
    """Added by deploy/patch_flo.py: let Flo use tools when FLO_TOOLS=1, else keep the plain provider."""
    import os

    if os.environ.get("FLO_TOOLS") != "1" or os.environ.get("LLM_PROVIDER") != "openai":
        return provider
    try:
        from app.flo_agent import TextProvider, answer_with_tools

        text = await answer_with_tools(db, user, chat, llm_messages)
        return TextProvider(text) if text else provider
    except Exception as e:
        print(f"[flo] tools failed, falling back to plain chat: {e}")
        return provider
'''
p.write_text(s)
print("patched", p)
