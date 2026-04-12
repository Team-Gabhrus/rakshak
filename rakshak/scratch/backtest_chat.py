import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

# Mocking the components as they exist in chat.py
class MockPart:
    def __init__(self, function_call=None, text=None):
        self.function_call = function_call
        self.text = text

class MockFunctionCall:
    def __init__(self, name, args):
        self.name = name
        self.args = args

class MockCandidate:
    def __init__(self, parts):
        self.content = MagicMock(parts=parts)

class MockChunk:
    def __init__(self, parts):
        self.candidates = [MockCandidate(parts)]

async def mock_tool_handler(db, hostname):
    return f"CBOM for {hostname}"

async def backtest_loop():
    print("Starting Backtest: Manual Tool Execution Loop")
    
    # Setup
    db = MagicMock()
    tool_map = {"get_subdomain_detailed_cbom": mock_tool_handler}
    
    # 1st Turn: Gemini requests a tool call
    turn1_parts = [MockPart(function_call=MockFunctionCall("get_subdomain_detailed_cbom", {"hostname": "api.test.com"}))]
    turn1_response = [MockChunk(turn1_parts)]
    
    # 2nd Turn: Gemini returns text after receiving tool response
    turn2_parts = [MockPart(text="The CBOM for api.test.com shows ML-KEM is in use.")]
    turn2_response = [MockChunk(turn2_parts)]
    
    # Mocking the chat session
    chat_session = AsyncMock()
    chat_session.send_message_async.side_effect = [
        AsyncMock(__aiter__=lambda x: iter(turn1_response)),
        AsyncMock(__aiter__=lambda x: iter(turn2_response))
    ]
    
    current_payload = "What's the CBOM for api.test.com?"
    full_reply = ""
    
    while True:
        print(f"Sending payload to Model: {current_payload}")
        response = await chat_session.send_message_async(current_payload, stream=True)
        
        tool_calls = []
        text_parts = []
        
        # Simulating async for chunk in response
        for chunk in turn1_response if current_payload == "What's the CBOM for api.test.com?" else turn2_response:
            for part in chunk.candidates[0].content.parts:
                if part.function_call:
                    tool_calls.append(part.function_call)
                elif part.text:
                    text_parts.append(part.text)
                    print(f"Yielding text: {part.text}")
        
        if not tool_calls:
            full_reply = "".join(text_parts)
            print(f"Final full reply: {full_reply}")
            break
            
        print(f"Detected {len(tool_calls)} tool calls")
        tool_responses = []
        tasks = []
        for fc in tool_calls:
            handler = tool_map.get(fc.name)
            if handler:
                print(f"Executing tool: {fc.name} with args {fc.args}")
                tasks.append(handler(db=db, **fc.args))
        
        if tasks:
            results = await asyncio.gather(*tasks)
            for fc, result in zip(tool_calls, results):
                tool_responses.append({"name": fc.name, "response": {"result": result}})
        
        current_payload = tool_responses
    
    print("Backtest Completed Successfully.")

if __name__ == "__main__":
    asyncio.run(backtest_loop())
