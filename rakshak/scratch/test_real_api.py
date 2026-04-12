import asyncio
import os
import google.generativeai as genai
from google.generativeai import types

# KEY: AIzaSyACcVP7ll7jckMQrbWwK3goUK-_2u0A6lE
API_KEY = "AIzaSyACcVP7ll7jckMQrbWwK3goUK-_2u0A6lE"
genai.configure(api_key=API_KEY)

# Mock tools
def get_weather(location: str):
    """Gets the weather for a location.
    Args:
        location: City and state, e.g. San Francisco, CA
    """
    return {"location": location, "weather": "sunny"}

async def test_manual_loop():
    print("Starting REAL API Test: Manual Tool Execution Loop")
    model = genai.GenerativeModel(
        model_name="gemini-1.5-flash",
        tools=[get_weather]
    )
    
    chat = model.start_chat(enable_automatic_function_calling=False)
    
    current_payload = "What is the weather in New York?"
    
    while True:
        print(f"\n--- Sending to Gemini: {current_payload}")
        try:
            response = await chat.send_message_async(current_payload, stream=True)
            
            tool_calls = []
            text_parts = []
            
            async for chunk in response:
                print(f"Chunk received...")
                for part in chunk.candidates[0].content.parts:
                    if part.function_call:
                        print(f"  Tool Call Found: {part.function_call.name}")
                        tool_calls.append(part.function_call)
                    elif part.text:
                        print(f"  Text Found: {part.text}")
                        text_parts.append(part.text)
            
            if not tool_calls:
                print("\nFINAL RESPONSE RECEIVED")
                print("".join(text_parts))
                break
            
            # Execute tools
            tool_responses = []
            for fc in tool_calls:
                # Simulating tool execution
                result = get_weather(**fc.args)
                tool_responses.append(types.Part.from_function_response(
                    name=fc.name,
                    response={"result": result}
                ))
            
            current_payload = tool_responses
        except Exception as e:
            print(f"ERROR: {e}")
            break

if __name__ == "__main__":
    asyncio.run(test_manual_loop())
