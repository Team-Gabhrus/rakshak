import asyncio
import google.generativeai as genai
from google.generativeai import types

# KEY: AIzaSyACcVP7ll7jckMQrbWwK3goUK-_2u0A6lE
API_KEY = "AIzaSyACcVP7ll7jckMQrbWwK3goUK-_2u0A6lE"
genai.configure(api_key=API_KEY)

def get_weather(location: str):
    """Gets the weather for a location.
    Args:
        location: City and state, e.g. San Francisco, CA
    """
    return {"location": location, "weather": "sunny"}

async def inspect_fc():
    print("Inspecting tool call structure for gemini-3-flash-preview")
    model = genai.GenerativeModel(
        model_name="gemini-3-flash-preview",
        tools=[get_weather]
    )
    
    chat = model.start_chat(enable_automatic_function_calling=False)
    
    try:
        response = await chat.send_message_async("How is the weather in London?", stream=True)
        
        async for chunk in response:
            for part in chunk.candidates[0].content.parts:
                if part.function_call:
                    fc = part.function_call
                    print(f"FC Name: {fc.name}")
                    print(f"FC Args: {type(fc.args)} {fc.args}")
                    print(f"FC ID: {getattr(fc, 'id', 'NO ID ATTR')}")
                    # Testing if Part.from_function_response accepts id
                    try:
                        p = types.Part.from_function_response(name=fc.name, response={"res": "ok"}, id=fc.id)
                        print("Part.from_function_response accepted id")
                    except Exception as e:
                        print(f"Part.from_function_response rejected id: {e}")
    except Exception as e:
        print(f"Outer Error: {e}")

if __name__ == "__main__":
    asyncio.run(inspect_fc())
