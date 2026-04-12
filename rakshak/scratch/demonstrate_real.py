import asyncio
import os
import google.generativeai as genai
from google.generativeai import types
from app.database import AsyncSessionLocal
from app.services.chat_tools import (
    get_domain_subdomain_inventory,
    get_subdomain_detailed_cbom,
    get_subdomain_remediation_guidance
)

# Using the provided key for demonstration
API_KEY = "AIzaSyACcVP7ll7jckMQrbWwK3goUK-_2u0A6lE"
genai.configure(api_key=API_KEY)

async def demonstrate_real_turn():
    print("Demonstrating Real Chat Turn with Gemini 3 Flash and Rakshak Database")
    
    model = genai.GenerativeModel(
        model_name="gemini-3-flash-preview",
        system_instruction="You are Rakshak AI. Use tools to answer questions about cryptographic security.",
        tools=[
            get_domain_subdomain_inventory,
            get_subdomain_detailed_cbom,
            get_subdomain_remediation_guidance
        ]
    )
    
    chat_session = model.start_chat(enable_automatic_function_calling=False)
    
    # User Query
    user_query = "What is the PQC status and algorithms for test.openquantumsafe.org?"
    print(f"\nUser: {user_query}")
    
    current_payload = user_query
    
    while True:
        response = await chat_session.send_message_async(current_payload, stream=True)
        
        tool_calls = []
        text_parts = []
        
        async for chunk in response:
            for part in chunk.candidates[0].content.parts:
                if part.function_call:
                    tool_calls.append(part.function_call)
                elif part.text:
                    text_parts.append(part.text)
                    print(f"Assistant: {part.text}")
        
        if not tool_calls:
            break
        
        print(f"-- Tool turns: {len(tool_calls)} calls detected --")
        tool_responses = []
        tool_map = {
            "get_domain_subdomain_inventory": get_domain_subdomain_inventory,
            "get_subdomain_detailed_cbom": get_subdomain_detailed_cbom,
            "get_subdomain_remediation_guidance": get_subdomain_remediation_guidance
        }
        
        for fc in tool_calls:
            handler = tool_map.get(fc.name)
            if handler:
                print(f"Executing {fc.name} for {fc.args}...")
                result = await handler(**dict(fc.args))
                tool_responses.append({
                    "function_response": {
                        "name": fc.name,
                        "response": {"result": result},
                        "id": fc.id
                    }
                })
        
        current_payload = tool_responses

    print("\nDemonstration complete.")

if __name__ == "__main__":
    asyncio.run(demonstrate_real_turn())
