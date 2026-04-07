"""Chat router — User chatbot for asset-specific queries."""
import json
import os
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
from dotenv import load_dotenv
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, delete
from app.database import get_db
from app.models.chat import ChatSession, ChatMessage, ChatSessionStatus
from app.models.user import User
from app.models.asset import Asset
from app.models.cbom import CBOMSnapshot
from app.dependencies import require_any_role
from app.services.audit_service import log_event

router = APIRouter(prefix="/api/chat", tags=["chat"])

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = "gemini-3-flash-preview"


class StartChatRequest(BaseModel):
    asset_id: int
    title: Optional[str] = None


class SendMessageRequest(BaseModel):
    message: str


class ChatSessionResponse(BaseModel):
    id: int
    asset_id: int
    asset_name: str
    title: str
    status: str
    created_at: str
    updated_at: str
    message_count: int


class ChatMessageResponse(BaseModel):
    id: int
    role: str
    content: str
    created_at: str


@router.post("/sessions/start")
async def start_chat_session(
    req: StartChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """Start a new chat session for a specific asset."""
    # Verify asset exists
    result = await db.execute(select(Asset).where(Asset.id == req.asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Create session
    session = ChatSession(
        user_id=current_user.id,
        asset_id=req.asset_id,
        title=req.title or f"Chat with {asset.name or asset.url}",
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)

    await log_event(db, "chat_session_started", f"Session #{session.id} for asset {asset.name}", current_user.id, current_user.username)

    return {
        "session_id": session.id,
        "asset_id": session.asset_id,
        "asset_name": asset.name or asset.url,
        "title": session.title,
        "message": "Chat session started. Ask me anything about this asset!",
    }


@router.get("/sessions")
async def list_chat_sessions(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """List all chat sessions for the current user."""
    result = await db.execute(
        select(ChatSession, Asset).join(Asset).where(ChatSession.user_id == current_user.id).order_by(desc(ChatSession.updated_at))
    )
    rows = result.all()

    sessions = []
    for session, asset in rows:
        sessions.append({
            "id": session.id,
            "asset_id": session.asset_id,
            "asset_name": asset.name or asset.url,
            "title": session.title,
            "status": session.status,
            "created_at": session.created_at.isoformat(),
            "updated_at": session.updated_at.isoformat(),
            "message_count": session.message_count,
        })

    return sessions


@router.delete("/sessions/{session_id}")
async def delete_chat_session(
    session_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """Delete a chat session and all its messages."""
    result = await db.execute(select(ChatSession).where(ChatSession.id == session_id))
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    await db.execute(delete(ChatMessage).where(ChatMessage.session_id == session_id))
    await db.execute(delete(ChatSession).where(ChatSession.id == session_id))
    await db.commit()

    return {"status": "success", "message": "Session and all messages deleted"}

    return {"message": "Session archived successfully"}


@router.get("/sessions/{session_id}/messages")
async def get_session_messages(
    session_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """Get all messages in a chat session."""
    result = await db.execute(select(ChatSession).where(ChatSession.id == session_id))
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    # Get asset details for context
    asset_result = await db.execute(select(Asset).where(Asset.id == session.asset_id))
    asset = asset_result.scalar_one_or_none()

    # Get messages
    msg_result = await db.execute(select(ChatMessage).where(ChatMessage.session_id == session_id).order_by(ChatMessage.created_at))
    messages = msg_result.scalars().all()

    return {
        "session_id": session.id,
        "asset_id": asset.id,
        "asset_name": asset.name or asset.url,
        "asset_url": asset.url,
        "messages": [
            {
                "id": m.id,
                "role": m.role,
                "content": m.content,
                "created_at": m.created_at.isoformat(),
            }
            for m in messages
        ],
    }


@router.post("/sessions/{session_id}/message")
async def send_chat_message(
    session_id: int,
    req: SendMessageRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """Send a message to the chatbot and get a streamed response."""
    # Verify session
    result = await db.execute(select(ChatSession).where(ChatSession.id == session_id))
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    # Store user message
    user_msg = ChatMessage(
        session_id=session_id,
        user_id=current_user.id,
        role="user",
        content=req.message,
    )
    db.add(user_msg)
    session.message_count += 1
    session.updated_at = datetime.utcnow()
    await db.commit()

    asset_result = await db.execute(select(Asset).where(Asset.id == session.asset_id))
    asset = asset_result.scalar_one_or_none()

    # Get last 15-20 messages for context
    msg_result = await db.execute(
        select(ChatMessage).where(ChatMessage.session_id == session_id).order_by(desc(ChatMessage.created_at)).limit(40)
    )
    recent_messages = list(reversed(msg_result.scalars().all()))

    # Get CBOM data for system prompt
    cbom_result = await db.execute(
        select(CBOMSnapshot).where(CBOMSnapshot.target_url == asset.url).order_by(desc(CBOMSnapshot.created_at)).limit(1)
    )
    cbom = cbom_result.scalar_one_or_none()

    system_prompt = await _build_system_prompt(asset, cbom)

    messages_for_api = []
    for msg in recent_messages:
        messages_for_api.append({
            "role": msg.role,
            "parts": [{"text": msg.content}]
        })

    import google.generativeai as genai
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel(
        model_name=GEMINI_MODEL,
        system_instruction=system_prompt,
        generation_config={
            "temperature": 0.7,
            "top_p": 0.95,
            "max_output_tokens": 2048,
        }
    )

    async def generate_response():
        try:
            from app.database import AsyncSessionLocal
            response = await model.generate_content_async(messages_for_api, stream=True)
            full_reply = ""
            async for chunk in response:
                if chunk.text:
                    full_reply += chunk.text
                    yield chunk.text

            # After yielding all chunks, store assistant response in a new DB session
            async with AsyncSessionLocal() as task_db:
                task_sess = await task_db.execute(select(ChatSession).where(ChatSession.id == session_id))
                tsession = task_sess.scalar_one()
                assistant_msg = ChatMessage(
                    session_id=session_id,
                    user_id=current_user.id,
                    role="assistant",
                    content=full_reply,
                )
                task_db.add(assistant_msg)
                tsession.message_count += 1
                await task_db.commit()

        except Exception as e:
            error_msg = f"\n\nI encountered an error while processing your request: {str(e)}. Please try again."
            yield error_msg

    return StreamingResponse(generate_response(), media_type="text/plain")


async def _generate_chat_response(*args, **kwargs):
    pass


async def _build_system_prompt(asset: Asset, cbom: CBOMSnapshot) -> str:
    """Build comprehensive system prompt with asset details and CBOM."""
    cbom_details = ""
    
    if cbom:
        # Parse CBOM data
        algorithms = json.loads(cbom.algorithms_json or "[]")
        protocols = json.loads(cbom.protocols_json or "[]")
        keys = json.loads(cbom.keys_json or "[]")
        certificates = json.loads(cbom.certificates_json or "[]")

        cbom_details = f"""
## Cryptographic Bill of Materials (CBOM)

### Algorithms Used:
{_format_list(algorithms, 'name')}

### Connection Protocols:
{_format_list(protocols, 'version')}

### Cryptographic Keys:
{_format_list(keys, 'name')}

### Certificates:
{_format_list(certificates, 'issuer_name')}

### Current PQC Status: {cbom.pqc_label or 'Unknown'}
"""

    system_prompt = f"""You are Rakshak AI, a specialized cybersecurity assistant focused on Post-Quantum Cryptography (PQC) and TLS security posture.

## Asset Information
- **Name:** {asset.name or 'Unknown'}
- **URL:** {asset.url}
- **Asset Type:** {asset.asset_type or 'Unknown'}
- **Risk Level:** {asset.risk_level.value if asset.risk_level else 'Unknown'}
- **TLS Version:** {asset.tls_version or 'Unknown'}
- **Key Length:** {asset.key_length or 'Unknown'} bits

{cbom_details}

## Your Role
1. **Answer asset-specific questions:** You can only answer questions related to the selected asset's security posture, cryptographic configuration, and PQC readiness.
2. **Provide remediation guidance:** Help users understand how to fix security issues and implement PQC migration playbooks step-by-step.
3. **Ask clarifying questions:** If you need more information about their platform, infrastructure, or implementation constraints, ask detailed follow-up questions.
4. **Scope enforcement:** If a user asks about a different asset or topic outside your scope, politely redirect them by saying: "I can only answer queries regarding the selected asset '{asset.name or asset.url}' in this session. Please start a new session to ask queries related to another asset or topic."

## Response Guidelines
- Be technical but clear
- Provide step-by-step implementation guidance
- Reference NIST FIPS standards when relevant
- Suggest practical mitigations based on the asset's current posture
- Ask counter-questions to understand the user's environment better
- Be conversational and helpful

**Remember:** Your scope is strictly this asset. Do not discuss other assets or unrelated topics."""

    return system_prompt


def _format_list(items: list, key: str) -> str:
    """Format a list of items for the system prompt."""
    if not items:
        return "- None"
    return "\n".join([f"- {item.get(key, str(item))}" for item in items[:10]])  # Limit to 10 items
