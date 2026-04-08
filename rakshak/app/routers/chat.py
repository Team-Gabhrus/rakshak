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
from app.models.asset import Asset, AssetDiscovery, DiscoveryCategory
from app.models.cbom import CBOMSnapshot
from app.dependencies import require_any_role
from app.services.audit_service import log_event

router = APIRouter(prefix="/api/chat", tags=["chat"])

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = "gemini-3-flash-preview"


class StartChatRequest(BaseModel):
    asset_id: Optional[int] = None
    domain: Optional[str] = None
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
    """Start a new chat session for a specific asset or domain."""
    if not req.asset_id and not req.domain:
        raise HTTPException(status_code=400, detail="Please select an asset or a domain")

    asset = None
    if req.domain and not req.asset_id:
        # Domain-only session: find or create a placeholder asset for this domain
        result = await db.execute(select(Asset).where(Asset.url == req.domain))
        asset = result.scalar_one_or_none()
        if not asset:
            asset = Asset(name=f"Domain: {req.domain}", url=req.domain)
            db.add(asset)
            await db.commit()
            await db.refresh(asset)
    elif req.asset_id:
        result = await db.execute(select(Asset).where(Asset.id == req.asset_id))
        asset = result.scalar_one_or_none()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")

    # Fetch domain context if domain provided
    domain_context_json = None
    if req.domain:
        try:
            domain_data = await _fetch_domain_context(req.domain, db)
            domain_context_json = json.dumps(domain_data)
        except Exception:
            domain_context_json = None

    # Build title
    if req.title:
        title = req.title
    elif req.domain:
        title = f"Chat about {req.domain}"
    elif asset:
        title = f"Chat with {asset.name or asset.url}"
    else:
        title = "Chat session"

    # Create session
    try:
        session = ChatSession(
            user_id=current_user.id,
            asset_id=asset.id,
            title=title,
            domain_context_json=domain_context_json,
        )
        # Set domain if the column exists
        try:
            session.domain = req.domain
        except Exception:
            pass
        db.add(session)
        await db.commit()
        await db.refresh(session)
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create session: {str(e)}")

    ctx_name = req.domain or (asset.name if asset else "unknown")
    await log_event(db, "chat_session_started", f"Session #{session.id} for {ctx_name}", current_user.id, current_user.username)

    return {
        "session_id": session.id,
        "asset_id": session.asset_id,
        "domain": req.domain,
        "title": session.title,
        "message": "Chat session started. Ask me anything!",
    }


@router.get("/sessions")
async def list_chat_sessions(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """List all chat sessions for the current user."""
    # Use outerjoin since domain-only sessions have no asset_id
    result = await db.execute(
        select(ChatSession, Asset).outerjoin(Asset, ChatSession.asset_id == Asset.id).where(ChatSession.user_id == current_user.id).order_by(desc(ChatSession.updated_at))
    )
    rows = result.all()

    sessions = []
    for session, asset in rows:
        # Detect domain session from domain_context_json or title
        is_domain = bool(session.domain_context_json) or (session.title and session.title.startswith("Chat about "))
        if asset:
            ctx_name = asset.name or asset.url
        else:
            ctx_name = "Unknown"
        
        domain_val = None
        try:
            domain_val = session.domain
        except Exception:
            pass
        
        sessions.append({
            "id": session.id,
            "asset_id": session.asset_id,
            "asset_name": ctx_name,
            "domain": domain_val,
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
    asset = None
    if session.asset_id:
        asset_result = await db.execute(select(Asset).where(Asset.id == session.asset_id))
        asset = asset_result.scalar_one_or_none()

    # Detect domain
    domain_val = None
    try:
        domain_val = session.domain
    except Exception:
        pass

    # Get messages
    msg_result = await db.execute(select(ChatMessage).where(ChatMessage.session_id == session_id).order_by(ChatMessage.created_at))
    messages = msg_result.scalars().all()

    return {
        "session_id": session.id,
        "asset_id": session.asset_id,
        "asset_name": (asset.name or asset.url) if asset else "Session",
        "asset_url": asset.url if asset else "",
        "domain": domain_val,
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

    asset = None
    cbom = None
    if session.asset_id:
        asset_result = await db.execute(select(Asset).where(Asset.id == session.asset_id))
        asset = asset_result.scalar_one_or_none()

    # Get last 15-20 messages for context
    msg_result = await db.execute(
        select(ChatMessage).where(ChatMessage.session_id == session_id).order_by(desc(ChatMessage.created_at)).limit(40)
    )
    recent_messages = list(reversed(msg_result.scalars().all()))

    # Detect if this is a domain session
    is_domain_session = bool(session.domain_context_json)

    # Build system prompt based on session type
    if is_domain_session:
        # Extract domain from context or title
        domain_name = "unknown"
        if session.domain_context_json:
            try:
                ctx = json.loads(session.domain_context_json)
                domain_name = ctx.get("domain", "unknown")
            except Exception:
                pass
        try:
            if session.domain:
                domain_name = session.domain
        except Exception:
            pass
        system_prompt = _build_domain_system_prompt(domain_name)
    elif asset:
        # Get CBOM data for system prompt
        cbom_result = await db.execute(
            select(CBOMSnapshot).where(CBOMSnapshot.target_url == asset.url).order_by(desc(CBOMSnapshot.created_at)).limit(1)
        )
        cbom = cbom_result.scalar_one_or_none()
        system_prompt = await _build_system_prompt(asset, cbom)
    else:
        system_prompt = "You are Rakshak AI, a cybersecurity assistant. Answer questions about security and PQC."

    # Inject domain context if available
    if session.domain_context_json:
        try:
            domain_ctx = json.loads(session.domain_context_json)
            system_prompt += _format_domain_context(domain_ctx)
        except Exception:
            pass

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


def _build_domain_system_prompt(domain: str) -> str:
    """Build system prompt for domain-only sessions (no specific asset)."""
    return f"""You are Rakshak AI, a specialized cybersecurity assistant focused on Post-Quantum Cryptography (PQC) and TLS security posture.

## Domain Context
- **Root Domain:** {domain}
- This session is focused on the domain "{domain}" and all its discovered subdomains.

## Your Role
1. **Answer domain-specific questions:** Help users understand the attack surface, subdomain exposure, DNS health, and infrastructure layout of "{domain}".
2. **Subdomain analysis:** Use the provided subdomain data (hostnames, DNS status, IPs) to answer questions about live/dead subdomains, common patterns, potential shadow IT, and exposed services.
3. **Provide remediation guidance:** Help users understand how to reduce their attack surface, consolidate subdomains, and improve DNS hygiene.
4. **PQC & TLS guidance:** When asked, advise on how to migrate the domain's infrastructure to post-quantum cryptography.
5. **Scope enforcement:** If a user asks about unrelated topics, politely redirect them by saying: "I can only answer queries about the domain '{domain}' and its subdomains in this session."

## Response Guidelines
- Be technical but clear
- Reference the subdomain data provided to you when answering
- Highlight any interesting patterns (e.g., many dead subdomains, cloud provider concentration)
- Be conversational and helpful

**Remember:** Your scope is strictly this domain and its subdomains."""


def _format_list(items: list, key: str) -> str:
    """Format a list of items for the system prompt."""
    if not items:
        return "- None"
    return "\n".join([f"- {item.get(key, str(item))}" for item in items[:10]])  # Limit to 10 items


async def _fetch_domain_context(domain: str, db: AsyncSession) -> dict:
    """Fetch subdomain data and CBOM details for a root domain."""
    result = await db.execute(
        select(AssetDiscovery).where(
            AssetDiscovery.category == DiscoveryCategory.domain
        )
    )
    discoveries = result.scalars().all()

    subdomains = []
    live_count = 0
    dead_count = 0
    for d in discoveries:
        meta = json.loads(d.metadata_json) if d.metadata_json else {}
        root = meta.get("root_domain", "")
        # Match discoveries belonging to this root domain, or the domain itself
        if root == domain or d.value == domain or d.value.endswith("." + domain):
            dns_status = meta.get("dns_status", "unknown")
            subdomains.append({
                "hostname": d.value,
                "dns_status": dns_status,
                "ips": meta.get("ips", []),
                "status": d.status.value if d.status else "new",
            })
            if dns_status == "live":
                live_count += 1
            elif dns_status == "dead":
                dead_count += 1

    # Fetch CBOM data for all these hostnames
    hostnames = [s["hostname"] for s in subdomains]
    asset_result = await db.execute(
        select(Asset, CBOMSnapshot)
        .outerjoin(CBOMSnapshot, CBOMSnapshot.asset_id == Asset.id)
        .where(Asset.url.in_(hostnames))
    )
    asset_data = asset_result.all()
    cbom_map = {}
    for a, c in asset_data:
        if c:
            cbom_map[a.url] = {
                "pqc_label": c.pqc_label,
                "cbom_timestamp": c.created_at.isoformat() if c.created_at else None,
                # Include counts rather than raw JSON to preserve token window
                "algorithms_count": len(json.loads(c.algorithms_json or "[]")),
                "protocols_count": len(json.loads(c.protocols_json or "[]")),
                "certificates_count": len(json.loads(c.certificates_json or "[]")),
            }
        else:
            cbom_map[a.url] = {"pqc_label": "Unknown", "algorithms_count": 0, "protocols_count": 0, "certificates_count": 0}

    # Attach CBOM data to subdomains
    for s in subdomains:
        s["cbom"] = cbom_map.get(s["hostname"])

    return {
        "root_domain": domain,
        "total_subdomains": len(subdomains),
        "live": live_count,
        "dead": dead_count,
        "subdomains": subdomains,
    }


def _format_domain_context(ctx: dict) -> str:
    """Format domain context for injection into the system prompt."""
    if not ctx or not ctx.get("subdomains"):
        return ""
    lines = [f"\n\n## Domain Intelligence: {ctx['root_domain']}"]
    lines.append(f"- **Total Subdomains:** {ctx['total_subdomains']}")
    lines.append(f"- **Live:** {ctx['live']}")
    lines.append(f"- **Dead (cert ghosts):** {ctx['dead']}")
    lines.append("\n### Subdomain Details and CBOM Context:")
    for s in ctx["subdomains"][:30]:  # cap at 30
        ips = ", ".join(s.get("ips", [])) if s.get("ips") else "no IPs"
        cbom_info = ""
        if s.get("cbom"):
            c = s["cbom"]
            cbom_info = f" | PQC: {c['pqc_label']} | Algos: {c['algorithms_count']} | Protos: {c['protocols_count']} | Certs: {c['certificates_count']}"
        lines.append(f"- {s['hostname']} — {s['dns_status']} ({ips}) [{s['status']}]{cbom_info}")
    lines.append("\nYou can use this subdomain data to answer questions about the domain's attack surface, exposure, and infrastructure.")
    return "\n".join(lines)


@router.get("/domain-context")
async def get_domain_context(
    domain: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """Get subdomain context for a root domain."""
    return await _fetch_domain_context(domain, db)


@router.get("/domains")
async def list_available_domains(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_role),
):
    """List unique root domains from AssetDiscovery for the domain selector."""
    result = await db.execute(
        select(AssetDiscovery).where(
            AssetDiscovery.category == DiscoveryCategory.domain
        )
    )
    discoveries = result.scalars().all()

    roots: dict[str, int] = {}
    for d in discoveries:
        meta = json.loads(d.metadata_json) if d.metadata_json else {}
        root = meta.get("root_domain", "")
        if root:
            roots[root] = roots.get(root, 0) + 1

    return [{"domain": k, "subdomain_count": v} for k, v in sorted(roots.items())]
