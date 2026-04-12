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
from app.services.chat_tools import (
    get_domain_subdomain_inventory,
    get_subdomain_detailed_cbom,
    get_subdomain_remediation_guidance
)
from app.services.domain_service import (
    get_assets_for_domains,
    get_latest_cbom_by_target,
    get_latest_scan_results_by_target,
    list_domain_inventory,
)
import re

router = APIRouter(prefix="/api/chat", tags=["chat"])

import google.generativeai as genai
from google.generativeai import types
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = "gemini-3-flash-preview"
genai.configure(api_key=GEMINI_API_KEY)


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


async def _refresh_domain_session_context(session: ChatSession, db: AsyncSession) -> dict | None:
    """Refresh persisted domain context so existing sessions see newly scanned targets."""
    domain_value = None
    try:
        domain_value = session.domain
    except Exception:
        domain_value = None

    if not domain_value:
        return None

    domain_data = await _fetch_domain_context(domain_value, db)
    session.domain_context_json = json.dumps(domain_data)

    if domain_data.get("targets"):
        target_urls = [target.get("url") for target in domain_data["targets"] if target.get("url")]
        if target_urls:
            preferred_url = next(
                (target["url"] for target in domain_data["targets"] if target.get("is_live")),
                target_urls[0],
            )
            asset_result = await db.execute(select(Asset).where(Asset.url == preferred_url))
            anchor_asset = asset_result.scalar_one_or_none()
            if anchor_asset:
                session.asset_id = anchor_asset.id

    return domain_data


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
    if req.asset_id:
        result = await db.execute(select(Asset).where(Asset.id == req.asset_id))
        asset = result.scalar_one_or_none()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
    elif req.domain:
        domain_assets = await get_assets_for_domains(db, [req.domain])
        if domain_assets:
            # Anchor domain sessions to one real asset so older deployed schemas
            # that still expect a non-null asset_id continue to work safely.
            asset = sorted(
                domain_assets,
                key=lambda item: (
                    item.last_scan or item.created_at,
                    item.url or "",
                ),
                reverse=True,
            )[0]

    # Fetch domain context if domain provided
    domain_context_json = None
    if req.domain:
        try:
            domain_data = await _fetch_domain_context(req.domain, db)
            domain_context_json = json.dumps(domain_data)
            if not asset and domain_data.get("targets"):
                first_target_url = domain_data["targets"][0].get("url")
                if first_target_url:
                    asset_result = await db.execute(select(Asset).where(Asset.url == first_target_url))
                    asset = asset_result.scalar_one_or_none()
        except Exception:
            domain_context_json = None

    if req.domain and not asset:
        raise HTTPException(status_code=400, detail="Selected domain has no inventory-backed targets available for chat.")

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
            asset_id=asset.id if asset else None,
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
        domain_val = None
        try:
            domain_val = session.domain
        except Exception:
            pass
        if domain_val:
            ctx_name = domain_val
        elif asset:
            ctx_name = asset.name or asset.url
        else:
            ctx_name = "Unknown"
        
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

    if domain_val:
        await _refresh_domain_session_context(session, db)
        await db.commit()

    # Get messages
    msg_result = await db.execute(select(ChatMessage).where(ChatMessage.session_id == session_id).order_by(ChatMessage.created_at))
    messages = msg_result.scalars().all()

    if session.asset_id:
        asset_result = await db.execute(select(Asset).where(Asset.id == session.asset_id))
        asset = asset_result.scalar_one_or_none()

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
    if getattr(session, "domain", None):
        domain_ctx = await _refresh_domain_session_context(session, db)
        await db.commit()
        is_domain_session = True
    else:
        domain_ctx = None

    # Build system prompt based on session type
    if is_domain_session:
        # Extract domain from context or title
        domain_name = "unknown"
        if domain_ctx:
            domain_name = domain_ctx.get("root_domain", "unknown")
        elif session.domain_context_json:
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

    # Inject domain context if available (High-level only)
    if domain_ctx:
        system_prompt += _format_domain_context(domain_ctx)
    elif session.domain_context_json:
        try:
            stored_domain_ctx = json.loads(session.domain_context_json)
            system_prompt += _format_domain_context(stored_domain_ctx)
        except Exception:
            pass

    # Transform history into the format required for start_chat
    history = []
    if recent_messages:
        # The last message is the one we just added to DB, but we pass it as 'content' to send_message
        # So history should be all BUT the last one.
        for msg in recent_messages[:-1]:
            history.append({
                "role": "model" if msg.role == "assistant" else "user",
                "parts": [msg.content]
            })

    model = genai.GenerativeModel(
        model_name=GEMINI_MODEL,
        system_instruction=system_prompt,
        tools=[
            get_domain_subdomain_inventory,
            get_subdomain_detailed_cbom,
            get_subdomain_remediation_guidance
        ],
        generation_config={
            "temperature": 0.7,
            "top_p": 0.95,
            "max_output_tokens": 2048,
        }
    )

    async def generate_response():
        try:
            import asyncio
            from app.database import AsyncSessionLocal
            
            # Start chat session with manual function calling
            chat_session = model.start_chat(history=history, enable_automatic_function_calling=False)
            
            # Send the initial user message
            current_payload = req.message
            full_reply = ""
            
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
                            yield part.text
                
                if not tool_calls:
                    full_reply = "".join(text_parts)
                    break
                
                # Turn with tool calls
                tool_map = {
                    "get_domain_subdomain_inventory": get_domain_subdomain_inventory,
                    "get_subdomain_detailed_cbom": get_subdomain_detailed_cbom,
                    "get_subdomain_remediation_guidance": get_subdomain_remediation_guidance
                }
                
                tool_responses = []
                tasks = []
                
                for fc in tool_calls:
                    handler = tool_map.get(fc.name)
                    if handler:
                        args = dict(fc.args)
                        tasks.append((fc.name, fc.id, handler(db=db, **args)))
                
                if tasks:
                    # Execute all tools in parallel
                    # Each task is (name, id, coroutine)
                    coroutines = [t[2] for t in tasks]
                    results = await asyncio.gather(*coroutines)
                    
                    for i, result in enumerate(results):
                        name = tasks[i][0]
                        fc_id = tasks[i][1]
                        tool_responses.append({
                            "function_response": {
                                "name": name,
                                "response": {"result": result},
                                "id": fc_id
                            }
                        })
                
                # Send tool results back to the model for the next turn
                current_payload = tool_responses

            # Store assistant response in a new DB session
            async with AsyncSessionLocal() as task_db:
                assistant_msg = ChatMessage(
                    session_id=session_id,
                    user_id=current_user.id,
                    role="assistant",
                    content=full_reply,
                )
                task_db.add(assistant_msg)
                
                # Update message count (user + assistant)
                task_sess = await task_db.execute(select(ChatSession).where(ChatSession.id == session_id))
                tsession = task_sess.scalar_one()
                tsession.message_count += 2
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

## PQC Classification Definitions
Rakshak classifies every scanned target into one of the following tiers:

- **Partially Quantum Safe:** The target uses a hybrid key-exchange algorithm (e.g., X25519+MLKEM768) or supports a NIST-approved post-quantum algorithm such as ML-KEM or ML-DSA alongside classical algorithms. It retains backward compatibility with older TLS versions (not limited to TLS 1.3 only), and its certificates are still signed with classical algorithms like RSA or ECDSA. This posture provides protection against Harvest-Now-Decrypt-Later (HNDL) attacks for key exchange but does not yet achieve full quantum safety.
- **PQC-Ready:** All negotiated key-exchange and cipher algorithms are quantum-safe (e.g., ML-KEM, ML-DSA only), and only TLS 1.3 is permitted — no fallback to older protocol versions. However, the server certificates are still signed using classical algorithms (RSA / ECDSA), so certificate-level authentication is not yet quantum-resistant. This tier is significantly more secure than Partially Quantum Safe but not fully airtight.
- **Fully Quantum Safe:** The target is fully quantum-resistant end-to-end. All key-exchange, cipher, and signature algorithms are quantum-safe (ML-KEM, ML-DSA, SLH-DSA, etc.), only TLS 1.3 is used, and the certificates themselves are signed with quantum-safe algorithms. Even if a fully capable cryptographically relevant quantum computer (CRQC) existed today, this target would remain secure.

Use these definitions whenever discussing a target's PQC posture, risk level, or migration roadmap.

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
- This session is focused on the domain "{domain}" and all inventory-backed targets and discovered dead hosts under it.

## Your Role
1. **Answer domain-specific questions:** Help users understand the attack surface, target coverage, DNS health, scan coverage, and infrastructure layout of "{domain}".
2. **Domain analysis:** Use the provided target inventory, scan results, CBOM summaries, recommendations, and playbook context to answer questions about live targets, dead hosts, PQC posture, and exposed services.
3. **Provide remediation guidance:** Help users understand how to reduce their attack surface, consolidate subdomains, close dead entries, and improve DNS hygiene.
4. **PQC & TLS guidance:** When asked, advise on how to migrate the domain's infrastructure to post-quantum cryptography based on the actual scanned targets in this domain.
5. **Scope enforcement:** If a user asks about unrelated topics, politely redirect them by saying: "I can only answer queries about the domain '{domain}' and its subdomains in this session."

## PQC Classification Definitions
Rakshak classifies every scanned target into one of the following tiers:

- **Partially Quantum Safe:** The target uses a hybrid key-exchange algorithm (e.g., X25519+MLKEM768) or supports a NIST-approved post-quantum algorithm such as ML-KEM or ML-DSA alongside classical algorithms. It retains backward compatibility with older TLS versions (not limited to TLS 1.3 only), and its certificates are still signed with classical algorithms like RSA or ECDSA. This posture provides protection against Harvest-Now-Decrypt-Later (HNDL) attacks for key exchange but does not yet achieve full quantum safety.
- **PQC-Ready:** All negotiated key-exchange and cipher algorithms are quantum-safe (e.g., ML-KEM, ML-DSA only), and only TLS 1.3 is permitted — no fallback to older protocol versions. However, the server certificates are still signed using classical algorithms (RSA / ECDSA), so certificate-level authentication is not yet quantum-resistant. This tier is significantly more secure than Partially Quantum Safe but not fully airtight.
- **Fully Quantum Safe:** The target is fully quantum-resistant end-to-end. All key-exchange, cipher, and signature algorithms are quantum-safe (ML-KEM, ML-DSA, SLH-DSA, etc.), only TLS 1.3 is used, and the certificates themselves are signed with quantum-safe algorithms. Even if a fully capable cryptographically relevant quantum computer (CRQC) existed today, this target would remain secure.

Use these definitions when discussing any target's PQC posture, risk level, or migration roadmap.

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


def get_root_domain(hostname: str) -> str:
    """Extract root domain from a hostname, handling two-part TLDs."""
    if not hostname: return ""
    # Remove protocol if present and ignore paths
    h = hostname.lower().split("://")[-1].split("/")[0]
    # Remove any port
    h = h.split(":")[0]
    parts = h.split(".")
    if len(parts) <= 2:
        return h
    
    # Check for two-part TLDs (co.uk, com.au, etc)
    tld_suffix = ".".join(parts[-2:])
    is_two_part = re.match(r"^(co|com|gov|org|edu|ac|bank|net|res|mod)\.[a-z]{2,3}$", tld_suffix)
    
    if is_two_part:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


async def _fetch_domain_context(domain: str, db: AsyncSession) -> dict:
    """Fetch asset-backed domain context with latest CBOM and scan details."""
    groups = await list_domain_inventory(db, [domain])
    group = groups[0] if groups else {"domain": domain, "targets": [], "dead_hosts": [], "target_count": 0}
    targets = group.get("targets", [])
    target_urls = [target["url"] for target in targets]
    latest_cbom = await get_latest_cbom_by_target(db, target_urls)
    latest_scans = await get_latest_scan_results_by_target(db, target_urls)

    enriched_targets = []
    scanned_count = 0
    live_count = 0
    for target in targets:
        scan_result = latest_scans.get(target["url"])
        cbom_snapshot = latest_cbom.get(target["url"])
        scanned = bool(scan_result)
        is_live = bool(scan_result and scan_result.status == "success")
        if scanned:
            scanned_count += 1
        if is_live:
            live_count += 1

        enriched_targets.append({
            "hostname": target["hostname"],
            "url": target["url"],
            "pqc_label": target["pqc_label"],
            "risk_level": target["risk_level"],
            "scanned": scanned,
            "scan_status": scan_result.status if scan_result else "not_scanned",
            "is_live": is_live,
            "tls_version": scan_result.tls_version if scan_result else target["tls_version"],
            "key_exchange": scan_result.key_exchange if scan_result else None,
            "authentication": scan_result.authentication if scan_result else None,
            "encryption": scan_result.encryption if scan_result else None,
            "hashing": scan_result.hashing if scan_result else None,
            "recommendations": json.loads(scan_result.recommendations_json or "[]")[:5] if scan_result and scan_result.recommendations_json else [],
            "playbook": json.loads(scan_result.playbook_json or "{}") if scan_result and scan_result.playbook_json else {},
            "cbom": {
                "pqc_label": cbom_snapshot.pqc_label if cbom_snapshot else None,
                "cbom_timestamp": cbom_snapshot.created_at.isoformat() if cbom_snapshot and cbom_snapshot.created_at else None,
                "algorithms_count": len(json.loads(cbom_snapshot.algorithms_json or "[]")) if cbom_snapshot else 0,
                "protocols_count": len(json.loads(cbom_snapshot.protocols_json or "[]")) if cbom_snapshot else 0,
                "certificates_count": len(json.loads(cbom_snapshot.certificates_json or "[]")) if cbom_snapshot else 0,
                "algorithms": json.loads(cbom_snapshot.algorithms_json or "[]")[:5] if cbom_snapshot else [],
                "protocols": json.loads(cbom_snapshot.protocols_json or "[]")[:5] if cbom_snapshot else [],
            },
        })

    return {
        "root_domain": group.get("domain", domain),
        "total_targets": len(enriched_targets),
        "scanned_targets": scanned_count,
        "live": live_count,
        "dead": len(group.get("dead_hosts", [])),
        "dead_hosts": group.get("dead_hosts", []),
        "targets": enriched_targets,
    }


def _format_domain_context(ctx: dict) -> str:
    """Format high-level domain context (stats only) for the system prompt."""
    if not ctx:
        return ""
    lines = [f"\n\n## Domain Intelligence: {ctx['root_domain']}"]
    lines.append(f"- **Total Targets:** {ctx['total_targets']}")
    lines.append(f"- **Scanned Targets:** {ctx['scanned_targets']}")
    lines.append(f"- **Live:** {ctx['live']}")
    lines.append(f"- **Dead Hosts:** {ctx['dead']}")
    
    lines.append("\n**Important:** You have access to tools to query specific subdomain details. Do not guess inventory. If the user asks about specific subdomains, their CBOM, or remediation steps, use the provided tools (`get_domain_subdomain_inventory`, `get_subdomain_detailed_cbom`, `get_subdomain_remediation_guidance`).")
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
    """List root domains from Asset Inventory, enriched with scan/dead-host counts."""
    groups = await list_domain_inventory(db)
    return [{
        "domain": group["domain"],
        "target_count": group["target_count"],
        "scanned_count": group["scanned_count"],
        "live_count": group["live_count"],
        "dead_count": group["dead_count"],
        "targets": [target["hostname"] for target in group["targets"]],
        "dead_hosts": group["dead_hosts"],
    } for group in groups]
