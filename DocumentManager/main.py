"""
SecureDocs - AI-Powered Secure Document Search Portal

FastAPI backend

Features:
- SQLite + SQLAlchemy persistent database
- Gemini AI document assistant
- Encrypted document storage
- Persistent Fernet encryption key
- Session authentication + CSRF protection
- Restricted document access
- PDF / DOCX / TXT / MD / CSV support
- Search and document retrieval
- Security headers
- CSP compatible with existing inline frontend JavaScript
- HSTS
- OPTIONS protection

Environment variables:
GEMINI_API_KEY
SECUREDOCS_FERNET_KEY
ADMIN_EMAIL
ADMIN_PASSWORD
COOKIE_SECURE
"""

import hashlib
import hmac
import io
import math
import os
import re
import secrets
import time
import uuid
import zipfile

from collections import Counter, defaultdict
from html import unescape
from pathlib import Path
from threading import Lock
from urllib.parse import quote

from cryptography.fernet import Fernet

from fastapi import (
    Depends,
    FastAPI,
    File,
    HTTPException,
    Request,
    UploadFile,
)

from fastapi.middleware.trustedhost import TrustedHostMiddleware

from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)

from pydantic import BaseModel, Field

from sqlalchemy import (
    Column,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    create_engine,
)

from sqlalchemy.orm import (
    declarative_base,
    relationship,
    sessionmaker,
    Session,
)

# Optional Gemini SDK
try:
    from google import genai
except ImportError:
    genai = None


# ============================================================
# CONFIG
# ============================================================

BASE = Path(__file__).resolve().parent

MAX_BYTES = 5 * 1024 * 1024
SESSION_TTL = 8 * 3600

EXTS = {
    ".txt",
    ".md",
    ".csv",
    ".pdf",
    ".docx",
}

SENSITIVE = re.compile(
    r"salar|payroll|confidential|secret|restricted",
    re.I,
)

SENSITIVE_NAME = re.compile(
    r"admin",
    re.I,
)

EMAIL = re.compile(
    r"^[^@\s]{1,64}@[^@\s]{1,120}\.[^@\s]{2,}$"
)

COOKIE_SECURE = os.getenv(
    "COOKIE_SECURE",
    "1",
).lower() not in {
    "0",
    "false",
    "no",
}


# ============================================================
# DATABASE
# ============================================================

DATABASE_URL = (
    "sqlite:///"
    + str(BASE / "securedocs.db")
)

engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False
    },
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    email = Column(
        String(150),
        unique=True,
        index=True,
        nullable=False,
    )

    pw = Column(
        String(500),
        nullable=False,
    )

    role = Column(
        String(30),
        default="employee",
        nullable=False,
    )

    queries = Column(
        Integer,
        default=0,
        nullable=False,
    )

    documents = relationship(
        "Document",
        back_populates="user",
        cascade="all, delete-orphan",
    )


class Document(Base):
    __tablename__ = "documents"

    id = Column(
        String(64),
        primary_key=True,
        index=True,
    )

    name = Column(
        String(100),
        nullable=False,
    )

    ext = Column(
        String(20),
        nullable=False,
    )

    owner = Column(
        String(150),
        ForeignKey("users.email"),
        nullable=False,
        index=True,
    )

    level = Column(
        Integer,
        default=1,
        nullable=False,
    )

    size = Column(
        Integer,
        nullable=False,
    )

    ts = Column(
        Float,
        nullable=False,
    )

    raw = Column(
        LargeBinary,
        nullable=False,
    )

    user = relationship(
        "User",
        back_populates="documents",
    )

    chunks = relationship(
        "DocumentChunk",
        back_populates="document",
        cascade="all, delete-orphan",
        order_by="DocumentChunk.position",
    )


class DocumentChunk(Base):
    __tablename__ = "document_chunks"

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    doc_id = Column(
        String(64),
        ForeignKey("documents.id"),
        nullable=False,
        index=True,
    )

    position = Column(
        Integer,
        nullable=False,
    )

    data = Column(
        LargeBinary,
        nullable=False,
    )

    document = relationship(
        "Document",
        back_populates="chunks",
    )


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


# ============================================================
# ENCRYPTION
# ============================================================

FERNET_KEY = os.getenv(
    "SECUREDOCS_FERNET_KEY"
)

if not FERNET_KEY:
    print(
        "\nWARNING: SECUREDOCS_FERNET_KEY is not set."
    )
    print(
        "A temporary encryption key will be generated."
    )
    print(
        "Set SECUREDOCS_FERNET_KEY in production "
        "so encrypted documents survive restarts.\n"
    )

    FERNET_KEY = Fernet.generate_key().decode()


try:
    FERNET = Fernet(
        FERNET_KEY.encode()
        if isinstance(FERNET_KEY, str)
        else FERNET_KEY
    )

except Exception:
    raise RuntimeError(
        "SECUREDOCS_FERNET_KEY is invalid. "
        "Generate a Fernet key and store it as a secret."
    )


def enc(data: bytes) -> bytes:
    return FERNET.encrypt(data)


def dec(data: bytes) -> bytes:
    return FERNET.decrypt(data)


# ============================================================
# LOCKS / RATE LIMITING
# ============================================================

LOCK = Lock()

FAILS = defaultdict(list)


# ============================================================
# PASSWORD HASHING
# ============================================================

def hash_pw(
    pw: str,
    salt=None,
):
    salt = (
        salt
        or secrets.token_bytes(16)
    )

    digest = hashlib.scrypt(
        pw.encode(),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
    )

    return (
        salt.hex()
        + "$"
        + digest.hex()
    )


def check_pw(
    pw: str,
    stored: str,
):
    try:
        salt, h = stored.split(
            "$",
            1,
        )

        calculated = hash_pw(
            pw,
            bytes.fromhex(salt),
        ).split(
            "$",
            1,
        )[1]

        return hmac.compare_digest(
            calculated,
            h,
        )

    except Exception:
        return False


# ============================================================
# ADMIN ACCOUNT
# ============================================================

ADMIN_EMAIL = os.getenv(
    "ADMIN_EMAIL",
    "admin@securedocs.com",
).strip().lower()

ADMIN_PW_ENV = os.getenv(
    "ADMIN_PASSWORD"
)

db = SessionLocal()

try:
    existing_admin = (
        db.query(User)
        .filter(
            User.email == ADMIN_EMAIL
        )
        .first()
    )

    if existing_admin is None:

        generated_admin_password = (
            ADMIN_PW_ENV
            or secrets.token_urlsafe(12)
        )

        admin = User(
            email=ADMIN_EMAIL,
            pw=hash_pw(
                generated_admin_password
            ),
            role="admin",
            queries=0,
        )

        db.add(admin)
        db.commit()

        print(
            "\n========================================"
        )
        print(
            " SecureDocs Admin Account"
        )
        print(
            "========================================"
        )
        print(
            f" Email: {ADMIN_EMAIL}"
        )
        print(
            f" Password: {generated_admin_password}"
        )
        print(
            "========================================\n"
        )

finally:
    db.close()


# ============================================================
# AUTHENTICATION
# ============================================================

SESSIONS = {}


def get_user(
    request: Request,
    db: Session,
):
    token = request.cookies.get("sid")

    if not token:
        return None

    session_hash = hashlib.sha256(
        token.encode()
    ).hexdigest()

    s = SESSIONS.get(session_hash)

    if not s:
        return None

    if s["exp"] < time.time():
        SESSIONS.pop(
            session_hash,
            None,
        )
        return None

    user = (
        db.query(User)
        .filter(
            User.email == s["email"]
        )
        .first()
    )

    if not user:
        SESSIONS.pop(
            session_hash,
            None,
        )
        return None

    return {
        "email": user.email,
        "role": user.role,
        "csrf": s["csrf"],
    }


def current_user(
    request: Request,
    db: Session = Depends(get_db),
):
    u = get_user(
        request,
        db,
    )

    if not u:
        raise HTTPException(
            401,
            "Please sign in.",
        )

    if request.method not in (
        "GET",
        "HEAD",
    ):
        csrf = request.headers.get(
            "x-csrf",
            "",
        )

        if not hmac.compare_digest(
            csrf,
            u["csrf"],
        ):
            raise HTTPException(
                403,
                "Security check failed. "
                "Reload the page.",
            )

    return u


# ============================================================
# TEXT PROCESSING
# ============================================================

STOP = set(
    """
    a an the and or of to in on for is are was were be it
    this that with as at by from what who how when which
    do does can i you we my our your about me tell
    """.split()
)


def tok(s):
    words = re.findall(
        r"[a-z0-9]+",
        s.lower(),
    )

    words = [
        w
        for w in words
        if w not in STOP
    ]

    return [
        (
            w[:-1]
            if len(w) > 3
            and w.endswith("s")
            else w
        )
        for w in words
    ]


# ============================================================
# FILE EXTRACTION
# ============================================================

def extract(
    ext,
    raw,
):
    try:

        if ext == ".pdf":

            if not raw.startswith(b"%PDF"):
                raise ValueError(
                    "Invalid PDF"
                )

            from pypdf import PdfReader

            reader = PdfReader(
                io.BytesIO(raw)
            )

            text = "\n".join(
                p.extract_text() or ""
                for p in reader.pages
            )

        elif ext == ".docx":

            with zipfile.ZipFile(
                io.BytesIO(raw)
            ) as z:

                info = z.getinfo(
                    "word/document.xml"
                )

                if info.file_size > 20_000_000:
                    raise ValueError(
                        "DOCX too large"
                    )

                xml = z.read(
                    "word/document.xml"
                ).decode(
                    "utf-8",
                    "replace",
                )

            xml = xml.replace(
                "</w:p>",
                "\n",
            )

            text = unescape(
                re.sub(
                    r"<[^>]+>",
                    "",
                    xml,
                )
            )

        else:

            text = raw.decode(
                "utf-8",
                "replace",
            )

    except ImportError:

        raise HTTPException(
            400,
            "PDF support needs pypdf.",
        )

    except HTTPException:
        raise

    except Exception:

        raise HTTPException(
            400,
            "Could not read this file. "
            "(Old .doc files: save as .docx first.)",
        )

    if not text.strip():

        raise HTTPException(
            400,
            "No readable text found in this file.",
        )

    return text


# ============================================================
# CHUNKING
# ============================================================

def chunk(
    text,
    size=500,
):
    out = []
    cur = ""

    parts = re.split(
        r"\n\s*\n|(?<=[.!?])\s+",
        text,
    )

    for part in parts:

        part = part.strip()

        if not part:
            continue

        if (
            len(cur) + len(part) > size
            and cur
        ):
            out.append(
                cur.strip()
            )

            cur = ""

        cur += part + " "

    if cur.strip():
        out.append(
            cur.strip()
        )

    return out


# ============================================================
# DOCUMENT ACCESS
# ============================================================

def visible(
    u,
    d,
):
    return (
        u["role"] == "admin"
        or d.level == 1
        or d.owner == u["email"]
    )


def meta(
    d,
    **kw,
):
    return {
        "id": d.id,
        "name": d.name,
        "ext": d.ext,
        "size": d.size,
        "ts": d.ts,
        "restricted": d.level > 1,
        **kw,
    }


# ============================================================
# DOCUMENT RETRIEVAL
# ============================================================

def retrieve(
    u,
    query,
    db,
    k=6,
):
    documents = (
        db.query(Document)
        .order_by(
            Document.ts.desc()
        )
        .all()
    )

    pool = []

    for d in documents:

        if not visible(u, d):
            continue

        try:

            texts = [d.name]

            for c in d.chunks:

                texts.append(
                    dec(c.data).decode(
                        "utf-8",
                        "replace",
                    )
                )

            for t in texts:
                pool.append(
                    (
                        d,
                        t,
                    )
                )

        except Exception:
            continue

    qt = set(tok(query))

    if not pool or not qt:
        return []

    toks = [
        Counter(tok(t))
        for _, t in pool
    ]

    df = Counter(
        w
        for c in toks
        for w in c
        if w in qt
    )

    scored = []

    for (d, t), tf in zip(
        pool,
        toks,
    ):

        score = sum(
            (
                (
                    1
                    + math.log(tf[w])
                )
                * math.log(
                    1
                    + len(pool) / df[w]
                )
            )
            for w in qt
            if tf[w] and df[w]
        )

        if score > 0:
            scored.append(
                (
                    score,
                    d,
                    t,
                )
            )

    scored.sort(
        key=lambda x: -x[0]
    )

    return scored[:k]


# ============================================================
# LOCAL ANSWER FALLBACK
# ============================================================

def local_answer(
    query,
    hits,
):
    qt = set(tok(query))

    found = []

    for score, d, t in hits:

        sentences = re.split(
            r"(?<=[.!?])\s+|\n",
            t,
        )

        for sent in sentences:

            overlap = len(
                qt
                & set(tok(sent))
            )

            if (
                overlap
                and len(sent) > 15
            ):
                found.append(
                    (
                        overlap,
                        score,
                        sent.strip(),
                        d.name,
                    )
                )

    found.sort(
        key=lambda x: (
            -x[0],
            -x[1],
        )
    )

    seen = set()
    best = []
    sources = []

    for (
        _,
        _,
        sent,
        name,
    ) in found:

        if sent in seen:
            continue

        seen.add(sent)
        best.append(sent)

        if name not in sources:
            sources.append(name)

        if len(best) == 3:
            break

    return (
        " ".join(best),
        sources,
    )


# ============================================================
# GEMINI
# ============================================================

GEMINI_API_KEY = os.getenv(
    "GEMINI_API_KEY"
)

gemini_client = None

if (
    GEMINI_API_KEY
    and genai is not None
):

    try:

        gemini_client = genai.Client(
            api_key=GEMINI_API_KEY
        )

        print(
            "Gemini AI: enabled"
        )

    except Exception as e:

        print(
            "Gemini AI initialization failed:",
            e,
        )

        gemini_client = None

elif not GEMINI_API_KEY:

    print(
        "Gemini AI: disabled "
        "(GEMINI_API_KEY missing)"
    )

elif genai is None:

    print(
        "Gemini AI: disabled "
        "(google-genai package missing)"
    )


GEMINI_MODEL = "gemini-3.8-flash"


def gemini_answer(
    query,
    hits,
):
    if not gemini_client:
        return None

    if not hits:
        return None

    context_parts = []

    for score, d, text in hits:

        context_parts.append(
            "DOCUMENT: "
            + d.name
            + "\n"
            + text[:5000]
        )

    context = "\n\n---\n\n".join(
        context_parts
    )

    prompt = f"""
You are SecureDocs AI, a document assistant.

Answer the user's question using ONLY
the document context supplied below.

Do not invent facts.
Do not use outside knowledge.

If the answer is not present in the
provided documents, clearly say that
the information was not found.

Keep the answer useful and reasonably
concise.

DOCUMENT CONTEXT:

{context}

USER QUESTION:

{query}
"""

    try:

        response = (
            gemini_client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
            )
        )

        text = getattr(
            response,
            "text",
            None,
        )

        if not text:
            return None

        sources = []

        for _, d, _ in hits:

            if d.name not in sources:
                sources.append(d.name)

        return (
            text.strip(),
            sources[:5],
        )

    except Exception as e:

        print(
            "Gemini request failed:",
            repr(e),
        )

        return None


# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"],
)


# ============================================================
# SECURITY MIDDLEWARE
# ============================================================

# IMPORTANT:
# The existing HTML files contain inline JavaScript
# and inline event handlers.
#
# Therefore script-src MUST include 'unsafe-inline'
# unless the HTML is later refactored to remove all
# inline JavaScript/event handlers.
#
# This is what fixes the browser error:
#
# "Executing inline script violates CSP"
#
# and:
#
# "Executing inline event handler violates CSP"

CSP_BASE = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


@app.middleware("http")
async def security_middleware(
    request: Request,
    call_next,
):

    if request.method == "OPTIONS":

        response = Response(
            status_code=405,
            content="Method Not Allowed",
            headers={
                "Allow": "GET, POST, HEAD",
            },
        )

    else:

        response = await call_next(
            request
        )

    response.headers.update(
        {
            "X-Content-Type-Options":
                "nosniff",

            "X-Frame-Options":
                "DENY",

            "Referrer-Policy":
                "no-referrer",

            "Cache-Control":
                "no-store",

            "Content-Security-Policy":
                CSP_BASE,

            "Permissions-Policy":
                "camera=(), "
                "microphone=(), "
                "geolocation=()",

            "Strict-Transport-Security":
                "max-age=31536000; "
                "includeSubDomains",
        }
    )

    return response


# ============================================================
# REQUEST MODELS
# ============================================================

class AuthIn(BaseModel):

    email: str = Field(
        max_length=150
    )

    password: str = Field(
        max_length=128
    )


class ChatIn(BaseModel):

    message: str = Field(
        min_length=1,
        max_length=500,
    )


# ============================================================
# AUTH API
# ============================================================

@app.post("/api/auth")
def auth(
    body: AuthIn,
    request: Request,
    db: Session = Depends(get_db),
):

    email = (
        body.email
        .strip()
        .lower()
    )

    if not EMAIL.match(email):

        raise HTTPException(
            400,
            "Enter a valid email address.",
        )

    key = (
        request.client.host
        if request.client
        else "?"
    )

    key = (
        key,
        email,
    )

    now = time.time()

    FAILS[key] = [
        t
        for t in FAILS[key]
        if t > now - 300
    ]

    if len(FAILS[key]) >= 5:

        raise HTTPException(
            429,
            "Too many attempts. "
            "Try again in 5 minutes.",
        )

    created = False

    with LOCK:

        user = (
            db.query(User)
            .filter(
                User.email == email
            )
            .first()
        )

        if user is None:

            if len(body.password) < 8:

                raise HTTPException(
                    400,
                    "New accounts need a password "
                    "of at least 8 characters.",
                )

            user = User(
                email=email,
                pw=hash_pw(
                    body.password
                ),
                role="employee",
                queries=0,
            )

            db.add(user)
            db.commit()

            created = True

        elif not check_pw(
            body.password,
            user.pw,
        ):

            FAILS[key].append(
                time.time()
            )

            raise HTTPException(
                401,
                "Incorrect email or password.",
            )

    token = secrets.token_urlsafe(32)

    csrf = secrets.token_urlsafe(24)

    expired = [
        h
        for h, s in SESSIONS.items()
        if s["exp"] < time.time()
    ]

    for h in expired:

        SESSIONS.pop(
            h,
            None,
        )

    SESSIONS[
        hashlib.sha256(
            token.encode()
        ).hexdigest()
    ] = {
        "email": email,
        "csrf": csrf,
        "exp": time.time() + SESSION_TTL,
    }

    response = JSONResponse(
        {
            "created": created,
        }
    )

    response.set_cookie(
        "sid",
        token,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="strict",
        secure=COOKIE_SECURE,
    )

    return response


@app.post("/api/logout")
def logout(
    request: Request,
    u=Depends(current_user),
):

    token = request.cookies.get("sid")

    if token:

        SESSIONS.pop(
            hashlib.sha256(
                token.encode()
            ).hexdigest(),
            None,
        )

    response = JSONResponse(
        {
            "ok": True
        }
    )

    response.delete_cookie("sid")

    return response


@app.get("/api/me")
def me(
    u=Depends(current_user),
):
    return u


# ============================================================
# FILE APIs
# ============================================================

@app.get("/api/files")
def files(
    u=Depends(current_user),
    db: Session = Depends(get_db),
):

    documents = (
        db.query(Document)
        .order_by(
            Document.ts.desc()
        )
        .all()
    )

    return [
        meta(d)
        for d in documents
        if visible(u, d)
    ]


@app.get("/api/stats")
def stats(
    u=Depends(current_user),
    db: Session = Depends(get_db),
):

    documents = (
        db.query(Document)
        .all()
    )

    count = sum(
        1
        for d in documents
        if visible(u, d)
    )

    user = (
        db.query(User)
        .filter(
            User.email == u["email"]
        )
        .first()
    )

    return {
        "total": count,
        "indexed": count,
        "queries": (
            user.queries
            if user
            else 0
        ),
    }


@app.post("/api/upload")
async def upload(
    file: UploadFile = File(...),
    u=Depends(current_user),
    db: Session = Depends(get_db),
):

    original_name = os.path.basename(
        file.filename or "file"
    )

    name = re.sub(
        r"[^\w.\- ]",
        "_",
        original_name,
    )[:100]

    if not name:
        name = "file"

    ext = Path(name).suffix.lower()

    if ext not in EXTS:

        raise HTTPException(
            400,
            "Supported types: "
            + ", ".join(
                sorted(EXTS)
            ),
        )

    raw = await file.read(
        MAX_BYTES + 1
    )

    if len(raw) > MAX_BYTES:

        raise HTTPException(
            413,
            "File is larger than 5 MB.",
        )

    if not raw:

        raise HTTPException(
            400,
            "File is empty.",
        )

    text = extract(
        ext,
        raw,
    )

    level = (
        3
        if (
            SENSITIVE.search(name)
            or SENSITIVE_NAME.search(name)
            or SENSITIVE.search(text[:3000])
        )
        else 1
    )

    doc_id = uuid.uuid4().hex

    document = Document(
        id=doc_id,
        name=name,
        ext=ext[1:].upper(),
        owner=u["email"],
        level=level,
        size=len(raw),
        ts=time.time(),
        raw=enc(raw),
    )

    db.add(document)

    chunks = chunk(text)

    for position, content in enumerate(chunks):

        db.add(
            DocumentChunk(
                doc_id=doc_id,
                position=position,
                data=enc(
                    content.encode(
                        "utf-8"
                    )
                ),
            )
        )

    db.commit()
    db.refresh(document)

    return meta(document)


@app.get(
    "/api/files/{doc_id}/download"
)
def download(
    doc_id: str,
    u=Depends(current_user),
    db: Session = Depends(get_db),
):

    d = (
        db.query(Document)
        .filter(
            Document.id == doc_id
        )
        .first()
    )

    if not d or not visible(u, d):

        raise HTTPException(
            404,
            "File not found.",
        )

    try:

        raw = dec(d.raw)

    except Exception:

        raise HTTPException(
            500,
            "Could not decrypt this document.",
        )

    return Response(
        raw,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition":
                "attachment; "
                "filename*=UTF-8''"
                + quote(d.name)
        },
    )


@app.get("/api/search")
def search(
    q: str = "",
    u=Depends(current_user),
    db: Session = Depends(get_db),
):

    results = {}

    for score, d, t in retrieve(
        u,
        q[:200],
        db,
        30,
    ):

        results.setdefault(
            d.id,
            meta(
                d,
                snippet=(
                    t
                    if t != d.name
                    else "Name match"
                )[:100],
            ),
        )

    return list(
        results.values()
    )


# ============================================================
# ASSISTANT API
# ============================================================

@app.post("/api/chat")
def chat(
    body: ChatIn,
    u=Depends(current_user),
    db: Session = Depends(get_db),
):

    user = (
        db.query(User)
        .filter(
            User.email == u["email"]
        )
        .first()
    )

    if user:

        user.queries = (
            user.queries or 0
        ) + 1

        db.commit()

    low = (
        body.message
        .lower()
        .strip()
    )

    docs = [
        d
        for d in (
            db.query(Document)
            .order_by(
                Document.ts.desc()
            )
            .all()
        )
        if visible(u, d)
    ]

    if re.fullmatch(
        r"(hi|hello|hey)\W*",
        low,
    ):

        return {
            "answer":
                "Hello! Ask me anything "
                "about the documents "
                "in your workspace.",
            "sources": [],
        }

    if not docs:

        return {
            "answer":
                "There are no documents yet. "
                "Upload some on the "
                "Documents page first.",
            "sources": [],
        }

    if (
        "summar" in low
        or re.search(
            r"\b(list|which|what)\b.*"
            r"\b(documents|files)\b",
            low,
        )
    ):

        lines = []

        for d in docs[:6]:

            preview = ""

            if d.chunks:

                try:

                    preview = dec(
                        d.chunks[0].data
                    ).decode(
                        "utf-8",
                        "replace",
                    )[:110]

                except Exception:
                    preview = ""

            lines.append(
                f"{d.name}: {preview}..."
            )

        return {
            "answer":
                f"You have {len(docs)} "
                "document(s). "
                + "  ".join(lines),

            "sources": [
                d.name
                for d in docs[:6]
            ],
        }

    hits = retrieve(
        u,
        body.message,
        db,
        6,
    )

    if not hits:

        return {
            "answer":
                "I couldn't find that in "
                "the documents you have "
                "access to.",
            "sources": [],
        }

    ai_result = gemini_answer(
        body.message,
        hits,
    )

    if ai_result:

        answer_text, sources = ai_result

        return {
            "answer": answer_text,
            "sources": sources,
        }

    answer_text, sources = local_answer(
        body.message,
        hits,
    )

    if not answer_text:

        return {
            "answer":
                "I couldn't find that in "
                "the documents you have "
                "access to.",
            "sources": [],
        }

    return {
        "answer": answer_text,
        "sources": sources,
    }


# ============================================================
# FRONTEND CONNECTOR
# ============================================================

PROTECTED = {
    "dashboard",
    "documents",
    "assistant",
}

PUBLIC = {
    "index",
    "login",
}


COMMON = r"""
const $=s=>document.querySelector(s);
let CSRF="",ME=null;

const mk=(t,c,x)=>{
    const e=document.createElement(t);
    if(c)e.className=c;
    if(x!=null)e.textContent=x;
    return e
};

async function api(p,o={}){

    o.headers=Object.assign(
        {"X-CSRF":CSRF},
        o.headers||{}
    );

    const r=await fetch(
        p,
        Object.assign(
            {credentials:"same-origin"},
            o
        )
    );

    if(r.status===401){
        location.href="login.html";

        throw new Error(
            "Please sign in."
        )
    }

    if(!r.ok){

        let m="Something went wrong.";

        try{

            const j=await r.json();

            if(
                typeof j.detail==="string"
            )
                m=j.detail;

        }catch(e){}

        throw new Error(m)
    }

    return r
}

const fmt=b=>
    b<1024
        ?b+" B"
        :b<1048576
            ?(b/1024).toFixed(1)+" KB"
            :(b/1048576).toFixed(1)+" MB";

function ago(t){

    const s=Math.max(
        0,
        Date.now()/1000-t
    );

    if(s<60)
        return "Just now";

    if(s<3600)
        return Math.floor(
            s/60
        )+" minutes ago";

    if(s<86400)
        return Math.floor(
            s/3600
        )+" hours ago";

    return Math.floor(
        s/86400
    )+" days ago"
}

function docRow(d,extra){

    const r=mk(
        "div",
        "document"
    );

    const l=mk(
        "div",
        "doc-left"
    );

    const w=mk("div");

    l.append(
        mk(
            "div",
            "doc-icon",
            d.ext
        )
    );

    w.append(
        mk(
            "div",
            "doc-name",
            d.name
        ),

        mk(
            "div",
            "doc-meta",
            fmt(d.size)
            +" · "
            +ago(d.ts)
            +(extra
                ?" · "+extra
                :"")
        )
    );

    l.append(w);

    r.append(
        l,

        mk(
            "div",
            "status",
            d.restricted
                ?"Restricted"
                :"Indexed"
        )
    );

    r.title="Click to download";
    r.style.cursor="pointer";

    r.onclick=()=>{

        location.href=
            "/api/files/"
            +d.id
            +"/download"

    };

    return r
}

const ready=fetch(
    "/api/me",
    {
        credentials:
            "same-origin"
    }
)

.then(r=>{

    if(!r.ok){

        location.href=
            "login.html";

        throw 0
    }

    return r.json()

})

.then(d=>{

    ME=d;
    CSRF=d.csrf;

    const avatar=
        $(".avatar");

    if(avatar)
        avatar.textContent=
            d.email
                .slice(0,2)
                .toUpperCase();

    const strong=
        $(".user-info strong");

    if(strong)
        strong.textContent=
            d.email.split("@")[0];

    const span=
        $(".user-info span");

    if(span)
        span.textContent=
            d.role==="admin"
                ?"Administrator"
                :"Secure account";

    const m=
        $(".user-mini");

    if(m){

        m.style.cursor=
            "pointer";

        m.title=
            "Click to sign out";

        m.onclick=async()=>{

            if(confirm("Sign out?")){

                await api(
                    "/api/logout",
                    {
                        method:"POST"
                    }
                );

                location.href=
                    "login.html"
            }
        }
    }
});
"""


PAGE_JS = {

"login": r"""
const $=s=>document.querySelector(s);

const sec=$(".security");

const dot=
    sec
        ?sec.querySelector(".security-dot")
        :null;

function note(m){

    if(!sec)
        return;

    if(dot){

        sec.replaceChildren(
            dot,
            document.createTextNode(m)
        );

    }else{

        sec.textContent=m;

    }
}

async function go(e){

    if(e)
        e.preventDefault();

    if(e)
        e.stopPropagation();

    const em=$("#email");
    const pw=$("#password");

    if(!em || !pw)
        return;

    if(
        !em.reportValidity()
        ||
        !pw.reportValidity()
    )
        return;

    note("Signing in...");

    try{

        const r=await fetch(
            "/api/auth",
            {
                method:"POST",

                credentials:
                    "same-origin",

                headers:{
                    "Content-Type":
                        "application/json"
                },

                body:JSON.stringify({
                    email:em.value,
                    password:pw.value
                })
            }
        );

        const j=await r.json();

        if(!r.ok)

            throw new Error(
                typeof j.detail==="string"
                    ?j.detail
                    :"Could not sign in."
            );

        note(
            j.created
                ?"Account created. Welcome!"
                :"Signed in. Redirecting..."
        );

        setTimeout(
            ()=>{
                location.href=
                    "dashboard.html"
            },

            j.created
                ?900
                :200
        )

    }catch(x){

        note(
            x.message
            ||"Could not sign in."
        )
    }
}

document.addEventListener(
    "click",
    e=>{

        if(
            e.target.closest(
                ".login-button"
            )
        )
            go(e)

    },
    true
);

document.addEventListener(
    "submit",
    go,
    true
);
""",


"dashboard": r"""
(async()=>{

    await ready;

    const f=
        await(
            await api(
                "/api/files"
            )
        ).json();

    const s=
        await(
            await api(
                "/api/stats"
            )
        ).json();

    const h=
        document.querySelectorAll(
            ".stat-card h2"
        );

    if(h[0])
        h[0].textContent=
            s.total;

    if(h[1])
        h[1].textContent=
            s.indexed;

    if(h[2])
        h[2].textContent=
            s.queries;

    const p=
        $(".content-grid .panel");

    if(!p)
        return;

    const link=
        p.querySelector(
            ".panel-header a"
        );

    if(link)
        link.href=
            "documents.html";

    p.querySelectorAll(
        ".document"
    ).forEach(
        x=>x.remove()
    );

    if(!f.length){

        const e=mk(
            "div",
            "document"
        );

        e.append(
            mk(
                "div",
                "doc-meta",
                "No documents yet. "
                +"Upload your first one."
            )
        );

        p.append(e)
    }

    f.slice(0,3).forEach(
        d=>p.append(
            docRow(d)
        )
    )

})();
""",


"documents": r"""
const list=$(".documents");

let ALL=[];

function draw(items){

    if(!list)
        return;

    list.replaceChildren();

    if(!items.length){

        const e=mk(
            "div",
            "document"
        );

        e.append(
            mk(
                "div",
                "doc-meta",
                "No documents found."
            )
        );

        list.append(e);

        return
    }

    items.forEach(
        d=>list.append(
            docRow(
                d,
                d.snippet
            )
        )
    )
}

async function load(){

    await ready;

    ALL=
        await(
            await api(
                "/api/files"
            )
        ).json();

    draw(ALL)
}

async function send(files){

    await ready;

    for(
        const f of files
    ){

        const t=mk(
            "div",
            "document"
        );

        const l=mk(
            "div",
            "doc-left"
        );

        const w=mk("div");

        l.append(
            mk(
                "div",
                "doc-icon",
                (
                    f.name
                    .split(".")
                    .pop()||""
                )
                .toUpperCase()
                .slice(0,4)
            )
        );

        w.append(
            mk(
                "div",
                "doc-name",
                f.name
            ),

            mk(
                "div",
                "doc-meta",
                fmt(f.size)
                +" · Uploading..."
            )
        );

        l.append(w);

        t.append(
            l,

            mk(
                "div",
                "status",
                "Uploading"
            )
        );

        list.prepend(t);

        try{

            const fd=
                new FormData();

            fd.append(
                "file",
                f
            );

            await api(
                "/api/upload",
                {
                    method:"POST",
                    body:fd
                }
            );

        }catch(x){

            alert(
                f.name
                +": "
                +x.message
            )
        }
    }

    load()
}

document.addEventListener(
    "change",
    e=>{

        if(
            e.target.id!=="fileInput"
        )
            return;

        e.stopPropagation();

        const fs=[
            ...e.target.files
        ];

        e.target.value="";

        send(fs)

    },
    true
);

const z=
    $(".upload-zone");

if(z){

    z.addEventListener(
        "dragover",
        e=>e.preventDefault()
    );

    z.addEventListener(
        "drop",
        e=>{

            e.preventDefault();

            send([
                ...e.dataTransfer.files
            ])

        }
    );
}

let timer;

const searchBox=
    $(".search");

if(searchBox){

    searchBox.addEventListener(
        "input",
        e=>{

            clearTimeout(timer);

            const v=
                e.target.value.trim();

            timer=setTimeout(
                async()=>{

                    if(!v){

                        draw(ALL);

                        return
                    }

                    await ready;

                    try{

                        draw(
                            await(
                                await api(
                                    "/api/search?q="
                                    +encodeURIComponent(v)
                                )
                            ).json()
                        )

                    }catch(x){}

                },
                250
            )
        }
    )
}

load();
""",


"assistant": r"""
const msgs=
    $("#messages");

ready.then(()=>{

    if(!msgs)
        return;

    [
        ...msgs.querySelectorAll(
            ".message"
        )
    ]
    .slice(1)
    .forEach(
        x=>x.remove()
    )
});

function add(
    cls,
    text,
    src
){

    if(!msgs)
        return;

    const m=mk(
        "div",
        "message "+cls
    );

    const b=mk(
        "div",
        "bubble",
        text
    );

    if(
        src
        &&
        src.length
    ){

        b.append(
            mk(
                "div",
                "source",
                "Source · "
                +src.join(" · ")
            )
        )
    }

    m.append(b);

    msgs.append(m);

    msgs.scrollTop=
        msgs.scrollHeight
}

document.addEventListener(
    "submit",
    async e=>{

        if(
            e.target.id!=="chatForm"
        )
            return;

        e.preventDefault();
        e.stopPropagation();

        const i=
            $("#chatInput");

        if(!i)
            return;

        const t=
            i.value.trim();

        if(!t)
            return;

        i.value="";

        add(
            "user",
            t
        );

        try{

            await ready;

            const response=
                await api(
                    "/api/chat",
                    {
                        method:"POST",

                        headers:{
                            "Content-Type":
                                "application/json"
                        },

                        body:
                            JSON.stringify({
                                message:t
                            })
                    }
                );

            const j=
                await response.json();

            add(
                "ai",
                j.answer,
                j.sources
            );

        }catch(x){

            add(
                "ai",
                x.message
            )
        }

    },
    true
);
""",

}


# ============================================================
# PAGE LOADING
# ============================================================

def load_page(
    name,
    user_ok,
    request=None,
):

    for p in (
        BASE / "pages" / f"{name}.html",
        BASE / f"{name}.html",
    ):

        if p.is_file():

            html = p.read_text(
                "utf-8"
            )

            break

    else:

        return HTMLResponse(
            f"""
            <h2>{name}.html not found</h2>
            <p>
                Put it next to main.py
                or inside a 'pages' folder.
            </p>
            """,
            500,
        )

    js = PAGE_JS.get(
        name,
        "",
    )

    if name in PROTECTED:
        js = COMMON + js

    if js:

        head, sep, tail = html.rpartition(
            "</body>"
        )

        script = (
            "<script>"
            + js
            + "</script>"
        )

        if sep:

            html = (
                head
                + script
                + "</body>"
                + tail
            )

        else:

            html += script

    return HTMLResponse(html)


# ============================================================
# ROUTES
# ============================================================

@app.get("/")
def home(
    request: Request,
):
    return load_page(
        "index",
        True,
        request,
    )


@app.get("/{name}.html")
def page(
    name: str,
    request: Request,
):

    if name not in (
        PROTECTED | PUBLIC
    ):

        raise HTTPException(
            404,
            "Not found",
        )

    if name in PROTECTED:

        db = SessionLocal()

        try:

            user = get_user(
                request,
                db,
            )

        finally:

            db.close()

        if not user:

            return RedirectResponse(
                "/login.html",
                status_code=303,
            )

    return load_page(
        name,
        True,
        request,
    )
