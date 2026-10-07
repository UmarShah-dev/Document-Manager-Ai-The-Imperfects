import csv
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
    Text,
    create_engine,
    inspect,
    text as sql_text,
)

from sqlalchemy.orm import (
    declarative_base,
    relationship,
    sessionmaker,
    Session,
)

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
        "check_same_thread": False,
    },
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


# ============================================================
# USER
# ============================================================

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
        default="visitor",
        nullable=False,
    )

    queries = Column(
        Integer,
        default=0,
        nullable=False,
    )

    full_name = Column(
        String(150),
        default="",
        nullable=False,
    )

    department = Column(
        String(100),
        default="",
        nullable=False,
    )

    job_title = Column(
        String(100),
        default="",
        nullable=False,
    )

    phone = Column(
        String(50),
        default="",
        nullable=False,
    )

    bio = Column(
        Text,
        default="",
        nullable=False,
    )

    theme = Column(
        String(30),
        default="system",
        nullable=False,
    )

    notifications = Column(
        Integer,
        default=1,
        nullable=False,
    )

    documents = relationship(
        "Document",
        back_populates="user",
        cascade="all, delete-orphan",
    )


# ============================================================
# DOCUMENT
# ============================================================

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


# ============================================================
# DOCUMENT CHUNKS
# ============================================================

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


# ============================================================
# AUDIT LOG
# ============================================================

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    ts = Column(
        Float,
        nullable=False,
        index=True,
    )

    user_email = Column(
        String(150),
        nullable=False,
        index=True,
    )

    action = Column(
        String(50),
        nullable=False,
        index=True,
    )

    description = Column(
        String(500),
        nullable=False,
    )

    document = Column(
        String(200),
        default="",
        nullable=False,
    )

    ip = Column(
        String(100),
        default="",
        nullable=False,
    )

    level = Column(
        String(30),
        default="info",
        nullable=False,
    )


# ============================================================
# CREATE TABLES
# ============================================================

Base.metadata.create_all(
    bind=engine
)


# ============================================================
# DATABASE MIGRATION
# ============================================================

def ensure_column(
    table,
    column,
    definition,
):
    try:
        inspector = inspect(engine)

        columns = {
            x["name"]
            for x in inspector.get_columns(table)
        }

        if column not in columns:
            with engine.begin() as conn:
                conn.execute(
                    sql_text(
                        f"ALTER TABLE {table} "
                        f"ADD COLUMN {column} "
                        f"{definition}"
                    )
                )

    except Exception as e:
        print(
            "Database migration warning:",
            repr(e),
        )


ensure_column(
    "users",
    "full_name",
    "VARCHAR(150) DEFAULT ''",
)

ensure_column(
    "users",
    "department",
    "VARCHAR(100) DEFAULT ''",
)

ensure_column(
    "users",
    "job_title",
    "VARCHAR(100) DEFAULT ''",
)

ensure_column(
    "users",
    "phone",
    "VARCHAR(50) DEFAULT ''",
)

ensure_column(
    "users",
    "bio",
    "TEXT DEFAULT ''",
)

ensure_column(
    "users",
    "theme",
    "VARCHAR(30) DEFAULT 'system'",
)

ensure_column(
    "users",
    "notifications",
    "INTEGER DEFAULT 1",
)


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

    FERNET_KEY = (
        Fernet.generate_key().decode()
    )


try:

    FERNET = Fernet(
        FERNET_KEY.encode()
        if isinstance(
            FERNET_KEY,
            str,
        )
        else FERNET_KEY
    )

except Exception:

    raise RuntimeError(
        "SECUREDOCS_FERNET_KEY is invalid."
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
# DEMO ACCOUNTS
# ============================================================

DEMO_ACCOUNTS = {

    "admin@securedocs.com": {
        "password": "SecureDocs_Admin_2026!X7",
        "role": "admin",
        "full_name": "Administrator",
    },

    "executive@securedocs.com": {
        "password": "exec123",
        "role": "executive",
        "full_name": "Executive User",
    },

    "visitor@securedocs.com": {
        "password": "visit123",
        "role": "visitor",
        "full_name": "Visitor User",
    },

}


ADMIN_EMAIL = "admin@securedocs.com"


def ensure_demo_accounts():

    db = SessionLocal()

    try:

        for email, info in DEMO_ACCOUNTS.items():

            user = (
                db.query(User)
                .filter(
                    User.email == email
                )
                .first()
            )

            if user is None:

                user = User(
                    email=email,
                    pw=hash_pw(
                        info["password"]
                    ),
                    role=info["role"],
                    queries=0,
                    full_name=info["full_name"],
                )

                db.add(user)

            else:

                # Reset the demo credentials so
                # the frontend developer test accounts
                # always work after deployment.
                user.pw = hash_pw(
                    info["password"]
                )

                user.role = info["role"]

                if not user.full_name:
                    user.full_name = (
                        info["full_name"]
                    )

        db.commit()

        print(
            "\n========================================"
        )
        print(
            " SecureDocs Demo Accounts"
        )
        print(
            "========================================"
        )
        print(
            " Admin     : admin@securedocs.com / SecureDocs_Admin_2026!X7"
        )
        print(
            " Executive : executive@securedocs.com / exec123"
        )
        print(
            " Visitor   : visitor@securedocs.com / visit123"
        )
        print(
            "========================================\n"
        )

    except Exception as e:

        db.rollback()

        print(
            "Demo account setup failed:",
            repr(e),
        )

    finally:

        db.close()


ensure_demo_accounts()


# ============================================================
# AUTHENTICATION
# ============================================================

SESSION_SECRET = hashlib.sha256(
    (
        FERNET_KEY
        + "|SecureDocs-Session-2026"
    ).encode()
).digest()


def make_session_cookie(
    email: str,
    csrf: str,
    expires: int,
) -> str:

    payload = (
        f"{email}|{csrf}|{expires}"
    ).encode()

    signature = hmac.new(
        SESSION_SECRET,
        payload,
        hashlib.sha256,
    ).hexdigest()

    encoded = (
        secrets.token_urlsafe(0)
        + payload.hex()
    )

    return encoded + "." + signature


def read_session_cookie(
    token: str,
):

    try:

        encoded, signature = token.split(
            ".",
            1,
        )

        payload = bytes.fromhex(
            encoded
        )

        expected = hmac.new(
            SESSION_SECRET,
            payload,
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(
            signature,
            expected,
        ):
            return None

        email, csrf, expires = (
            payload.decode().split(
                "|",
                2,
            )
        )

        expires = int(expires)

        if expires < int(time.time()):
            return None

        return {
            "email": email,
            "csrf": csrf,
            "exp": expires,
        }

    except Exception:

        return None


def get_user(
    request: Request,
    db: Session,
):

    token = request.cookies.get(
        "sid"
    )

    if not token:
        return None

    session = read_session_cookie(
        token
    )

    if not session:
        return None

    user = (
        db.query(User)
        .filter(
            User.email == session["email"]
        )
        .first()
    )

    if not user:
        return None

    return {
        "email": user.email,
        "role": user.role,
        "csrf": session["csrf"],
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


def require_admin(u):

    if u["role"] != "admin":

        raise HTTPException(
            403,
            "Administrator access required.",
        )

    return u


# ============================================================
# AUDIT HELPER
# ============================================================

def audit(
    db,
    request,
    user_email,
    action,
    description,
    document="",
    level="info",
):

    try:

        ip = (
            request.client.host
            if request.client
            else ""
        )

        db.add(
            AuditLog(
                ts=time.time(),
                user_email=user_email,
                action=action,
                description=description[:500],
                document=document[:200],
                ip=ip[:100],
                level=level[:30],
            )
        )

        db.commit()

    except Exception as e:

        print(
            "Audit log error:",
            repr(e),
        )

        db.rollback()


# ============================================================
# TEXT PROCESSING
# ============================================================

STOP = set(
    """
    a an the and or of to in on for is are was were be it
    this that with as at by from what who how when which
    do does can i you we my our your about me tell
    happening happening's
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

            if not raw.startswith(
                b"%PDF"
            ):

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

            xml = xml.replace(
                "</w:tr>",
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
    size=700,
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
        "owner": d.owner,
        "restricted": d.level > 1,
        **kw,
    }


# ============================================================
# DOCUMENT NAME MATCHING
# ============================================================

def normalize_name(name):

    return set(
        tok(
            Path(name).stem
        )
    )


def find_named_documents(
    u,
    query,
    db,
):

    q = query.lower()

    documents = (
        db.query(Document)
        .order_by(
            Document.ts.desc()
        )
        .all()
    )

    matches = []

    for d in documents:

        if not visible(u, d):
            continue

        full_name = d.name.lower()

        stem = Path(
            d.name
        ).stem.lower()

        if (
            full_name in q
            or stem in q
        ):

            matches.append(d)
            continue

        name_tokens = normalize_name(
            d.name
        )

        query_tokens = set(
            re.findall(
                r"[a-z0-9]+",
                q,
            )
        )

        if (
            name_tokens
            and name_tokens.issubset(
                query_tokens
            )
        ):

            matches.append(d)

    return matches


# ============================================================
# DOCUMENT RETRIEVAL
# ============================================================

def retrieve(
    u,
    query,
    db,
    k=6,
):

    named_docs = find_named_documents(
        u,
        query,
        db,
    )

    if named_docs:

        pool = []

        for d in named_docs:

            for c in d.chunks:

                try:

                    content = dec(
                        c.data
                    ).decode(
                        "utf-8",
                        "replace",
                    ).strip()

                    if content:

                        pool.append(
                            (
                                d,
                                content,
                                c.position,
                            )
                        )

                except Exception:

                    continue

        if not pool:
            return []

        qt = set(
            tok(query)
        )

        for d in named_docs:

            qt -= normalize_name(
                d.name
            )

        qt -= {
            "what",
            "happen",
            "happening",
            "tell",
            "about",
            "document",
            "file",
            "report",
            "explain",
            "describe",
        }

        if not qt:

            return [
                (
                    1.0,
                    d,
                    content,
                )
                for d, content, position
                in pool[:k]
            ]

        toks = [
            Counter(tok(content))
            for _, content, _ in pool
        ]

        df = Counter(
            word
            for c in toks
            for word in c
            if word in qt
        )

        scored = []

        for (
            (d, content, position),
            tf,
        ) in zip(
            pool,
            toks,
        ):

            score = 0.0

            for word in qt:

                if tf[word] and df[word]:

                    score += (
                        (
                            1
                            + math.log(
                                tf[word]
                            )
                        )
                        * math.log(
                            1
                            + len(pool)
                            / df[word]
                        )
                    )

            if score > 0:

                scored.append(
                    (
                        score,
                        d,
                        content,
                    )
                )

        scored.sort(
            key=lambda x: -x[0]
        )

        if scored:

            return scored[:k]

        return [
            (
                1.0,
                d,
                content,
            )
            for d, content, position
            in pool[:k]
        ]

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

        for c in d.chunks:

            try:

                content = dec(
                    c.data
                ).decode(
                    "utf-8",
                    "replace",
                ).strip()

                if content:

                    pool.append(
                        (
                            d,
                            content,
                        )
                    )

            except Exception:

                continue

    qt = set(
        tok(query)
    )

    if not pool or not qt:
        return []

    toks = [
        Counter(tok(content))
        for _, content in pool
    ]

    df = Counter(
        word
        for c in toks
        for word in c
        if word in qt
    )

    scored = []

    for (
        (d, content),
        tf,
    ) in zip(
        pool,
        toks,
    ):

        score = sum(
            (
                (
                    1
                    + math.log(
                        tf[word]
                    )
                )
                * math.log(
                    1
                    + len(pool)
                    / df[word]
                )
            )
            for word in qt
            if tf[word]
            and df[word]
        )

        if score > 0:

            scored.append(
                (
                    score,
                    d,
                    content,
                )
            )

    scored.sort(
        key=lambda x: -x[0]
    )

    return scored[:k]


# ============================================================
# LOCAL DOCUMENT FALLBACK
# ============================================================

def local_answer(
    query,
    hits,
):

    qt = set(
        tok(query)
    )

    found = []

    for score, d, content in hits:

        if (
            content.strip().lower()
            == d.name.strip().lower()
        ):
            continue

        sentences = re.split(
            r"(?<=[.!?])\s+|\n",
            content,
        )

        for sentence in sentences:

            sentence = sentence.strip()

            if not sentence:
                continue

            overlap = len(
                qt
                & set(
                    tok(sentence)
                )
            )

            if (
                overlap
                and len(sentence) > 15
            ):

                found.append(
                    (
                        overlap,
                        score,
                        sentence,
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
        sentence,
        name,
    ) in found:

        if sentence in seen:
            continue

        seen.add(sentence)
        best.append(sentence)

        if name not in sources:
            sources.append(name)

        if len(best) == 5:
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
            repr(e),
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


# ============================================================
# GEMINI DOCUMENT MODE
# ============================================================

def gemini_answer(
    query,
    hits,
):

    if not gemini_client:
        return None

    if not hits:
        return None

    context_parts = []

    for score, d, content in hits:

        context_parts.append(
            "DOCUMENT: "
            + d.name
            + "\nDOCUMENT CONTENT:\n"
            + content[:7000]
        )

    context = (
        "\n\n====================\n\n"
        .join(context_parts)
    )

    prompt = f"""
You are SecureDocs AI, an AI assistant
inside a private document management system.

The user is asking about document content.

Answer using the supplied document content.

IMPORTANT RULES:

1. Never answer using only a filename.
2. Never treat a filename as document content.
3. Carefully read the supplied text.
4. If the user asks what is happening,
   explain actual events, activities,
   findings, status, changes, or important
   information described in the document.
5. If a specific document is named,
   focus primarily on that document.
6. Do not invent facts.
7. Do not use outside knowledge for
   document-specific questions.
8. If information is missing, say so.
9. Give a natural useful answer.
10. Mention dates, numbers, findings,
    actions, risks, and conclusions when
    they actually appear in the content.

DOCUMENT CONTEXT:

{context}

USER QUESTION:

{query}

ANSWER:
"""

    try:

        response = (
            gemini_client
            .models
            .generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
            )
        )

        result = getattr(
            response,
            "text",
            None,
        )

        if not result:
            return None

        sources = []

        for _, d, _ in hits:

            if d.name not in sources:

                sources.append(
                    d.name
                )

        return (
            result.strip(),
            sources[:5],
        )

    except Exception as e:

        print(
            "Gemini document request failed:",
            repr(e),
        )

        return None


# ============================================================
# GEMINI GENERAL MODE
# ============================================================

def gemini_general(
    query,
):

    if not gemini_client:
        return None

    prompt = f"""
You are SecureDocs AI.

You are the general-purpose AI assistant
inside the SecureDocs application.

You can answer general questions normally.

You can:

- Have normal conversations.
- Answer casual questions.
- Explain concepts.
- Help with school and learning.
- Help with programming.
- Generate code.
- Debug code.
- Explain errors.
- Create examples.
- Help plan projects.
- Brainstorm ideas.
- Rewrite and improve text.
- Give step-by-step instructions.
- Answer how-to questions.
- Discuss technology.
- Answer questions about yourself.

IMPORTANT:

1. Answer naturally and helpfully.
2. You are NOT restricted to document questions.
3. If the user asks for code, provide useful,
   complete code when appropriate.
4. If the user asks how to do something,
   explain how to do it.
5. If the user asks "Who are you?",
   say you are SecureDocs AI.
6. Do not invent private information about
   the user.
7. If asked for the user's name and it has
   not been provided, say you don't know.
8. Do not pretend to know personal information
   that was never supplied.
9. Keep simple questions concise.
10. For complicated requests, give clear
    step-by-step help.

USER QUESTION:

{query}

ANSWER:
"""

    try:

        response = (
            gemini_client
            .models
            .generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
            )
        )

        result = getattr(
            response,
            "text",
            None,
        )

        if not result:
            return None

        return result.strip()

    except Exception as e:

        print(
            "Gemini general request failed:",
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
                "Allow": "GET, POST, PATCH, DELETE, HEAD",
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
        max_length=5000,
    )


class ProfileUpdate(BaseModel):

    full_name: str = Field(
        default="",
        max_length=150,
    )

    department: str = Field(
        default="",
        max_length=100,
    )

    job_title: str = Field(
        default="",
        max_length=100,
    )

    phone: str = Field(
        default="",
        max_length=50,
    )

    bio: str = Field(
        default="",
        max_length=2000,
    )


class SettingsUpdate(BaseModel):

    theme: str = Field(
        default="system",
        max_length=30,
    )

    notifications: bool = True


class UserRoleUpdate(BaseModel):

    role: str = Field(
        min_length=1,
        max_length=30,
    )


class UserCreate(BaseModel):

    email: str = Field(
        max_length=150
    )

    password: str = Field(
        min_length=8,
        max_length=128,
    )

    role: str = Field(
        default="visitor",
        max_length=30,
    )


class PasswordChange(BaseModel):

    current_password: str = Field(
        max_length=128
    )

    new_password: str = Field(
        min_length=8,
        max_length=128
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

    ip = (
        request.client.host
        if request.client
        else "?"
    )

    key = (
        ip,
        email,
    )

    now = time.time()

    FAILS[key] = [
        t
        for t in FAILS[key]
        if t > now - 300
    ]

    if len(
        FAILS[key]
    ) >= 5:

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

            if len(
                body.password
            ) < 8:

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
                role="visitor",
                queries=0,
                full_name="",
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

    csrf = secrets.token_urlsafe(
        24
    )

    expires = int(
        time.time()
        + SESSION_TTL
    )

    token = make_session_cookie(
        email,
        csrf,
        expires,
    )

    audit(
        db,
        request,
        email,
        "login",
        "User signed in.",
        level="info",
    )

    response = JSONResponse(
        {
            "created": created,
            "csrf": csrf,
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
    db: Session = Depends(get_db),
):

    token = request.cookies.get(
        "sid"
    )

    audit(
        db,
        request,
        u["email"],
        "logout",
        "User signed out.",
    )

    response = JSONResponse(
        {
            "ok": True
        }
    )

    response.delete_cookie(
        "sid"
    )

    return response


@app.get("/api/me")
def me(
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

    return {
        **u,
        "full_name": (
            user.full_name
            if user
            else ""
        ),
        "department": (
            user.department
            if user
            else ""
        ),
        "job_title": (
            user.job_title
            if user
            else ""
        ),
    }


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

    documents = db.query(
        Document
    ).all()

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
    request: Request,
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

    ext = Path(
        name
    ).suffix.lower()

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

    document_text = extract(
        ext,
        raw,
    )

    level = (
        3
        if (
            SENSITIVE.search(name)
            or SENSITIVE_NAME.search(name)
            or SENSITIVE.search(
                document_text[:3000]
            )
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

    chunks = chunk(
        document_text
    )

    for position, content in enumerate(
        chunks
    ):

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

    db.refresh(
        document
    )

    audit(
        db,
        request,
        u["email"],
        "upload",
        f"Uploaded document: {name}",
        document=name,
        level="info",
    )

    return meta(
        document
    )


@app.get(
    "/api/files/{doc_id}/download"
)
def download(
    doc_id: str,
    request: Request,
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

    if not d or not visible(
        u,
        d,
    ):

        raise HTTPException(
            404,
            "File not found.",
        )

    try:

        raw = dec(
            d.raw
        )

    except Exception:

        raise HTTPException(
            500,
            "Could not decrypt this document.",
        )

    audit(
        db,
        request,
        u["email"],
        "download",
        f"Downloaded document: {d.name}",
        document=d.name,
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


# ============================================================
# SEARCH
# ============================================================

@app.get("/api/search")
def search(
    q: str = "",
    u=Depends(current_user),
    db: Session = Depends(get_db),
):

    results = {}

    for score, d, content in retrieve(
        u,
        q[:300],
        db,
        30,
    ):

        results.setdefault(
            d.id,
            meta(
                d,
                snippet=content[:300],
            ),
        )

    return list(
        results.values()
    )


# ============================================================
# AI SEARCH
# ============================================================

@app.get("/api/ai-search")
def ai_search(
    q: str = "",
    u=Depends(current_user),
    db: Session = Depends(get_db),
):

    q = q.strip()

    if not q:

        return {
            "answer": "",
            "sources": [],
            "results": [],
        }

    hits = retrieve(
        u,
        q[:500],
        db,
        10,
    )

    if not hits:

        general = gemini_general(q)

        return {
            "answer": general or
            "No relevant document content was found.",
            "sources": [],
            "results": [],
        }

    ai = gemini_answer(
        q,
        hits,
    )

    results = []

    for score, d, content in hits:

        results.append(
            {
                **meta(d),
                "score": round(
                    float(score),
                    4,
                ),
                "snippet": content[:400],
            }
        )

    return {
        "answer": (
            ai[0]
            if ai
            else local_answer(
                q,
                hits,
            )[0]
        ),
        "sources": (
            ai[1]
            if ai
            else list(
                {
                    d.name
                    for _, d, _ in hits
                }
            )[:5]
        ),
        "results": results,
    }


# ============================================================
# GENERAL + DOCUMENT AI ASSISTANT
# ============================================================

@app.post("/api/chat")
def chat(
    body: ChatIn,
    request: Request,
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

    query = body.message.strip()

    if not query:

        raise HTTPException(
            400,
            "Message cannot be empty.",
        )

    low = query.lower()

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

    # ========================================================
    # GREETING
    # ========================================================

    if re.fullmatch(
        r"(hi|hello|hey)\W*",
        low,
    ):

        answer = gemini_general(
            query
        )

        return {
            "answer":
                answer
                or
                "Hello! I'm SecureDocs AI. "
                "How can I help?",
            "sources": [],
        }

    # ========================================================
    # DOCUMENT LIST
    # ========================================================

    if docs and (
        "summar" in low
        or re.search(
            r"\b(list|which|what)\b.*"
            r"\b(documents|files)\b",
            low,
        )
    ):

        lines = []

        for d in docs[:10]:

            preview = ""

            if d.chunks:

                try:

                    preview = dec(
                        d.chunks[0].data
                    ).decode(
                        "utf-8",
                        "replace",
                    )[:180]

                except Exception:

                    preview = ""

            lines.append(
                f"{d.name}: {preview}..."
            )

        return {
            "answer":
                f"You have {len(docs)} "
                "document(s) available.\n\n"
                + "\n".join(lines),

            "sources": [
                d.name
                for d in docs[:10]
            ],
        }

    # ========================================================
    # DOCUMENT RETRIEVAL
    # ========================================================

    hits = retrieve(
        u,
        query,
        db,
        8,
    )

    # ========================================================
    # DOCUMENT MODE
    # ========================================================

    if hits:

        ai_result = gemini_answer(
            query,
            hits,
        )

        if ai_result:

            answer_text, sources = ai_result

            audit(
                db,
                request,
                u["email"],
                "ai",
                "AI document question answered.",
                document=", ".join(
                    sources[:3]
                ),
            )

            return {
                "answer": answer_text,
                "sources": sources,
            }

        answer_text, sources = local_answer(
            query,
            hits,
        )

        if answer_text:

            return {
                "answer": answer_text,
                "sources": sources,
            }

        named = find_named_documents(
            u,
            query,
            db,
        )

        if named:

            previews = []

            for d in named:

                for c in d.chunks[:3]:

                    try:

                        content = dec(
                            c.data
                        ).decode(
                            "utf-8",
                            "replace",
                        ).strip()

                        if content:

                            previews.append(
                                content[:700]
                            )

                    except Exception:

                        continue

            if previews:

                return {
                    "answer":
                        "Here is the relevant "
                        "content I found in "
                        + named[0].name
                        + ":\n\n"
                        + "\n\n".join(
                            previews
                        ),
                    "sources": [
                        d.name
                        for d in named
                    ],
                }

    # ========================================================
    # GENERAL GEMINI MODE
    # ========================================================

    general = gemini_general(
        query
    )

    if general:

        audit(
            db,
            request,
            u["email"],
            "ai",
            "AI general question answered.",
        )

        return {
            "answer": general,
            "sources": [],
        }

    # ========================================================
    # FINAL FALLBACK
    # ========================================================

    return {
        "answer":
            "The AI assistant is temporarily "
            "unavailable. Please try again.",
        "sources": [],
    }


# ============================================================
# PROFILE API
# ============================================================

@app.get("/api/profile")
def get_profile(
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

    if not user:

        raise HTTPException(
            404,
            "User not found.",
        )

    return {
        "id": user.id,
        "email": user.email,
        "role": user.role,
        "full_name": user.full_name or "",
        "department": user.department or "",
        "job_title": user.job_title or "",
        "phone": user.phone or "",
        "bio": user.bio or "",
        "queries": user.queries or 0,
    }


@app.put("/api/profile")
def update_profile(
    body: ProfileUpdate,
    request: Request,
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

    if not user:

        raise HTTPException(
            404,
            "User not found.",
        )

    user.full_name = body.full_name.strip()
    user.department = body.department.strip()
    user.job_title = body.job_title.strip()
    user.phone = body.phone.strip()
    user.bio = body.bio.strip()

    db.commit()

    audit(
        db,
        request,
        u["email"],
        "profile",
        "Profile information updated.",
    )

    return {
        "ok": True,
        "profile": {
            "email": user.email,
            "full_name": user.full_name,
            "department": user.department,
            "job_title": user.job_title,
            "phone": user.phone,
            "bio": user.bio,
        },
    }


@app.post("/api/profile/password")
def change_password(
    body: PasswordChange,
    request: Request,
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

    if not user:

        raise HTTPException(
            404,
            "User not found.",
        )

    if not check_pw(
        body.current_password,
        user.pw,
    ):

        audit(
            db,
            request,
            u["email"],
            "warning",
            "Failed password change attempt.",
            level="warning",
        )

        raise HTTPException(
            401,
            "Current password is incorrect.",
        )

    user.pw = hash_pw(
        body.new_password
    )

    db.commit()

    audit(
        db,
        request,
        u["email"],
        "security",
        "Password changed.",
    )

    return {
        "ok": True
    }


# ============================================================
# SETTINGS API
# ============================================================

@app.get("/api/settings")
def get_settings(
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

    if not user:

        raise HTTPException(
            404,
            "User not found.",
        )

    return {
        "theme": user.theme or "system",
        "notifications": bool(
            user.notifications
        ),
    }


@app.put("/api/settings")
def update_settings(
    body: SettingsUpdate,
    request: Request,
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

    if not user:

        raise HTTPException(
            404,
            "User not found.",
        )

    allowed_themes = {
        "system",
        "light",
        "dark",
    }

    if body.theme not in allowed_themes:

        raise HTTPException(
            400,
            "Invalid theme.",
        )

    user.theme = body.theme

    user.notifications = (
        1
        if body.notifications
        else 0
    )

    db.commit()

    audit(
        db,
        request,
        u["email"],
        "settings",
        "Account settings updated.",
    )

    return {
        "ok": True,
        "theme": user.theme,
        "notifications": bool(
            user.notifications
        ),
    }


# ============================================================
# ADMIN — USERS
# ============================================================

@app.get("/api/users")
def users(
    u=Depends(current_user),
    db: Session = Depends(get_db),
):

    require_admin(u)

    all_users = (
        db.query(User)
        .order_by(
            User.id.asc()
        )
        .all()
    )

    return [
        {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name or "",
            "department": user.department or "",
            "job_title": user.job_title or "",
            "role": user.role,
            "queries": user.queries or 0,
            "documents": len(
                user.documents
            ),
        }
        for user in all_users
    ]


@app.post("/api/users")
def create_user(
    body: UserCreate,
    request: Request,
    u=Depends(current_user),
    db: Session = Depends(get_db),
):

    require_admin(u)

    email = (
        body.email
        .strip()
        .lower()
    )

    if not EMAIL.match(email):

        raise HTTPException(
            400,
            "Invalid email address.",
        )

    if body.role not in {
        "admin",
        "executive",
        "visitor",
    }:

        raise HTTPException(
            400,
            "Invalid role.",
        )

    existing = (
        db.query(User)
        .filter(
            User.email == email
        )
        .first()
    )

    if existing:

        raise HTTPException(
            409,
            "User already exists.",
        )

    user = User(
        email=email,
        pw=hash_pw(
            body.password
        ),
        role=body.role,
        queries=0,
        full_name="",
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    audit(
        db,
        request,
        u["email"],
        "permission",
        f"Created user {email}.",
        level="info",
    )

    return {
        "id": user.id,
        "email": user.email,
        "role": user.role,
    }


@app.patch("/api/users/{user_id}/role")
def update_user_role(
    user_id: int,
    body: UserRoleUpdate,
    request: Request,
    u=Depends(current_user),
    db: Session = Depends(get_db),
):

    require_admin(u)

    if body.role not in {
        "admin",
        "executive",
        "visitor",
    }:

        raise HTTPException(
            400,
            "Invalid role.",
        )

    user = (
        db.query(User)
        .filter(
            User.id == user_id
        )
        .first()
    )

    if not user:

        raise HTTPException(
            404,
            "User not found.",
        )

    old_role = user.role

    user.role = body.role

    db.commit()

    audit(
        db,
        request,
        u["email"],
        "permission",
        (
            f"Changed {user.email} "
            f"from {old_role} "
            f"to {body.role}."
        ),
        level="info",
    )

    return {
        "ok": True,
        "id": user.id,
        "role": user.role,
    }


@app.delete("/api/users/{user_id}")
def delete_user(
    user_id: int,
    request: Request,
    u=Depends(current_user),
    db: Session = Depends(get_db),
):

    require_admin(u)

    user = (
        db.query(User)
        .filter(
            User.id == user_id
        )
        .first()
    )

    if not user:

        raise HTTPException(
            404,
            "User not found.",
        )

    if user.email == ADMIN_EMAIL:

        raise HTTPException(
            400,
            "The primary administrator cannot be deleted.",
        )

    email = user.email

    db.delete(user)
    db.commit()

    audit(
        db,
        request,
        u["email"],
        "permission",
        f"Deleted user {email}.",
        level="warning",
    )

    return {
        "ok": True
    }


# ============================================================
# ROLES & PERMISSIONS
# ============================================================

ROLE_PERMISSIONS = {

    "admin": [
        "View all documents",
        "Upload documents",
        "Download documents",
        "Use AI assistant",
        "Use AI search",
        "Manage users",
        "Manage roles",
        "View audit logs",
        "Manage settings",
        "Manage profiles",
    ],

    "executive": [
        "View accessible documents",
        "Upload documents",
        "Download documents",
        "Use AI assistant",
        "Use AI search",
        "View own profile",
    ],

    "visitor": [
        "View accessible documents",
        "Upload documents",
        "Download documents",
        "Use AI assistant",
        "Use AI search",
    ],

}


@app.get("/api/roles")
def roles(
    u=Depends(current_user),
):

    require_admin(u)

    return [
        {
            "name": name,
            "permissions": permissions,
        }
        for name, permissions
        in ROLE_PERMISSIONS.items()
    ]


@app.get("/api/roles/{role_name}")
def role_detail(
    role_name: str,
    u=Depends(current_user),
):

    require_admin(u)

    if role_name not in ROLE_PERMISSIONS:

        raise HTTPException(
            404,
            "Role not found.",
        )

    return {
        "name": role_name,
        "permissions":
            ROLE_PERMISSIONS[
                role_name
            ],
    }


# ============================================================
# AUDIT LOG API
# ============================================================

@app.get("/api/audit")
def audit_logs(
    q: str = "",
    action: str = "all",
    limit: int = 100,
    offset: int = 0,
    u=Depends(current_user),
    db: Session = Depends(get_db),
):

    require_admin(u)

    limit = max(
        1,
        min(limit, 500),
    )

    offset = max(
        0,
        offset,
    )

    query = (
        db.query(AuditLog)
        .order_by(
            AuditLog.ts.desc()
        )
    )

    if q.strip():

        term = (
            "%"
            + q.strip()
            + "%"
        )

        query = query.filter(
            (
                AuditLog.user_email.ilike(term)
                | AuditLog.description.ilike(term)
                | AuditLog.document.ilike(term)
                | AuditLog.ip.ilike(term)
            )
        )

    if action.lower() != "all":

        query = query.filter(
            AuditLog.action
            == action.lower()
        )

    total = query.count()

    logs = (
        query
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "total": total,
        "logs": [
            {
                "id": log.id,
                "ts": log.ts,
                "user": log.user_email,
                "email": log.user_email,
                "action": log.action,
                "description":
                    log.description,
                "document":
                    log.document,
                "ip": log.ip,
                "level": log.level,
            }
            for log in logs
        ],
    }


@app.get("/api/audit/stats")
def audit_stats(
    u=Depends(current_user),
    db: Session = Depends(get_db),
):

    require_admin(u)

    logs = (
        db.query(AuditLog)
        .all()
    )

    counts = Counter(
        x.action
        for x in logs
    )

    return {
        "total": len(logs),
        "login": counts["login"],
        "upload": counts["upload"],
        "ai": counts["ai"],
        "permission":
            counts["permission"],
        "warning":
            counts["warning"],
        "security":
            counts["security"],
    }


# ============================================================
# AUDIT CSV
# ============================================================

@app.get("/api/audit/export")
def audit_export(
    u=Depends(current_user),
    db: Session = Depends(get_db),
):

    require_admin(u)

    logs = (
        db.query(AuditLog)
        .order_by(
            AuditLog.ts.desc()
        )
        .all()
    )

    lines = [
        "timestamp,user,action,description,document,ip,level"
    ]

    for log in logs:

        values = [
            time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.localtime(
                    log.ts
                ),
            ),
            log.user_email,
            log.action,
            log.description,
            log.document,
            log.ip,
            log.level,
        ]

        escaped = []

        for value in values:

            value = str(
                value or ""
            ).replace(
                '"',
                '""',
            )

            escaped.append(
                '"' + value + '"'
            )

        lines.append(
            ",".join(
                escaped
            )
        )

    content = (
        "\n".join(lines)
        + "\n"
    )

    return Response(
        content,
        media_type="text/csv",
        headers={
            "Content-Disposition":
                "attachment; "
                'filename="securedocs-audit.csv"'
        },
    )


# ============================================================
# FRONTEND PAGE ACCESS
# ============================================================

PROTECTED = {
    "dashboard",
    "documents",
    "assistant",
    "search",
    "users",
    "roles",
    "audit",
    "settings",
    "profile",
}

PUBLIC = {
    "index",
    "login",
}


# ============================================================
# ROLE PAGE ACCESS
# ============================================================

PAGE_ACCESS = {

    # 9 pages
    "admin": {
        "dashboard",
        "documents",
        "assistant",
        "search",
        "users",
        "roles",
        "audit",
        "settings",
        "profile",
    },

    # 5 pages
    "executive": {
        "dashboard",
        "documents",
        "assistant",
        "search",
        "profile",
    },

    # 4 pages
    "visitor": {
        "dashboard",
        "documents",
        "assistant",
        "search",
    },

}


# ============================================================
# FRONTEND CONNECTOR
# ============================================================

COMMON = r"""
/*
 * SecureDocs common frontend connector.
 *
 * Everything is attached to window instead of declaring
 * global const/let variables. This prevents collisions
 * with the JavaScript already inside the new HTML pages.
 */

window.$ = window.$ || function(s){
    return document.querySelector(s);
};

window.CSRF = "";
window.ME = null;

window.mk = function(t,c,x){

    const e = document.createElement(t);

    if(c)
        e.className = c;

    if(x != null)
        e.textContent = x;

    return e;
};


window.api = async function(p,o={}){

    o.headers = Object.assign(
        {
            "X-CSRF": window.CSRF
        },
        o.headers || {}
    );

    const r = await fetch(
        p,
        Object.assign(
            {
                credentials:"same-origin"
            },
            o
        )
    );

    if(r.status === 401){

        location.href =
            "/login.html";

        throw new Error(
            "Please sign in."
        );
    }

    if(r.status === 403){

        throw new Error(
            "You do not have permission to perform this action."
        );
    }

    if(!r.ok){

        let m =
            "Something went wrong.";

        try{

            const j =
                await r.json();

            if(
                typeof j.detail === "string"
            ){
                m = j.detail;
            }

        }catch(e){}

        throw new Error(m);
    }

    return r;
};


window.fmt = function(b){

    return b < 1024
        ? b + " B"
        : b < 1048576
            ? (b / 1024).toFixed(1) + " KB"
            : (b / 1048576).toFixed(1) + " MB";
};


window.ago = function(t){

    const s = Math.max(
        0,
        Date.now() / 1000 - t
    );

    if(s < 60)
        return "Just now";

    if(s < 3600)
        return Math.floor(
            s / 60
        ) + " minutes ago";

    if(s < 86400)
        return Math.floor(
            s / 3600
        ) + " hours ago";

    return Math.floor(
        s / 86400
    ) + " days ago";
};


window.docRow = function(d,extra){

    const r = window.mk(
        "div",
        "document"
    );

    const l = window.mk(
        "div",
        "doc-left"
    );

    const w = window.mk(
        "div"
    );

    l.append(
        window.mk(
            "div",
            "doc-icon",
            d.ext
        )
    );

    w.append(
        window.mk(
            "div",
            "doc-name",
            d.name
        ),

        window.mk(
            "div",
            "doc-meta",
            window.fmt(d.size)
            + " · "
            + window.ago(d.ts)
            + (
                extra
                    ? " · " + extra
                    : ""
            )
        )
    );

    l.append(w);

    r.append(
        l,

        window.mk(
            "div",
            "status",
            d.restricted
                ? "Restricted"
                : "Indexed"
        )
    );

    r.title =
        "Click to download";

    r.style.cursor =
        "pointer";

    r.onclick = () => {

        location.href =
            "/api/files/"
            + d.id
            + "/download";

    };

    return r;
};


window.ready = fetch(
    "/api/me",
    {
        credentials:
            "same-origin"
    }
)
.then(r => {

    if(!r.ok){

        location.href =
            "login.html";

        throw 0;
    }

    return r.json();

})
.then(d => {

    window.ME = d;
    window.CSRF = d.csrf;

    const avatar =
        window.$(".avatar");

    if(avatar)
        avatar.textContent =
            d.email
                .slice(0,2)
                .toUpperCase();

    const strong =
        window.$(
            ".user-info strong"
        );

    if(strong)
        strong.textContent =
            d.full_name
            ||
            d.email.split("@")[0];

    const span =
        window.$(
            ".user-info span"
        );

    if(span){

        if(d.role === "admin"){

            span.textContent =
                "Administrator";

        }else if(
            d.role === "executive"
        ){

            span.textContent =
                "Executive";

        }else if(
            d.role === "visitor"
        ){

            span.textContent =
                "Visitor";

        }else{

            span.textContent =
                "Secure account";
        }
    }

    const m =
        window.$(".user-mini");

    if(m){

        m.style.cursor =
            "pointer";

        m.title =
            "Click to sign out";

        m.onclick = async () => {

            if(confirm("Sign out?")){

                await window.api(
                    "/api/logout",
                    {
                        method:"POST"
                    }
                );

                location.href =
                    "login.html";
            }
        };
    }

});
"""


# ============================================================
# EXISTING PAGE JAVASCRIPT
# ============================================================

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
                    "/dashboard.html";
            },
            j.created
                ?900
                :200
        );

    }catch(x){

        note(
            x.message
            ||
            "Could not sign in."
        );
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
            go(e);

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

    await window.ready;

    const f =
        await(
            await window.api(
                "/api/files"
            )
        ).json();

    const s =
        await(
            await window.api(
                "/api/stats"
            )
        ).json();

    const h =
        document.querySelectorAll(
            ".stat-card h2"
        );

    if(h[0])
        h[0].textContent=s.total;

    if(h[1])
        h[1].textContent=s.indexed;

    if(h[2])
        h[2].textContent=s.queries;

    const p =
        document.querySelector(
            ".content-grid .panel"
        );

    if(!p)
        return;

    const link =
        p.querySelector(
            ".panel-header a"
        );

    if(link)
        link.href =
            "documents.html";

    p.querySelectorAll(
        ".document"
    ).forEach(
        x=>x.remove()
    );

    if(!f.length){

        const e =
            window.mk(
                "div",
                "document"
            );

        e.append(
            window.mk(
                "div",
                "doc-meta",
                "No documents yet. "
                +"Upload your first one."
            )
        );

        p.append(e);
    }

    f.slice(0,3).forEach(
        d=>p.append(
            window.docRow(d)
        )
    );

})();
""",


"documents": r"""
const list =
    window.$(".documents");

let ALL=[];

function draw(items){

    if(!list)
        return;

    list.replaceChildren();

    if(!items.length){

        const e =
            window.mk(
                "div",
                "document"
            );

        e.append(
            window.mk(
                "div",
                "doc-meta",
                "No documents found."
            )
        );

        list.append(e);

        return;
    }

    items.forEach(
        d=>list.append(
            window.docRow(
                d,
                d.snippet
            )
        )
    );
}

async function load(){

    await window.ready;

    ALL =
        await(
            await window.api(
                "/api/files"
            )
        ).json();

    draw(ALL);
}

async function send(files){

    await window.ready;

    for(
        const f of files
    ){

        const t =
            window.mk(
                "div",
                "document"
            );

        const l =
            window.mk(
                "div",
                "doc-left"
            );

        const w =
            window.mk(
                "div"
            );

        l.append(
            window.mk(
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
            window.mk(
                "div",
                "doc-name",
                f.name
            ),

            window.mk(
                "div",
                "doc-meta",
                window.fmt(f.size)
                +" · Uploading..."
            )
        );

        l.append(w);

        t.append(
            l,

            window.mk(
                "div",
                "status",
                "Uploading"
            )
        );

        list.prepend(t);

        try{

            const fd =
                new FormData();

            fd.append(
                "file",
                f
            );

            await window.api(
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
            );
        }
    }

    load();
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

        send(fs);

    },
    true
);

const z =
    window.$(".upload-zone");

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
            ]);

        }
    );
}

let timer;

const searchBox =
    window.$(".search");

if(searchBox){

    searchBox.addEventListener(
        "input",
        e=>{

            clearTimeout(timer);

            const v =
                e.target.value.trim();

            timer=setTimeout(
                async()=>{

                    if(!v){

                        draw(ALL);

                        return;
                    }

                    await window.ready;

                    try{

                        draw(
                            await(
                                await window.api(
                                    "/api/search?q="
                                    +encodeURIComponent(v)
                                )
                            ).json()
                        );

                    }catch(x){}
                },
                250
            );
        }
    );
}

load();
""",


"assistant": r"""
const msgs =
    window.$("#messages");

window.ready.then(()=>{

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
    );
});

function add(
    cls,
    text,
    src
){

    if(!msgs)
        return;

    const m =
        window.mk(
            "div",
            "message "+cls
        );

    const b =
        window.mk(
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
            window.mk(
                "div",
                "source",
                "Source · "
                +src.join(" · ")
            )
        );
    }

    m.append(b);

    msgs.append(m);

    msgs.scrollTop =
        msgs.scrollHeight;
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

        const i =
            window.$("#chatInput");

        if(!i)
            return;

        const t =
            i.value.trim();

        if(!t)
            return;

        i.value="";

        add(
            "user",
            t
        );

        try{

            await window.ready;

            const response =
                await window.api(
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

            const j =
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
            );
        }

    },
    true
);
""",

}


# ============================================================
# PAGE LOADING
# ============================================================

ALLOWED_PAGES = {
    "index",
    "login",
    "dashboard",
    "documents",
    "assistant",
    "search",
    "users",
    "roles",
    "audit",
    "settings",
    "profile",
}


def find_page_file(name: str):

    if name not in ALLOWED_PAGES:
        return None

    filename = f"{name}.html"

    candidates = [

        BASE / "pages" / filename,

        BASE / filename,

        BASE / "DocumentManager" / "pages" / filename,

        BASE / "DocumentManager" / filename,

        BASE.parent / "pages" / filename,

        BASE.parent / filename,

        BASE.parent / "DocumentManager" / "pages" / filename,

        BASE.parent / "DocumentManager" / filename,

    ]

    for path in candidates:

        try:

            if path.is_file():
                return path

        except Exception:

            continue

    search_roots = [
        BASE,
        BASE.parent,
    ]

    for root in search_roots:

        try:

            for path in root.rglob(filename):

                if path.is_file():
                    return path

        except Exception:

            continue

    return None


def load_page(name: str):

    if name not in ALLOWED_PAGES:

        raise HTTPException(
            404,
            "Page not found.",
        )

    page_path = find_page_file(
        name
    )

    if page_path is None:

        return HTMLResponse(
            f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>SecureDocs</title>

                <style>

                    body {{
                        font-family:
                            Arial,
                            sans-serif;

                        background:#0b0d10;

                        color:white;

                        display:flex;

                        align-items:center;

                        justify-content:center;

                        min-height:100vh;

                        margin:0;
                    }}

                    .box {{
                        max-width:650px;

                        padding:40px;

                        text-align:center;
                    }}

                    h1 {{
                        margin-bottom:12px;
                    }}

                    p {{
                        color:#aaa;

                        line-height:1.6;
                    }}

                    code {{
                        color:#fff;
                    }}

                </style>

            </head>

            <body>

                <div class="box">

                    <h1>
                        SecureDocs
                    </h1>

                    <p>
                        The page
                        <code>{name}.html</code>
                        could not be found on the server.
                    </p>

                    <p>
                        Make sure the HTML file is included
                        in the deployed project.
                    </p>

                </div>

            </body>

            </html>
            """,
            status_code=500,
        )

    try:

        html = page_path.read_text(
            encoding="utf-8"
        )

    except Exception as e:

        print(
            "Could not read page:",
            page_path,
            repr(e),
        )

        return HTMLResponse(
            "<h2>Could not load page.</h2>",
            status_code=500,
        )

    js = PAGE_JS.get(
        name,
        "",
    )

    if name in PROTECTED:

        js = (
            COMMON
            + "\n"
            + js
        )

    if js.strip():

        script = (
            "\n<script>\n"
            + js
            + "\n</script>\n"
        )

        lower_html = html.lower()

        body_position = lower_html.rfind(
            "</body>"
        )

        if body_position != -1:

            html = (
                html[:body_position]
                + script
                + html[body_position:]
            )

        else:

            html += script

    return HTMLResponse(
        content=html,
        media_type="text/html",
    )


# ============================================================
# PAGE ACCESS CHECK
# ============================================================

def page_allowed(
    name,
    user,
):

    if name not in PROTECTED:
        return True

    role = user.get(
        "role",
        "visitor",
    )

    allowed = PAGE_ACCESS.get(
        role,
        set(),
    )

    return name in allowed


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():

    return load_page(
        "index"
    )


# ============================================================
# NORMAL PAGE ROUTES
# ============================================================

@app.get("/{name}.html")
def page(
    name: str,
    request: Request,
):

    if name not in ALLOWED_PAGES:

        raise HTTPException(
            404,
            "Not found",
        )

    if name in PUBLIC:

        return load_page(
            name
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

        # ====================================================
        # ROLE-BASED PAGE ACCESS
        # ====================================================

        if not page_allowed(
            name,
            user,
        ):

            return RedirectResponse(
                "/dashboard.html",
                status_code=303,
            )

    return load_page(
        name
    )


# ============================================================
# /pages/*.html ROUTES
# ============================================================

@app.get("/pages/{name}.html")
def page_from_pages_folder(
    name: str,
    request: Request,
):

    if name not in ALLOWED_PAGES:

        raise HTTPException(
            404,
            "Not found",
        )

    if name in PUBLIC:

        return load_page(
            name
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

        # ====================================================
        # ROLE-BASED PAGE ACCESS
        # ====================================================

        if not page_allowed(
            name,
            user,
        ):

            return RedirectResponse(
                "/dashboard.html",
                status_code=303,
            )

    return load_page(
        name
    )
