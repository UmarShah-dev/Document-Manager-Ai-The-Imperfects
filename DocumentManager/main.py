"""
SecureDocs - AI-Powered Secure Document Search Portal  (FastAPI backend)

Put these 5 files (UNCHANGED) next to main.py, or inside a folder called "pages":
    index.html  login.html  dashboard.html  documents.html  assistant.html
Install : python -m pip install fastapi uvicorn python-multipart cryptography   (+ pypdf for PDF files)
Run     : python -m uvicorn main:app --reload      ->  http://127.0.0.1:8000

Your HTML files are served exactly as they are (same look). This file only adds a small script
at the bottom of each page that connects it to the real backend.
Data lives in memory: it is wiped when the server stops or reloads (as requested).
"""
import hashlib, hmac, io, math, os, re, secrets, time, uuid, zipfile
from collections import Counter, defaultdict
from html import unescape
from pathlib import Path
from threading import Lock
from urllib.parse import quote

from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

BASE = Path(__file__).resolve().parent
MAX_BYTES, SESSION_TTL = 5 * 1024 * 1024, 8 * 3600
EXTS = {".txt", ".md", ".csv", ".pdf", ".docx"}
SECURE = os.getenv("HTTPS") == "1"
# Files whose name/content match these are "Restricted": only admins (and the uploader) can see them.
SENSITIVE = re.compile(r"salar|payroll|confidential|secret|restricted", re.I)
SENSITIVE_NAME = re.compile(r"admin", re.I)

# ---------------- in-memory storage + encryption ----------------
FERNET = Fernet(Fernet.generate_key())  # new key every start; data is in memory anyway
enc, dec = FERNET.encrypt, FERNET.decrypt
LOCK = Lock()
USERS, SESSIONS, DOCS = {}, {}, {}
QUERIES, FAILS = Counter(), defaultdict(list)

def hash_pw(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    return salt.hex() + "$" + hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1).hex()

def check_pw(pw, stored):
    salt, h = stored.split("$")
    return hmac.compare_digest(hash_pw(pw, bytes.fromhex(salt)).split("$")[1], h)

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@securedocs.com")
ADMIN_PW = os.getenv("ADMIN_PASSWORD") or secrets.token_urlsafe(9)
USERS[ADMIN_EMAIL] = {"pw": hash_pw(ADMIN_PW), "role": "admin"}
print(f"\n  Admin login (sees restricted files):  {ADMIN_EMAIL}  /  {ADMIN_PW}\n")

# ---------------- auth ----------------
EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,120}\.[^@\s]{2,}$")

def get_user(request: Request):
    tok = request.cookies.get("sid")
    s = tok and SESSIONS.get(hashlib.sha256(tok.encode()).hexdigest())
    if not s or s["exp"] < time.time() or s["email"] not in USERS:
        return None
    return {"email": s["email"], "role": USERS[s["email"]]["role"], "csrf": s["csrf"]}

def current_user(request: Request):
    u = get_user(request)
    if not u:
        raise HTTPException(401, "Please sign in.")
    if request.method not in ("GET", "HEAD") and not hmac.compare_digest(request.headers.get("x-csrf", ""), u["csrf"]):
        raise HTTPException(403, "Security check failed. Reload the page.")
    return u

# ---------------- text processing / small search "AI" ----------------
STOP = set("a an the and or of to in on for is are was were be it this that with as at by from what who how when which do does can i you we my our your about me tell".split())
def tok(s):
    ws = [w for w in re.findall(r"[a-z0-9]+", s.lower()) if w not in STOP]
    return [w[:-1] if len(w) > 3 and w.endswith("s") else w for w in ws]

def extract(ext, raw):
    try:
        if ext == ".pdf":
            if not raw.startswith(b"%PDF"): raise ValueError
            from pypdf import PdfReader
            text = "\n".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(raw)).pages)
        elif ext == ".docx":
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                if z.getinfo("word/document.xml").file_size > 20_000_000: raise ValueError
                xml = z.read("word/document.xml").decode("utf-8", "replace")
            text = unescape(re.sub(r"<[^>]+>", "", xml.replace("</w:p>", "\n")))
        else:
            text = raw.decode("utf-8", "replace")
    except ImportError:
        raise HTTPException(400, "PDF support needs:  python -m pip install pypdf")
    except Exception:
        raise HTTPException(400, "Could not read this file. (Old .doc files: save as .docx first.)")
    if not text.strip():
        raise HTTPException(400, "No readable text found in this file.")
    return text

def chunk(text, size=500):
    out, cur = [], ""
    for part in re.split(r"\n\s*\n|(?<=[.!?])\s+", text):
        if len(cur) + len(part) > size and cur: out.append(cur.strip()); cur = ""
        cur += part.strip() + " "
    return out + [cur.strip()] if cur.strip() else out

def visible(u, d):  # role-based access
    return u["role"] == "admin" or d["level"] == 1 or d["owner"] == u["email"]

def meta(d, **kw):
    return {"id": d["id"], "name": d["name"], "ext": d["ext"], "size": d["size"], "ts": d["ts"], "restricted": d["level"] > 1, **kw}

def retrieve(u, query, k=6):
    pool = [(d, t) for d in list(DOCS.values()) if visible(u, d) for t in [d["name"]] + [dec(c).decode() for c in d["chunks"]]]
    qt = set(tok(query))
    if not pool or not qt: return []
    toks = [Counter(tok(t)) for _, t in pool]
    df = Counter(w for c in toks for w in c if w in qt)
    scored = []
    for (d, t), tf in zip(pool, toks):
        s = sum((1 + math.log(tf[w])) * math.log(1 + len(pool) / df[w]) for w in qt if tf[w])
        if s > 0: scored.append((s, d, t))
    scored.sort(key=lambda x: -x[0])
    return scored[:k]

def answer(query, hits):
    """Tiny rule-based 'AI': answers ONLY with sentences found in the user's own documents."""
    qt, found = set(tok(query)), []
    for s, d, t in hits:
        for sent in re.split(r"(?<=[.!?])\s+|\n", t):
            ov = len(qt & set(tok(sent)))
            if ov and len(sent) > 15: found.append((ov, s, sent.strip(), d["name"]))
    found.sort(key=lambda x: (-x[0], -x[1]))
    seen, best, srcs = set(), [], []
    for _, _, sent, name in found:
        if sent in seen: continue
        seen.add(sent); best.append(sent)
        if name not in srcs: srcs.append(name)
        if len(best) == 3: break
    return " ".join(best), srcs

# ---------------- app ----------------
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(","))

CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")

@app.middleware("http")
async def secure_headers(request: Request, call_next):
    r = await call_next(request)
    r.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                      "Cache-Control": "no-store", "Content-Security-Policy": CSP,
                      "Permissions-Policy": "camera=(), microphone=(), geolocation=()"})
    if SECURE: r.headers["Strict-Transport-Security"] = "max-age=31536000"
    return r

class AuthIn(BaseModel):
    email: str = Field(max_length=150)
    password: str = Field(max_length=128)

class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=500)

@app.post("/api/auth")
def auth(body: AuthIn, request: Request):
    """Sign in. If the email is new, an account is created (sign up) and the email is stored."""
    email = body.email.strip().lower()
    if not EMAIL.match(email): raise HTTPException(400, "Enter a valid email address.")
    key = (request.client.host if request.client else "?", email)
    FAILS[key] = [t for t in FAILS[key] if t > time.time() - 300]
    if len(FAILS[key]) >= 5: raise HTTPException(429, "Too many attempts. Try again in 5 minutes.")
    created = False
    with LOCK:
        user = USERS.get(email)
        if user is None:
            if len(body.password) < 8: raise HTTPException(400, "New accounts need a password of at least 8 characters.")
            USERS[email] = {"pw": hash_pw(body.password), "role": "employee"}; created = True
        elif not check_pw(body.password, user["pw"]):
            FAILS[key].append(time.time())
            raise HTTPException(401, "Incorrect email or password.")
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    for h in [h for h, s in SESSIONS.items() if s["exp"] < time.time()]: SESSIONS.pop(h, None)
    SESSIONS[hashlib.sha256(token.encode()).hexdigest()] = {"email": email, "csrf": csrf, "exp": time.time() + SESSION_TTL}
    resp = JSONResponse({"created": created})
    resp.set_cookie("sid", token, max_age=SESSION_TTL, httponly=True, samesite="strict", secure=SECURE)
    return resp

@app.post("/api/logout")
def logout(request: Request, u=Depends(current_user)):
    SESSIONS.pop(hashlib.sha256(request.cookies["sid"].encode()).hexdigest(), None)
    resp = JSONResponse({"ok": True}); resp.delete_cookie("sid"); return resp

@app.get("/api/me")
def me(u=Depends(current_user)):
    return u

@app.get("/api/files")
def files(u=Depends(current_user)):
    return [meta(d) for d in sorted(DOCS.values(), key=lambda d: -d["ts"]) if visible(u, d)]

@app.get("/api/stats")
def stats(u=Depends(current_user)):
    n = sum(1 for d in DOCS.values() if visible(u, d))
    return {"total": n, "indexed": n, "queries": QUERIES[u["email"]]}

@app.post("/api/upload")
async def upload(file: UploadFile = File(...), u=Depends(current_user)):
    name = re.sub(r"[^\w.\- ]", "_", os.path.basename(file.filename or "file"))[:100]
    ext = Path(name).suffix.lower()
    if ext not in EXTS: raise HTTPException(400, "Supported types: " + ", ".join(sorted(EXTS)))
    raw = await file.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES: raise HTTPException(413, "File is larger than 5 MB.")
    if not raw: raise HTTPException(400, "File is empty.")
    text = extract(ext, raw)
    level = 3 if (SENSITIVE.search(name) or SENSITIVE_NAME.search(name) or SENSITIVE.search(text[:3000])) else 1
    doc_id = uuid.uuid4().hex
    DOCS[doc_id] = {"id": doc_id, "name": name, "ext": ext[1:].upper(), "owner": u["email"], "level": level,
                    "size": len(raw), "ts": time.time(), "raw": enc(raw), "chunks": [enc(c.encode()) for c in chunk(text)]}
    return meta(DOCS[doc_id])

@app.get("/api/files/{doc_id}/download")
def download(doc_id: str, u=Depends(current_user)):
    d = DOCS.get(doc_id)
    if not d or not visible(u, d): raise HTTPException(404, "File not found.")  # hide that secret files exist
    return Response(dec(d["raw"]), media_type="application/octet-stream",
                    headers={"Content-Disposition": "attachment; filename*=UTF-8''" + quote(d["name"])})

@app.get("/api/search")
def search(q: str = "", u=Depends(current_user)):
    out = {}
    for s, d, t in retrieve(u, q[:200], 30):
        out.setdefault(d["id"], meta(d, snippet=(t if t != d["name"] else "Name match")[:100]))
    return list(out.values())

@app.post("/api/chat")
def chat(body: ChatIn, u=Depends(current_user)):
    QUERIES[u["email"]] += 1
    low = body.message.strip().lower()
    docs = sorted((d for d in DOCS.values() if visible(u, d)), key=lambda d: -d["ts"])
    if re.fullmatch(r"(hi|hello|hey)\W*", low):
        return {"answer": "Hello! Ask me anything about the documents in your workspace.", "sources": []}
    if not docs:
        return {"answer": "There are no documents yet. Upload some on the Documents page first.", "sources": []}
    if "summar" in low or re.search(r"\b(list|which|what)\b.*\b(documents|files)\b", low):
        lines = [f"{d['name']}: {dec(d['chunks'][0]).decode()[:110]}..." for d in docs[:6]]
        return {"answer": f"You have {len(docs)} document(s). " + "  ".join(lines), "sources": [d["name"] for d in docs[:6]]}
    ans, srcs = answer(body.message, retrieve(u, body.message, 5))
    if not ans:
        return {"answer": "I couldn't find that in the documents you have access to.", "sources": []}
    return {"answer": ans, "sources": srcs}

# ---------------- pages: your HTML files, served untouched + a small connector script ----------------
PROTECTED = {"dashboard", "documents", "assistant"}
PUBLIC = {"index", "login"}

COMMON = r"""
const $=s=>document.querySelector(s);let CSRF="",ME=null;
const mk=(t,c,x)=>{const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e};
async function api(p,o={}){o.headers=Object.assign({"X-CSRF":CSRF},o.headers||{});
 const r=await fetch(p,Object.assign({credentials:"same-origin"},o));
 if(r.status===401){location.href="login.html";throw new Error("Please sign in.")}
 if(!r.ok){let m="Something went wrong.";try{const j=await r.json();if(typeof j.detail==="string")m=j.detail}catch(e){}throw new Error(m)}
 return r}
const fmt=b=>b<1024?b+" B":b<1048576?(b/1024).toFixed(1)+" KB":(b/1048576).toFixed(1)+" MB";
function ago(t){const s=Math.max(0,Date.now()/1000-t);if(s<60)return"Just now";if(s<3600)return Math.floor(s/60)+" minutes ago";if(s<86400)return Math.floor(s/3600)+" hours ago";return Math.floor(s/86400)+" days ago"}
function docRow(d,extra){const r=mk("div","document"),l=mk("div","doc-left"),w=mk("div");l.append(mk("div","doc-icon",d.ext));
 w.append(mk("div","doc-name",d.name),mk("div","doc-meta",fmt(d.size)+" · "+ago(d.ts)+(extra?" · "+extra:"")));l.append(w);
 r.append(l,mk("div","status",d.restricted?"Restricted":"Indexed"));r.title="Click to download";r.style.cursor="pointer";
 r.onclick=()=>{location.href="/api/files/"+d.id+"/download"};return r}
const ready=fetch("/api/me",{credentials:"same-origin"}).then(r=>{if(!r.ok){location.href="login.html";throw 0}return r.json()}).then(d=>{
 ME=d;CSRF=d.csrf;$(".avatar").textContent=d.email.slice(0,2).toUpperCase();
 $(".user-info strong").textContent=d.email.split("@")[0];$(".user-info span").textContent=d.role==="admin"?"Administrator":"Secure account";
 const m=$(".user-mini");m.style.cursor="pointer";m.title="Click to sign out";
 m.onclick=async()=>{if(confirm("Sign out?")){await api("/api/logout",{method:"POST"});location.href="login.html"}}});
"""

PAGE_JS = {
"login": r"""
const $=s=>document.querySelector(s);
const sec=$(".security"),dot=sec.querySelector(".security-dot");
function note(m){sec.replaceChildren(dot,document.createTextNode(m))}
async function go(e){e.preventDefault();e.stopPropagation();const em=$("#email"),pw=$("#password");
 if(!em.reportValidity()||!pw.reportValidity())return;note("Signing in...");
 try{const r=await fetch("/api/auth",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:em.value,password:pw.value})});
  const j=await r.json();if(!r.ok)throw new Error(typeof j.detail==="string"?j.detail:"Could not sign in.");
  note(j.created?"Account created. Welcome!":"Signed in. Redirecting...");setTimeout(()=>{location.href="dashboard.html"},j.created?900:200)}
 catch(x){note(x.message)}}
document.addEventListener("click",e=>{if(e.target.closest(".login-button"))go(e)},true);
document.addEventListener("submit",go,true);
""",
"dashboard": r"""
(async()=>{await ready;const f=await(await api("/api/files")).json(),s=await(await api("/api/stats")).json();
 const h=document.querySelectorAll(".stat-card h2");h[0].textContent=s.total;h[1].textContent=s.indexed;h[2].textContent=s.queries;
 const p=$(".content-grid .panel");p.querySelector(".panel-header a").href="documents.html";p.querySelectorAll(".document").forEach(x=>x.remove());
 if(!f.length){const e=mk("div","document");e.append(mk("div","doc-meta","No documents yet. Upload your first one."));p.append(e)}
 f.slice(0,3).forEach(d=>p.append(docRow(d)))})();
""",
"documents": r"""
const list=$(".documents");let ALL=[];
function draw(items){list.replaceChildren();if(!items.length){const e=mk("div","document");e.append(mk("div","doc-meta","No documents found."));list.append(e);return}
 items.forEach(d=>list.append(docRow(d,d.snippet)))}
async function load(){await ready;ALL=await(await api("/api/files")).json();draw(ALL)}
async function send(files){await ready;for(const f of files){const t=mk("div","document"),l=mk("div","doc-left"),w=mk("div");
  l.append(mk("div","doc-icon",(f.name.split(".").pop()||"").toUpperCase().slice(0,4)));
  w.append(mk("div","doc-name",f.name),mk("div","doc-meta",fmt(f.size)+" · Uploading..."));l.append(w);t.append(l,mk("div","status","Uploading"));list.prepend(t);
  try{const fd=new FormData();fd.append("file",f);await api("/api/upload",{method:"POST",body:fd})}catch(x){alert(f.name+": "+x.message)}}
 load()}
document.addEventListener("change",e=>{if(e.target.id!=="fileInput")return;e.stopPropagation();const fs=[...e.target.files];e.target.value="";send(fs)},true);
const z=$(".upload-zone");z.addEventListener("dragover",e=>e.preventDefault());z.addEventListener("drop",e=>{e.preventDefault();send([...e.dataTransfer.files])});
let timer;$(".search").addEventListener("input",e=>{clearTimeout(timer);const v=e.target.value.trim();
 timer=setTimeout(async()=>{if(!v){draw(ALL);return}await ready;try{draw(await(await api("/api/search?q="+encodeURIComponent(v))).json())}catch(x){}},250)});
load();
""",
"assistant": r"""
const msgs=$("#messages");
ready.then(()=>{[...msgs.querySelectorAll(".message")].slice(1).forEach(x=>x.remove())});
function add(cls,text,src){const m=mk("div","message "+cls),b=mk("div","bubble",text);
 if(src&&src.length)b.append(mk("div","source","Source · "+src.join(" · ")));m.append(b);msgs.append(m);msgs.scrollTop=msgs.scrollHeight}
document.addEventListener("submit",async e=>{if(e.target.id!=="chatForm")return;e.preventDefault();e.stopPropagation();
 const i=$("#chatInput"),t=i.value.trim();if(!t)return;i.value="";add("user",t);
 try{await ready;const j=await(await api("/api/chat",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({message:t})})).json();add("ai",j.answer,j.sources)}
 catch(x){add("ai",x.message)}},true);
""",
}

def load_page(name, user_ok):
    for p in (BASE / "pages" / f"{name}.html", BASE / f"{name}.html"):
        if p.is_file():
            html = p.read_text("utf-8")
            break
    else:
        return HTMLResponse(f"<h2>{name}.html not found</h2><p>Put it next to main.py (or in a 'pages' folder).</p>", 500)
    js = PAGE_JS.get(name, "")
    if name in PROTECTED: js = COMMON + js
    if js:
        head, sep, tail = html.rpartition("</body>")
        html = (head + f"<script>{js}</script></body>" + tail) if sep else html + f"<script>{js}</script>"
    return HTMLResponse(html)

@app.get("/")
def home():
    return load_page("index", True)

@app.get("/{name}.html")
def page(name: str, request: Request):
    if name not in PROTECTED | PUBLIC:
        raise HTTPException(404, "Not found")
    if name in PROTECTED and not get_user(request):
        return RedirectResponse("/login.html", status_code=303)
    return load_page(name, True)