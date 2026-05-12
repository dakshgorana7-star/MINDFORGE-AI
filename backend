from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from pydantic import BaseModel
from datetime import datetime, timedelta
from passlib.context import CryptContext
import sqlite3, json, os, random, anthropic, jwt

app = FastAPI(title="MindForge API v3.0 â€” Multi-User", version="3.0.0")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Security Config
SECRET_KEY = os.environ.get("JWT_SECRET", "mindforge_secret_2024_change_in_production")
ALGORITHM = "HS256"
TOKEN_HOURS = 24 * 7  # 7 days

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer()


def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)


def create_token(user_id: int, email: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired. Please log in again.")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token.")


def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    return decode_token(creds.credentials)


# Database
DB_PATH = "mindforge.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Users table
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL,
            email      TEXT    UNIQUE NOT NULL,
            password   TEXT    NOT NULL,
            created_at TEXT    NOT NULL
        )
    """
    )

    # Analyses table (linked to user)
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS analyses (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            text        TEXT    NOT NULL,
            topic       TEXT,
            score       REAL,
            verdict     TEXT,
            perspectives TEXT,
            biases      TEXT,
            counter_arg TEXT,
            blind_spot  TEXT,
            created_at  TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """
    )
    conn.commit()
    conn.close()


init_db()

# ML Engine
PERSPECTIVE_KEYWORDS = {
    "utilitarian": [
        "benefit",
        "outcome",
        "result",
        "majority",
        "useful",
        "practical",
        "efficient",
        "welfare",
        "consequence",
        "improve",
        "maximize",
        "effective",
        "good for",
        "helps",
    ],
    "deontological": [
        "duty",
        "right",
        "wrong",
        "moral",
        "principle",
        "obligation",
        "rule",
        "ethics",
        "ethical",
        "must",
        "should",
        "ought",
        "justice",
        "rights",
        "dignity",
        "fair",
        "responsibility",
    ],
    "libertarian": [
        "freedom",
        "free",
        "individual",
        "choice",
        "government",
        "liberty",
        "autonomy",
        "personal",
        "private",
        "control",
        "interference",
        "regulation",
        "mandate",
        "restrict",
        "ban",
    ],
    "collectivist": [
        "community",
        "society",
        "together",
        "shared",
        "common",
        "group",
        "collective",
        "public",
        "social",
        "nation",
        "people",
        "citizens",
        "everyone",
        "unity",
        "cooperation",
    ],
    "empiricist": [
        "data",
        "evidence",
        "study",
        "research",
        "prove",
        "fact",
        "science",
        "statistics",
        "measured",
        "observed",
        "experiment",
        "analysis",
        "shows",
        "found",
        "according to",
        "survey",
    ],
    "rationalist": [
        "logic",
        "logical",
        "reason",
        "reasoning",
        "argument",
        "conclude",
        "therefore",
        "rational",
        "analysis",
        "deduce",
        "premise",
        "follow",
        "sense",
        "clearly",
        "evident",
    ],
    "optimistic": [
        "hope",
        "better",
        "improve",
        "progress",
        "growth",
        "opportunity",
        "positive",
        "future",
        "bright",
        "promising",
        "potential",
        "can",
        "will",
        "capable",
        "confident",
        "succeed",
    ],
    "pessimistic": [
        "fail",
        "decline",
        "worse",
        "problem",
        "risk",
        "crisis",
        "danger",
        "never",
        "impossible",
        "cannot",
        "doubt",
        "fear",
        "worried",
        "threat",
        "damage",
        "harm",
        "catastrophe",
    ],
    "progressive": [
        "change",
        "reform",
        "new",
        "modern",
        "innovation",
        "evolve",
        "update",
        "forward",
        "advance",
        "progress",
        "revolution",
        "transform",
        "rethink",
        "bold",
        "radical",
    ],
    "conservative": [
        "tradition",
        "preserve",
        "stability",
        "values",
        "history",
        "proven",
        "maintain",
        "protect",
        "established",
        "time-tested",
        "heritage",
        "culture",
        "classic",
        "careful",
        "caution",
    ],
    "skeptical": [
        "doubt",
        "question",
        "claim",
        "verify",
        "uncertain",
        "really",
        "actually",
        "sure",
        "proof",
        "skeptical",
        "misleading",
        "exaggerated",
        "unsure",
        "unproven",
        "unreliable",
        "myth",
    ],
    "idealistic": [
        "ideal",
        "perfect",
        "dream",
        "vision",
        "aspire",
        "ultimate",
        "best",
        "imagine",
        "utopia",
        "should be",
        "could be",
        "would be",
        "strive",
        "pursue",
        "goal",
        "purpose",
    ],
}

BIAS_KEYWORDS = {
    "confirmation bias": [
        "obviously",
        "clearly",
        "everyone knows",
        "of course",
        "certainly",
        "definitely",
        "proves",
        "confirms",
        "no doubt",
        "undeniably",
    ],
    "black-and-white thinking": [
        "either",
        "never",
        "always",
        "only",
        "must",
        "impossible",
        "no choice",
        "absolute",
        "absolutely",
        "totally",
        "completely",
        "solely",
    ],
    "appeal to authority": [
        "experts say",
        "scientists say",
        "studies show",
        "research proves",
        "official",
        "authorities",
        "according to experts",
        "professionals agree",
    ],
    "straw man": [
        "they think",
        "they believe",
        "opponents think",
        "critics think",
        "they claim",
        "people who disagree",
        "those who oppose",
    ],
    "slippery slope": [
        "will lead to",
        "leads to",
        "next thing",
        "eventually",
        "spiral",
        "inevitably",
        "end up",
        "before long",
        "first step",
        "gateway",
        "domino",
    ],
    "hasty generalization": [
        "all people",
        "every person",
        "everyone does",
        "nobody",
        "none of them",
        "always the case",
        "universally",
        "without exception",
    ],
    "ad hominem": [
        "stupid",
        "idiot",
        "naive",
        "ignorant",
        "they just",
        "uneducated",
        "don't understand",
        "can't see",
        "too dumb",
        "clueless",
    ],
}


def run_ml(text: str) -> dict:
    lower = text.lower()
    words = lower.split()

    persp = []
    for label, kws in PERSPECTIVE_KEYWORDS.items():
        hits = sum(1 for kw in kws if kw in lower)
        raw = min(0.95, 0.25 + hits * 0.12 + random.uniform(0, 0.08)) if hits > 0 else random.uniform(0.10, 0.22)
        persp.append({"label": label, "confidence": round(raw, 3)})
    persp.sort(key=lambda x: x["confidence"], reverse=True)
    top_persp = persp[: max(4, len([p for p in persp if p["confidence"] > 0.28]))]

    biases = []
    for label, kws in BIAS_KEYWORDS.items():
        hits = sum(1 for kw in kws if kw in lower)
        if hits > 0:
            raw = min(0.93, 0.30 + hits * 0.18 + random.uniform(0, 0.10))
            biases.append({"label": label, "confidence": round(raw, 3)})
    biases.sort(key=lambda x: x["confidence"], reverse=True)

    score = min(100, max(20, len(top_persp) * 12 + min(20, len(words) // 5) + (8 if len(set(words)) > 20 else 4)))
    top_labels = {p["label"] for p in top_persp}
    missing = [p["label"] for p in persp if p["label"] not in top_labels][:4]

    return {"perspectives": top_persp, "biases": biases[:4], "score": round(score), "missing": missing}


def generate_insight(text, perspectives, biases, topic) -> dict:
    bias_str = ", ".join(biases) if biases else "none detected"
    client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
    prompt = f"""You are MindForge â€” a sharp, witty AI co-pilot. Like Jarvis from Iron Man: confident, clever, concise, slightly playful.

Argument: "{text}"
Topic: {topic or 'general'}
Perspectives: {', '.join(perspectives)}
Biases: {bias_str}

Return ONLY valid JSON:
{{
  "counter_argument": "2-3 sentences. Direct and clever. Challenge their core assumption.",
  "blind_spot": "1 sentence. What did they completely miss? Be specific.",
  "socratic_question": "1 sharp question that makes them genuinely rethink.",
  "strength_1": "One genuine logical strength (1 sentence)",
  "strength_2": "Another strength (1 sentence)",
  "weakness_1": "One clear logical weakness (1 sentence)",
  "weakness_2": "Another weakness (1 sentence)",
  "verdict": "One of: Balanced | One-sided | Deeply nuanced | Biased"
}}"""
    msg = client.messages.create(
        model="claude-sonnet-4-20250514", max_tokens=600, messages=[{"role": "user", "content": prompt}]
    )
    try:
        return json.loads(msg.content[0].text.strip())
    except:
        return {
            "counter_argument": "Interesting take â€” the opposing view would reframe your conclusion entirely.",
            "blind_spot": "You haven't considered the perspective of those most affected.",
            "socratic_question": "What evidence would actually change your mind?",
            "strength_1": "Clear central claim.",
            "strength_2": "Intuitive reasoning.",
            "weakness_1": "Assumptions not justified.",
            "weakness_2": "Doesn't address counterarguments.",
            "verdict": "One-sided",
        }


# SCHEMAS
class SignupRequest(BaseModel):
    name: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class AnalyzeRequest(BaseModel):
    text: str
    topic: str = ""


# AUTH ENDPOINTS
@app.post("/auth/signup")
def signup(req: SignupRequest):
    """Create a new user account."""
    if len(req.name.strip()) < 2:
        raise HTTPException(400, "Name is too short.")
    if "@" not in req.email:
        raise HTTPException(400, "Invalid email address.")
    if len(req.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters.")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE email=?", (req.email.lower(),))
    if c.fetchone():
        conn.close()
        raise HTTPException(409, "An account with this email already exists.")

    hashed = hash_password(req.password)
    c.execute(
        "INSERT INTO users (name,email,password,created_at) VALUES (?,?,?,?)",
        (req.name.strip(), req.email.lower(), hashed, datetime.now().isoformat()),
    )
    conn.commit()
    user_id = c.lastrowid
    conn.close()

    token = create_token(user_id, req.email.lower())
    return {"message": "Account created!", "token": token, "user": {"id": user_id, "name": req.name, "email": req.email.lower()}}


@app.post("/auth/login")
def login(req: LoginRequest):
    """Login with email and password."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id,name,email,password FROM users WHERE email=?", (req.email.lower(),))
    row = c.fetchone()
    conn.close()

    if not row:
        raise HTTPException(401, "No account found with this email.")
    if not verify_password(req.password, row[3]):
        raise HTTPException(401, "Incorrect password.")

    token = create_token(row[0], row[2])
    return {"message": "Welcome back!", "token": token, "user": {"id": row[0], "name": row[1], "email": row[2]}}


@app.get("/auth/me")
def get_me(user=Depends(get_current_user)):
    """Get current user info."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id,name,email,created_at FROM users WHERE id=?", (user["user_id"],))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "User not found.")
    return {"id": row[0], "name": row[1], "email": row[2], "created_at": row[3]}


# ANALYZE ENDPOINT
@app.post("/analyze")
async def analyze(req: AnalyzeRequest, user=Depends(get_current_user)):
    """Run full ML pipeline â€” requires authentication."""
    if len(req.text.split()) < 8:
        raise HTTPException(400, "Please write at least 8 words.")

    ml = run_ml(req.text)
    labels = [p["label"] for p in ml["perspectives"][:4]]
    bnames = [b["label"] for b in ml["biases"]]
    insight = generate_insight(req.text, labels, bnames, req.topic)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """INSERT INTO analyses (user_id,text,topic,score,verdict,perspectives,biases,counter_arg,blind_spot,created_at)
                 VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            user["user_id"],
            req.text,
            req.topic,
            ml["score"],
            insight.get("verdict"),
            json.dumps(ml["perspectives"]),
            json.dumps(ml["biases"]),
            insight.get("counter_argument"),
            insight.get("blind_spot"),
            datetime.now().isoformat(),
        ),
    )
    conn.commit()
    saved_id = c.lastrowid
    conn.close()

    return {**ml, **insight, "saved_id": saved_id}


# HISTORY ENDPOINTS
@app.get("/history")
def get_history(user=Depends(get_current_user)):
    """Get ALL analyses for the logged-in user."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """SELECT id,text,topic,score,verdict,created_at
                 FROM analyses WHERE user_id=? ORDER BY id DESC LIMIT 50""",
        (user["user_id"],),
    )
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "text": r[1][:120], "topic": r[2], "score": r[3], "verdict": r[4], "created_at": r[5]} for r in rows]


@app.get("/history/stats")
def get_stats(user=Depends(get_current_user)):
    """Get personal statistics for profile page."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*),AVG(score),MAX(score),MIN(score) FROM analyses WHERE user_id=?", (user["user_id"],))
    r = c.fetchone()
    conn.close()
    return {"total": r[0], "avg_score": round(r[1] or 0, 1), "best_score": r[2], "worst_score": r[3]}


@app.delete("/history/{analysis_id}")
def delete_analysis(analysis_id: int, user=Depends(get_current_user)):
    """Delete a specific analysis."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM analyses WHERE id=? AND user_id=?", (analysis_id, user["user_id"]))
    conn.commit()
    conn.close()
    return {"message": "Deleted."}


@app.get("/", include_in_schema=False)
def root():
    return FileResponse("index.html")
