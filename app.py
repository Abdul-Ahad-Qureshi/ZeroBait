import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

import os
import sys
import secrets
import re
import math
import ipaddress
import unicodedata
import json
import csv
import io
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict
import concurrent.futures
from contextlib import asynccontextmanager
from collections import defaultdict
import threading

import uvicorn
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Query, UploadFile, File
from fastapi.responses import RedirectResponse, JSONResponse, PlainTextResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from passlib.context import CryptContext
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl, ValidationError, Field
import joblib
import pandas as pd
import whois
import dns.resolver
from sqlalchemy.orm import Session
from sqlalchemy import func

import database
from database import ScanHistory, FeedbackReport, ContactMessage, User, AuditLog

APP_START_TIME = time.time()
LOOKUP_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=10, thread_name_prefix="threat_lookup_")

@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db()
    yield
    LOOKUP_EXECUTOR.shutdown(wait=False)

app = FastAPI(
    title="ZeroBait Threat Intelligence API",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

IS_PROD = os.environ.get("ENVIRONMENT", "development").lower() == "production"
SECURE_COOKIE = os.environ.get("SECURE_COOKIE", "false").lower() == "true"

SECRET_KEY = os.environ.get("SECRET_KEY") or os.environ.get("SESSION_SECRET")
if not SECRET_KEY:
    if IS_PROD:
        raise RuntimeError("FATAL: SECRET_KEY environment variable is required in production mode.")
    SECRET_KEY = secrets.token_hex(32)

SUSPICIOUS_TLDS = ['.xyz', '.top', '.pw', '.cc', '.info', '.tk', '.ml', '.work', '.click', '.fit', '.gq', '.cf', '.buzz', '.monster', '.rest', '.sbs']

# Global Protected Brands Target Database for Impersonation Radar
PROTECTED_BRANDS = {
    "paypal": ["paypal.com", "paypal-community.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "azure.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com", "accounts.google.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "metamask": ["metamask.io"],
    "docusign": ["docusign.com", "docusign.net"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "telegram": ["telegram.org", "t.me"],
    "adobe": ["adobe.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"]
}

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

app.add_middleware(SecurityHeadersMiddleware)

class SimpleRateLimiter:
    def __init__(self):
        self.requests = defaultdict(list)
        self.lock = threading.Lock()

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> bool:
        now = time.time()
        with self.lock:
            self.requests[key] = [t for t in self.requests[key] if now - t < window_seconds]
            if len(self.requests[key]) >= max_requests:
                return False
            self.requests[key].append(now)
            return True

rate_limiter = SimpleRateLimiter()

def check_rate_limit(request: Request, limit: int = 40, window: int = 60):
    client_ip = request.client.host if request.client else "127.0.0.1"
    key = f"{client_ip}:{request.url.path}"
    if not rate_limiter.is_allowed(key, limit, window):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {limit} requests per {window} seconds. Please slow down."
        )

allowed_origins_env = os.environ.get("CORS_ORIGINS", "*")
if allowed_origins_env.strip() == "*":
    allowed_origins = ["*"]
else:
    allowed_origins = [orig.strip() for orig in allowed_origins_env.split(",") if orig.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True if allowed_origins != ["*"] else False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    same_site="lax",
    https_only=SECURE_COOKIE
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Load ML Model
model_path = os.path.join(BASE_DIR, "phishing_model.pkl")
if os.path.exists(model_path):
    try:
        model = joblib.load(model_path)
    except Exception as e:
        print(f"Warning: Could not load model from {model_path}: {e}")
        model = None
else:
    model = None

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def get_current_user(request: Request, db: Session = Depends(database.get_db)) -> Optional[User]:
    user_id = request.session.get("user_id")
    if user_id:
        try:
            return db.query(User).filter(User.id == user_id).first()
        except Exception:
            return None
    return None

def _get_user_for_request(request: Request) -> Optional[User]:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    db = database.SessionLocal()
    try:
        return db.query(User).filter(User.id == user_id).first()
    except Exception:
        return None
    finally:
        db.close()

def require_admin(user: Optional[User] = Depends(get_current_user)) -> User:
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    if getattr(user, "role", "analyst") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator clearance required")
    return user

@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    accept = request.headers.get("accept", "")
    is_html = "text/html" in accept and not request.url.path.startswith("/api/") and not request.url.path.startswith("/predict")
    
    if exc.status_code == status.HTTP_404_NOT_FOUND and is_html:
        user = _get_user_for_request(request)
        return templates.TemplateResponse(
            request=request,
            name="404.html",
            context={"active_page": "404", "user": user},
            status_code=404
        )
    
    if exc.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR and is_html:
        user = _get_user_for_request(request)
        return templates.TemplateResponse(
            request=request,
            name="500.html",
            context={"active_page": "500", "user": user},
            status_code=500
        )
        
    return JSONResponse(
        status_code=exc.status_code,
        content={"status": "error", "detail": exc.detail}
    )

@app.exception_handler(Exception)
async def custom_unhandled_exception_handler(request: Request, exc: Exception):
    accept = request.headers.get("accept", "")
    is_html = "text/html" in accept and not request.url.path.startswith("/api/") and not request.url.path.startswith("/predict")
    
    if is_html:
        user = _get_user_for_request(request)
        return templates.TemplateResponse(
            request=request,
            name="500.html",
            context={"active_page": "500", "user": user},
            status_code=500
        )
    return JSONResponse(
        status_code=500,
        content={"status": "error", "detail": "An internal service anomaly occurred. Please try again."}
    )

# URL Defanger & Refanger utility
def defang_url(url: str) -> str:
    """Sanitizes URL for safe forensic sharing (e.g. hxxps://evil[.]com/path)."""
    if not url: return ""
    d = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    d = d.replace(".", "[.]")
    return d

def refang_url(defanged_url: str) -> str:
    """Restores defanged URL back to standard format."""
    if not defanged_url: return ""
    r = defanged_url.replace("hxxp://", "http://").replace("hxxps://", "https://")
    r = r.replace("[.]", ".").replace("(.)", ".")
    return r

# IP Classification & SSRF Defense
def classify_ip_target(domain_or_ip: str) -> Dict[str, bool]:
    clean = domain_or_ip.split(':')[0]
    try:
        ip_obj = ipaddress.ip_address(clean)
        return {
            "is_ip": True,
            "is_private": ip_obj.is_private,
            "is_loopback": ip_obj.is_loopback,
            "is_link_local": ip_obj.is_link_local,
            "is_reserved": ip_obj.is_reserved
        }
    except ValueError:
        is_local_name = clean.lower() in ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
        return {
            "is_ip": False,
            "is_private": is_local_name,
            "is_loopback": is_local_name,
            "is_link_local": False,
            "is_reserved": is_local_name
        }

# Homograph / Punycode Detector
def detect_homograph_attack(domain: str) -> Dict[str, any]:
    if not domain:
        return {"is_homograph": False, "is_punycode": False, "scripts": []}
    
    is_punycode = "xn--" in domain.lower()
    scripts = set()
    for char in domain:
        if char.isalnum():
            try:
                scripts.add(unicodedata.name(char).split()[0])
            except Exception:
                pass
                
    has_mixed_scripts = len(scripts) > 1 and ("LATIN" in scripts and ("CYRILLIC" in scripts or "GREEK" in scripts or "ARABIC" in scripts))
    return {
        "is_homograph": bool(is_punycode or has_mixed_scripts),
        "is_punycode": is_punycode,
        "has_mixed_scripts": has_mixed_scripts,
        "scripts": list(scripts)
    }

# Shannon Entropy Calculation
def calculate_shannon_entropy(s: str) -> float:
    if not s: return 0.0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return round(entropy, 2)

# Brand Impersonation Radar
def detect_brand_impersonation(url: str, domain: str) -> Dict[str, any]:
    url_lower = url.lower()
    domain_lower = domain.lower()
    detected_brand = None
    is_impersonation = False
    
    for brand, legit_domains in PROTECTED_BRANDS.items():
        if brand in url_lower:
            is_legit = any(domain_lower == legit or domain_lower.endswith("." + legit) for legit in legit_domains)
            if not is_legit:
                detected_brand = brand
                is_impersonation = True
                break
                
    return {
        "is_impersonation": is_impersonation,
        "target_brand": detected_brand.title() if detected_brand else None,
        "trusted_domains": PROTECTED_BRANDS.get(detected_brand, []) if detected_brand else []
    }

# Feature Extraction & Analysis
def extract_features(url: str):
    url = str(url)
    clean_url = url.replace('[', '').replace(']', '')
    try:
        if not clean_url.startswith('http://') and not clean_url.startswith('https://'):
            parsed_url = urlparse('http://' + clean_url)
        else:
            parsed_url = urlparse(clean_url)
        hostname_length = len(parsed_url.netloc) if parsed_url.netloc else len(url)
        domain = parsed_url.netloc.split(':')[0]
    except Exception:
        hostname_length = len(url)
        domain = ""
        
    ip_status = classify_ip_target(domain)
    homograph_status = detect_homograph_attack(domain)
    brand_status = detect_brand_impersonation(url, domain)
    entropy_score = calculate_shannon_entropy(url)

    return {
        'url_length': len(url),
        'hostname_length': hostname_length,
        'count_hyphens': url.count('-'),
        'count_at_symbol': url.count('@'),
        'count_dots': url.count('.'),
        'count_digits': sum(c.isdigit() for c in url),
        'has_ip_address': 1 if ip_status["is_ip"] else 0,
        'is_private_ip': 1 if ip_status["is_private"] or ip_status["is_loopback"] else 0,
        'is_homograph': 1 if homograph_status["is_homograph"] else 0,
        'is_brand_impersonation': 1 if brand_status["is_impersonation"] else 0,
        'uses_https': 1 if url.startswith('https://') else 0,
        'uses_shortener': 1 if re.search(r'bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|bit\.do|mcaf\.ee', url, re.I) else 0,
        'domain': domain,
        'entropy': entropy_score,
        'ip_status': ip_status,
        'homograph_status': homograph_status,
        'brand_status': brand_status,
        'defanged_url': defang_url(url)
    }

# Deep DNS Inspector (A, MX, TXT / SPF)
def deep_dns_inspection(domain: str, is_private: bool = False) -> dict:
    if not domain or is_private:
        return {
            "has_dns": not is_private,
            "ip_addresses": ["127.0.0.1"] if is_private else [],
            "mx_records": [],
            "has_mx": False,
            "has_spf": False
        }
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    
    ip_addrs = []
    mx_hosts = []
    has_spf = False
    
    try:
        a_records = resolver.resolve(domain, 'A')
        ip_addrs = [r.to_text() for r in a_records]
    except Exception:
        pass
        
    try:
        mx_records = resolver.resolve(domain, 'MX')
        mx_hosts = [r.exchange.to_text().rstrip('.') for r in mx_records]
    except Exception:
        pass
        
    try:
        txt_records = resolver.resolve(domain, 'TXT')
        for r in txt_records:
            t = r.to_text()
            if "v=spf1" in t or "v=DMARC1" in t:
                has_spf = True
                break
    except Exception:
        pass

    return {
        "has_dns": bool(ip_addrs),
        "ip_addresses": ip_addrs[:4],
        "mx_records": mx_hosts[:3],
        "has_mx": bool(mx_hosts),
        "has_spf": has_spf
    }

def _fetch_whois(domain: str):
    try:
        w = whois.whois(domain)
        creation_date = getattr(w, 'creation_date', None)
        registrar = getattr(w, 'registrar', None) or "Unknown"
        name_servers = getattr(w, 'name_servers', None) or []
        if isinstance(name_servers, list):
            name_servers = [str(ns).lower() for ns in name_servers[:3]]
        else:
            name_servers = [str(name_servers).lower()] if name_servers else []

        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None
        
        age_days = -1
        if creation_date:
            if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
                age_days = (datetime.now(timezone.utc) - creation_date).days
            else:
                age_days = (datetime.now() - creation_date).days
        return {"age_days": age_days, "registrar": str(registrar), "name_servers": name_servers}
    except Exception:
        return {"age_days": -1, "registrar": "Unknown", "name_servers": []}

def check_domain_info(domain: str, is_private: bool = False) -> dict:
    if not domain or is_private:
        return {"age_days": -1, "registrar": "Internal Network" if is_private else "Unknown", "name_servers": []}
    try:
        future = LOOKUP_EXECUTOR.submit(_fetch_whois, domain)
        return future.result(timeout=2.5)
    except concurrent.futures.TimeoutError:
        return {"age_days": -1, "registrar": "Lookup Timeout", "name_servers": []}
    except Exception:
        return {"age_days": -1, "registrar": "Unknown", "name_servers": []}

def calculate_heuristic_score(url: str, features: dict):
    score = 0.0
    flags = []
    url_lower = url.lower()
    domain = features.get('domain', '')
    is_private = bool(features.get('is_private_ip', 0))

    # 1. Brand Impersonation Radar
    brand_status = features.get('brand_status', {})
    if brand_status.get('is_impersonation'):
        target = brand_status.get('target_brand', 'Major Brand')
        score += 50.0
        flags.append({"label": f"Targeted Brand Impersonation detected ({target})", "points": 50})

    # 2. Homograph & Punycode Spoofing Signal
    if features.get('is_homograph', 0):
        score += 45.0
        flags.append({"label": "Homograph / IDN Spoofed Domain detected", "points": 45})

    # 3. Private Subnet / SSRF Classification
    if is_private:
        score += 35.0
        flags.append({"label": "Internal RFC 1918 / Loopback address", "points": 35})
        domain_whois = {"age_days": -1, "registrar": "Internal / Loopback", "name_servers": []}
        dns_intel = deep_dns_inspection(domain, is_private=True)
    elif domain:
        dns_intel = deep_dns_inspection(domain, is_private=False)
        if not dns_intel["has_dns"]:
            score += 30.0
            flags.append({"label": "No DNS A-record (dead/unregistered domain)", "points": 30})

        domain_whois = check_domain_info(domain, is_private)
        age_days = domain_whois.get("age_days", -1)
        if age_days != -1 and age_days < 30:
            score += 25.0
            flags.append({"label": f"Brand-new domain ({age_days} days old)", "points": 25})
    else:
        domain_whois = {"age_days": -1, "registrar": "Unknown", "name_servers": []}
        dns_intel = {"has_dns": False, "ip_addresses": [], "mx_records": [], "has_mx": False, "has_spf": False}

    # 4. IP Address in URL
    if features.get('has_ip_address', 0) and not is_private:
        score += 55.0
        flags.append({"label": "Direct IP address used instead of hostname", "points": 55})

    # 5. Length Penalties
    if features.get('url_length', 0) > 75:
        score += 15.0
        flags.append({"label": f"Excessively long URL ({features['url_length']} chars)", "points": 15})

    # 6. Subdomain Abuse
    if features.get('count_dots', 0) >= 3:
        score += 20.0
        flags.append({"label": f"Excessive subdomains ({features['count_dots']} dots)", "points": 20})

    # 7. Shortener Detection
    if features.get('uses_shortener', 0):
        score += 25.0
        flags.append({"label": "URL shortener service detected", "points": 25})

    # 8. High Entropy
    if features.get('entropy', 0) > 4.4:
        score += 15.0
        flags.append({"label": f"High Shannon Entropy ({features['entropy']} bits) — randomized tokens", "points": 15})

    # 9. Phishing Keywords
    keywords = ['login', 'secure', 'account', 'update', 'verify', 'banking', 'signin', 'auth', 'billing', 'wallet', 'crypto', 'recovery']
    matched_kw = [kw for kw in keywords if kw in url_lower]
    if matched_kw:
        pts = min(20.0 * len(matched_kw), 40.0)
        score += pts
        flags.append({"label": f"Phishing keywords: {', '.join(matched_kw)}", "points": int(pts)})

    # 10. High-Risk TLDs
    matched_tlds = [tld for tld in SUSPICIOUS_TLDS if tld in url_lower]
    if matched_tlds:
        score += 20.0
        flags.append({"label": f"Suspicious TLD: {', '.join(matched_tlds)}", "points": 20})

    # 11. Credential Bypass (@ symbol)
    if features.get('count_at_symbol', 0) > 0:
        score += 30.0
        flags.append({"label": "@ symbol in URL (credential bypass)", "points": 30})

    return min(score, 100.0), flags, domain_whois, dns_intel

# Google Safe Browsing API v4 Live Client
def check_external_feeds(url: str) -> str:
    api_key = os.environ.get("SAFE_BROWSING_API_KEY")
    if not api_key:
        return "Clean (Telemetry Baseline)"
    
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "threat-intel-engine", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data and data.get("matches"):
                return "Flagged Threat (Google Safe Browsing)"
            return "Verified Clean (Google Safe Browsing)"
    except Exception:
        return "Clean (Safe Browsing Fallback)"

class URLValidator(BaseModel):
    url: HttpUrl

class URLRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)

class BulkURLRequest(BaseModel):
    urls: List[str] = Field(..., max_items=25)

class ReportRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)
    predicted_score: float = Field(..., ge=0.0, le=100.0)
    is_malicious: bool

def process_url(url: str) -> dict:
    url = url.strip()
    url = unicodedata.normalize('NFKC', url)

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
        
    try:
        validated = URLValidator(url=url)
        clean_url = str(validated.url)
    except ValidationError:
        return {"error": "Invalid URL format. Please provide a valid web address."}

    features = extract_features(clean_url)
    
    ml_features = {k: v for k, v in features.items() if k not in [
        'domain', 'ip_status', 'homograph_status', 'brand_status', 'is_private_ip', 'is_homograph', 'is_brand_impersonation', 'defanged_url', 'entropy'
    ]}
    df = pd.DataFrame([ml_features])

    heuristic_score, flags, domain_whois, dns_intel = calculate_heuristic_score(clean_url, features)

    if model:
        try:
            ml_prob = model.predict_proba(df)[0][1] * 100
            probability = (ml_prob * 0.1) + (heuristic_score * 0.9)
            is_malicious = probability > 50.0
        except Exception:
            probability = heuristic_score
            is_malicious = probability > 50.0
    else:
        probability = heuristic_score
        is_malicious = probability > 50.0

    if probability >= 75:
        threat_level = "High"
    elif probability >= 40:
        threat_level = "Medium"
    else:
        threat_level = "Low"

    safe_browsing = check_external_feeds(clean_url)
    domain = features.get('domain', '')

    domain_info = {
        "domain": domain,
        "age_days": domain_whois.get("age_days", -1),
        "registrar": domain_whois.get("registrar", "Unknown"),
        "name_servers": domain_whois.get("name_servers", []),
        "has_dns": dns_intel.get("has_dns", False),
        "ip_addresses": dns_intel.get("ip_addresses", []),
        "mx_records": dns_intel.get("mx_records", []),
        "has_mx": dns_intel.get("has_mx", False),
        "has_spf": dns_intel.get("has_spf", False),
        "uses_https": bool(features.get('uses_https', 0)),
        "is_homograph": bool(features.get('is_homograph', 0)),
        "is_brand_impersonation": bool(features.get('is_brand_impersonation', 0)),
        "brand_target": features.get('brand_status', {}).get('target_brand'),
        "is_private": bool(features.get('is_private_ip', 0)),
        "entropy": features.get('entropy', 0.0),
        "defanged_url": features.get('defanged_url', clean_url),
        "suspicious_tld": any(tld in clean_url.lower() for tld in SUSPICIOUS_TLDS),
    }

    return {
        "url": clean_url,
        "defanged_url": features.get('defanged_url', clean_url),
        "features": features,
        "flags": flags,
        "domain_info": domain_info,
        "score": float(round(probability, 2)),
        "threat_level": threat_level,
        "is_malicious": bool(is_malicious),
        "safe_browsing": safe_browsing
    }

def log_scan(db: Session, result: dict, user_id: Optional[int] = None):
    if "error" not in result:
        try:
            scan = ScanHistory(
                url=result["url"],
                score=result["score"],
                threat_level=result["threat_level"],
                user_id=user_id
            )
            db.add(scan)
            db.commit()
        except Exception:
            db.rollback()

# --- Healthcheck & Observability ---
@app.get("/healthz")
@app.get("/api/health")
def healthcheck(db: Session = Depends(database.get_db)):
    db_ok = False
    try:
        db.query(User).first()
        db_ok = True
    except Exception:
        db_ok = False
        
    return {
        "status": "healthy" if db_ok else "degraded",
        "uptime_seconds": round(time.time() - APP_START_TIME, 2),
        "database_connected": db_ok,
        "model_loaded": model is not None,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

# --- SOC IOC Blocklist Exporter (STIX 2.1, CSV, TXT) ---
@app.get("/api/ioc/export")
def export_ioc_blocklist(
    format: str = Query(default="txt", pattern="^(txt|csv|stix)$"),
    min_score: float = Query(default=60.0, ge=0.0, le=100.0),
    db: Session = Depends(database.get_db)
):
    scans = db.query(ScanHistory).filter(ScanHistory.score >= min_score).order_by(ScanHistory.timestamp.desc()).limit(500).all()
    
    if format == "csv":
        csv_lines = ["indicator_url,threat_score,threat_level,first_observed_utc"]
        for s in scans:
            ts = s.timestamp.isoformat() if s.timestamp else ""
            csv_lines.append(f'"{s.url}",{s.score},"{s.threat_level}","{ts}"')
        return Response(
            content="\n".join(csv_lines),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=ioc_blocklist_{int(time.time())}.csv"}
        )
    elif format == "stix":
        stix_objects = []
        for s in scans:
            stix_objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{secrets.token_hex(16)}",
                "created": s.timestamp.isoformat() if s.timestamp else datetime.now(timezone.utc).isoformat(),
                "name": f"Malicious URL Indicator ({s.threat_level})",
                "pattern": f"[url:value = '{s.url}']",
                "pattern_type": "stix",
                "valid_from": s.timestamp.isoformat() if s.timestamp else datetime.now(timezone.utc).isoformat(),
                "confidence": int(s.score)
            })
        bundle = {
            "type": "bundle",
            "id": f"bundle--{secrets.token_hex(16)}",
            "objects": stix_objects
        }
        return JSONResponse(
            content=bundle,
            headers={"Content-Disposition": f"attachment; filename=stix_indicators_{int(time.time())}.json"}
        )
    else: # Plaintext
        txt_lines = [f"# Threat Intelligence Autonomous IOC Blocklist — Generated {datetime.now(timezone.utc).isoformat()}"]
        for s in scans:
            txt_lines.append(s.url)
        return PlainTextResponse(
            content="\n".join(txt_lines),
            headers={"Content-Disposition": f"attachment; filename=ioc_blocklist_{int(time.time())}.txt"}
        )

# --- Feature B: Enterprise Bulk CSV Import & Advanced Threat Exporter ---

@app.post("/api/threats/import-csv")
async def import_csv_threats(
    file: UploadFile = File(...),
    db: Session = Depends(database.get_db),
    user: Optional[User] = Depends(get_current_user)
):
    if not file.filename.lower().endswith(('.csv', '.txt')):
        raise HTTPException(status_code=400, detail="Invalid file format. Please upload a .csv or .txt file.")
    
    contents = await file.read()
    text = contents.decode('utf-8', errors='ignore')
    
    extracted_urls = []
    
    if file.filename.lower().endswith('.csv'):
        f_io = io.StringIO(text)
        reader = csv.reader(f_io)
        header = None
        url_col_idx = -1
        
        for row in reader:
            if not row or not any(c.strip() for c in row):
                continue
            if header is None:
                header = [c.strip().lower() for c in row]
                for idx, col_name in enumerate(header):
                    if col_name in ["url", "target", "domain", "link", "indicator", "website", "site", "target_url", "indicator_url"]:
                        url_col_idx = idx
                        break
                if url_col_idx != -1:
                    continue
                else:
                    url_col_idx = 0
            
            if url_col_idx < len(row):
                val = row[url_col_idx].strip()
                if val and not val.lower().startswith("indicator") and not val.lower().startswith("url") and ("." in val or val.startswith("http")):
                    extracted_urls.append(val)
    else: # .txt
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and ("." in line or line.startswith("http")):
                extracted_urls.append(line)
                
    seen = set()
    unique_urls = []
    for u in extracted_urls:
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)
            if len(unique_urls) >= 500:
                break
                
    if not unique_urls:
        raise HTTPException(status_code=400, detail="No valid URLs found in the uploaded file.")
        
    results = []
    for u in unique_urls:
        r = process_url(u)
        if "error" not in r:
            log_scan(db, r, user.id if user else None)
        results.append(r)
        
    high_count = sum(1 for r in results if r.get("threat_level") == "High")
    medium_count = sum(1 for r in results if r.get("threat_level") == "Medium")
    low_count = sum(1 for r in results if r.get("threat_level") == "Low")
    
    return {
        "status": "success",
        "filename": file.filename,
        "total_processed": len(results),
        "high_threats": high_count,
        "medium_threats": medium_count,
        "low_threats": low_count,
        "results": results
    }

@app.get("/api/threats/export")
def export_threats_advanced(
    format: str = Query(default="csv", pattern="^(csv|json|stix|txt)$"),
    threat_level: str = Query(default="all"),
    min_score: float = Query(default=0.0, ge=0.0, le=100.0),
    limit: int = Query(default=1000, ge=1, le=5000),
    db: Session = Depends(database.get_db)
):
    query = db.query(ScanHistory).filter(ScanHistory.score >= min_score)
    if threat_level != "all":
        query = query.filter(ScanHistory.threat_level == threat_level)
        
    scans = query.order_by(ScanHistory.timestamp.desc()).limit(limit).all()
    timestamp_suffix = int(time.time())
    
    if format == "csv":
        csv_lines = ["indicator_url,threat_score,threat_level,observed_timestamp_utc"]
        for s in scans:
            ts = s.timestamp.isoformat() if s.timestamp else ""
            csv_lines.append(f'"{s.url}",{s.score},"{s.threat_level}","{ts}"')
        return Response(
            content="\n".join(csv_lines),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=threat_intel_export_{timestamp_suffix}.csv"}
        )
    elif format == "json":
        items = [
            {
                "url": s.url,
                "score": s.score,
                "threat_level": s.threat_level,
                "timestamp": s.timestamp.isoformat() if s.timestamp else None
            }
            for s in scans
        ]
        return JSONResponse(
            content={"total": len(items), "exported_at": datetime.now(timezone.utc).isoformat(), "indicators": items},
            headers={"Content-Disposition": f"attachment; filename=threat_intel_export_{timestamp_suffix}.json"}
        )
    elif format == "stix":
        stix_objects = []
        for s in scans:
            stix_objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{secrets.token_hex(16)}",
                "created": s.timestamp.isoformat() if s.timestamp else datetime.now(timezone.utc).isoformat(),
                "name": f"Threat Indicator ({s.threat_level})",
                "pattern": f"[url:value = '{s.url}']",
                "pattern_type": "stix",
                "valid_from": s.timestamp.isoformat() if s.timestamp else datetime.now(timezone.utc).isoformat(),
                "confidence": int(s.score)
            })
        bundle = {
            "type": "bundle",
            "id": f"bundle--{secrets.token_hex(16)}",
            "objects": stix_objects
        }
        return JSONResponse(
            content=bundle,
            headers={"Content-Disposition": f"attachment; filename=stix_bundle_{timestamp_suffix}.json"}
        )
    else: # Plaintext
        txt_lines = [f"# Threat Intelligence Export — {datetime.now(timezone.utc).isoformat()}"]
        for s in scans:
            txt_lines.append(s.url)
        return PlainTextResponse(
            content="\n".join(txt_lines),
            headers={"Content-Disposition": f"attachment; filename=threat_indicators_{timestamp_suffix}.txt"}
        )

# --- Feature C: Global Omnibar Command Palette Endpoint ---

@app.get("/api/search/omni")
def omni_search(
    q: str = Query(default=""),
    db: Session = Depends(database.get_db),
    user: Optional[User] = Depends(get_current_user)
):
    query_str = q.strip().lower()
    results = {
        "actions": [],
        "navigation": [],
        "threats": []
    }
    
    # 1. Navigation matches
    nav_catalog = [
        {"title": "Threat Scanner", "description": "Inspect single or batch URLs for zero-day phishing", "url": "/#scanner", "category": "Scanner"},
        {"title": "Live Threat Tracker", "description": "Global telemetry streams and threat velocity", "url": "/tracker", "category": "Live Feeds"},
        {"title": "Threat Database", "description": "Searchable repository of indexed indicators", "url": "/threats", "category": "Repository"},
        {"title": "SOC Analyst Tools", "description": "URL Defanger, Base64 de-obfuscator, hash calculator", "url": "/tools", "category": "Utilities"},
        {"title": "API Documentation", "description": "REST Swagger specs and SIEM connectors", "url": "/api-docs", "category": "Docs"},
        {"title": "Interactive Swagger UI", "description": "Live OpenAPI testing playground", "url": "/docs", "category": "Docs"},
        {"title": "About Threat Intel", "description": "Engine architecture & machine learning heuristics", "url": "/about", "category": "System"},
        {"title": "Contact & Dispatch", "description": "Security team contact and false positive triage", "url": "/contact", "category": "Support"},
        {"title": "Privacy Policy & Governance", "description": "Zero-retention standards and GDPR controls", "url": "/privacy", "category": "Compliance"},
    ]
    
    if user:
        nav_catalog.append({"title": f"Analyst Workspace ({user.username})", "description": "Private inspection audit history and GDPR controls", "url": "/profile", "category": "Workspace"})
        if getattr(user, "role", "analyst") == "admin":
            nav_catalog.append({"title": "SOC Administration Console", "description": "RBAC user management, audit trails, and system telemetry", "url": "/admin", "category": "Governance"})
    else:
        nav_catalog.append({"title": "Sign In / Register", "description": "Authenticate to save personal inspection history", "url": "/login", "category": "Identity"})

    for nav in nav_catalog:
        if not query_str or query_str in nav["title"].lower() or query_str in nav["description"].lower():
            results["navigation"].append(nav)

    # 2. Quick Actions
    if query_str:
        if query_str.startswith("http") or "." in query_str:
            clean_target = query_str.replace(" ", "")
            results["actions"].append({
                "title": f"Quick Scan: {clean_target}",
                "description": "Run full neural and heuristic evaluation on this URL",
                "action": "scan",
                "payload": clean_target
            })
            results["actions"].append({
                "title": f"Defang Target: {clean_target}",
                "description": "Convert into safe inert text (hxxp://...)",
                "action": "defang",
                "payload": clean_target
            })
            results["actions"].append({
                "title": f"Calculate SHA-256 Hash",
                "description": "Compute cryptographic IOC hash for SIEM hunting",
                "action": "hash",
                "payload": clean_target
            })
            
    # 3. Threat Indicators search
    if query_str:
        scans = (
            db.query(ScanHistory)
            .filter(ScanHistory.url.ilike(f"%{query_str}%"))
            .order_by(ScanHistory.timestamp.desc())
            .limit(6)
            .all()
        )
        for s in scans:
            results["threats"].append({
                "url": s.url,
                "score": s.score,
                "threat_level": s.threat_level,
                "timestamp": s.timestamp.isoformat() if s.timestamp else None
            })
            
    return results



# --- API Endpoints ---

@app.post("/predict")
def predict_api(request: Request, payload: URLRequest, db: Session = Depends(database.get_db), user: Optional[User] = Depends(get_current_user)):
    check_rate_limit(request, limit=40, window=60)
    result = process_url(payload.url)
    if "error" not in result:
        log_scan(db, result, user.id if user else None)
    return result

@app.post("/predict/bulk")
def predict_bulk(request: Request, payload: BulkURLRequest, db: Session = Depends(database.get_db), user: Optional[User] = Depends(get_current_user)):
    check_rate_limit(request, limit=15, window=60)
    results = []
    for url in payload.urls[:25]:
        url = url.strip()
        if not url: continue
        r = process_url(url)
        if "error" not in r:
            log_scan(db, r, user.id if user else None)
        results.append(r)
    return results

@app.get("/")
def home(request: Request, url: Optional[str] = None, db: Session = Depends(database.get_db), user: Optional[User] = Depends(get_current_user)):
    ctx = {"active_page": "home", "user": user}
    if url:
        result = process_url(url)
        if "error" in result:
            ctx["error"] = result["error"]
            return templates.TemplateResponse(request, "index.html", ctx)
        log_scan(db, result, user.id if user else None)
        result.update(ctx)
        return templates.TemplateResponse(request, "index.html", result)
    ctx["result"] = None
    return templates.TemplateResponse(request, "index.html", ctx)

@app.post("/")
def analyze_web(request: Request, url: str = Form(...), db: Session = Depends(database.get_db), user: Optional[User] = Depends(get_current_user)):
    check_rate_limit(request, limit=30, window=60)
    result = process_url(url)
    ctx = {"active_page": "home", "user": user}
    if "error" in result:
        ctx["error"] = result["error"]
        return templates.TemplateResponse(request, "index.html", ctx)
    log_scan(db, result, user.id if user else None)
    result.update(ctx)
    return templates.TemplateResponse(request, "index.html", result)

@app.post("/api/report")
def report_feedback(report: ReportRequest, db: Session = Depends(database.get_db), user: Optional[User] = Depends(get_current_user)):
    try:
        feedback = FeedbackReport(
            url=report.url,
            predicted_score=report.predicted_score,
            is_malicious=report.is_malicious,
            user_id=user.id if user else None
        )
        db.add(feedback)
        db.commit()
        return {"status": "success", "message": "Feedback recorded."}
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Database error recording feedback.")

@app.get("/api/history")
def get_history(limit: int = Query(default=10, ge=1, le=50), db: Session = Depends(database.get_db)):
    scans = db.query(ScanHistory).order_by(ScanHistory.timestamp.desc()).limit(limit).all()
    return [
        {
            "url": s.url,
            "score": s.score,
            "threat_level": s.threat_level,
            "timestamp": s.timestamp.isoformat() if s.timestamp else None
        }
        for s in scans
    ]

@app.get("/api/stats")
def get_stats(db: Session = Depends(database.get_db)):
    total_scans = db.query(ScanHistory).count()
    high_threat = db.query(ScanHistory).filter(ScanHistory.threat_level == "High").count()
    medium_threat = db.query(ScanHistory).filter(ScanHistory.threat_level == "Medium").count()
    low_threat = db.query(ScanHistory).filter(ScanHistory.threat_level == "Low").count()
    
    now_utc = datetime.now(timezone.utc)
    start_of_today = datetime(now_utc.year, now_utc.month, now_utc.day, tzinfo=timezone.utc)
    scans_today = db.query(ScanHistory).filter(ScanHistory.timestamp >= start_of_today).count()
    
    return {
        "total_scans": total_scans,
        "scans_today": scans_today,
        "high_threat": high_threat,
        "medium_threat": medium_threat,
        "low_threat": low_threat,
    }

@app.get("/api/trend")
def get_trend(db: Session = Depends(database.get_db)):
    result = []
    now_utc = datetime.now(timezone.utc)
    today = datetime(now_utc.year, now_utc.month, now_utc.day, tzinfo=timezone.utc)
    
    for i in range(6, -1, -1):
        day_start = today - timedelta(days=i)
        day_end = day_start + timedelta(days=1)
        day_str = day_start.strftime('%Y-%m-%d')
        
        total = db.query(ScanHistory).filter(
            ScanHistory.timestamp >= day_start,
            ScanHistory.timestamp < day_end
        ).count()
        
        high = db.query(ScanHistory).filter(
            ScanHistory.timestamp >= day_start,
            ScanHistory.timestamp < day_end,
            ScanHistory.threat_level == "High"
        ).count()
        
        result.append({"date": day_str, "total": total, "high": high})
    return result

class ContactRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: str = Field(..., min_length=5, max_length=255, pattern=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    subject: str = Field(..., min_length=3, max_length=200)
    inquiry_type: str = Field(..., min_length=2, max_length=50)
    message: str = Field(..., min_length=10, max_length=3000)

@app.get("/tracker")
def tracker_page(request: Request, user: Optional[User] = Depends(get_current_user)):
    return templates.TemplateResponse(request, "tracker.html", {"active_page": "tracker", "user": user})

@app.get("/threats")
def threats_page(request: Request, user: Optional[User] = Depends(get_current_user), db: Session = Depends(database.get_db)):
    scans = db.query(ScanHistory).order_by(ScanHistory.timestamp.desc()).limit(100).all()
    return templates.TemplateResponse(request, "threats.html", {"active_page": "threats", "user": user, "scans": scans})

@app.get("/tools")
def tools_page(request: Request, user: Optional[User] = Depends(get_current_user)):
    return templates.TemplateResponse(request, "tools.html", {"active_page": "tools", "user": user})

@app.get("/api-docs")
def api_docs_page(request: Request, user: Optional[User] = Depends(get_current_user)):
    return templates.TemplateResponse(request, "api_docs.html", {"active_page": "api_docs", "user": user})

@app.get("/privacy")
def privacy_page(request: Request, user: Optional[User] = Depends(get_current_user)):
    return templates.TemplateResponse(request, "privacy.html", {"active_page": "privacy", "user": user})

@app.get("/about")
def about_page(request: Request, user: Optional[User] = Depends(get_current_user)):
    return templates.TemplateResponse(request, "about.html", {"active_page": "about", "user": user})

@app.get("/contact")
def contact_page(request: Request, user: Optional[User] = Depends(get_current_user)):
    return templates.TemplateResponse(request, "contact.html", {"active_page": "contact", "user": user})

@app.get("/api/user/history")
def get_user_history(
    limit: int = Query(default=10, ge=1, le=50),
    user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    if not user:
        return []
    scans = db.query(ScanHistory).filter(ScanHistory.user_id == user.id).order_by(ScanHistory.timestamp.desc()).limit(limit).all()
    return [
        {
            "url": s.url,
            "score": s.score,
            "threat_level": s.threat_level,
            "timestamp": s.timestamp.isoformat() if s.timestamp else None
        }
        for s in scans
    ]

@app.post("/api/user/history/clear")
def clear_user_history(
    user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        db.query(ScanHistory).filter(ScanHistory.user_id == user.id).delete()
        db.commit()
        return {"status": "success", "message": "Personal scan history permanently purged."}
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Database error clearing history.")

@app.get("/api/user/history/export")
def export_user_history_csv(
    user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    scans = db.query(ScanHistory).filter(ScanHistory.user_id == user.id).order_by(ScanHistory.timestamp.desc()).all()
    csv_lines = ["url,threat_score,threat_level,timestamp_utc"]
    for s in scans:
        ts = s.timestamp.isoformat() if s.timestamp else ""
        csv_lines.append(f'"{s.url}",{s.score},"{s.threat_level}","{ts}"')
    return Response(
        content="\n".join(csv_lines),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=personal_scan_history_{user.username}_{int(time.time())}.csv"}
    )

@app.post("/api/contact")
def submit_contact(request: Request, contact: ContactRequest, db: Session = Depends(database.get_db), user: Optional[User] = Depends(get_current_user)):
    check_rate_limit(request, limit=5, window=60)
    try:
        msg = ContactMessage(
            name=contact.name.strip(),
            email=contact.email.strip(),
            subject=contact.subject.strip(),
            inquiry_type=contact.inquiry_type.strip(),
            message=contact.message.strip(),
            user_id=user.id if user else None
        )
        db.add(msg)
        db.commit()
        return {"status": "success", "message": "Your message has been received by our security team."}
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Database error logging contact message.")

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., min_length=5, max_length=255, pattern=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    password: str = Field(..., min_length=8, max_length=128)

@app.get("/register")
def register_page(request: Request, user: Optional[User] = Depends(get_current_user)):
    if user:
        return RedirectResponse(url="/")
    return RedirectResponse(url="/login?mode=register")

@app.post("/api/register")
def api_register(request: Request, req: RegisterRequest, db: Session = Depends(database.get_db)):
    check_rate_limit(request, limit=5, window=60)
    clean_username = req.username.strip()
    if not re.match(r"^[a-zA-Z0-9_-]+$", clean_username):
        raise HTTPException(status_code=400, detail="Username can only contain alphanumeric characters, underscores, and dashes.")
    
    if db.query(User).filter(User.username == clean_username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    try:
        hashed = get_password_hash(req.password)
        user_count = db.query(User).count()
        assigned_role = "admin" if user_count == 0 else "analyst"
        user = User(username=clean_username, email=req.email, hashed_password=hashed, role=assigned_role, is_active=True)
        db.add(user)
        db.commit()
        return {"status": "success", "role": assigned_role}
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Database error during registration.")

@app.get("/login")
def login_page(request: Request, user: Optional[User] = Depends(get_current_user)):
    if user:
        return RedirectResponse(url="/")
    return templates.TemplateResponse(request, "login.html", {"active_page": "login"})

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login")
def api_login(request: Request, req: LoginRequest, db: Session = Depends(database.get_db)):
    check_rate_limit(request, limit=8, window=60)
    clean_username = req.username.strip()
    user = db.query(User).filter(User.username == clean_username).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not getattr(user, "is_active", True):
        raise HTTPException(status_code=403, detail="Account has been suspended by SOC Administration.")
    
    request.session.clear()
    request.session["user_id"] = user.id
    return {"status": "success", "role": getattr(user, "role", "analyst")}

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/")

@app.get("/profile")
def profile_page(
    request: Request,
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
    user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    if not user:
        return RedirectResponse(url="/login")
    
    offset = (page - 1) * limit
    total_scans = db.query(ScanHistory).filter(ScanHistory.user_id == user.id).count()
    scans = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == user.id)
        .order_by(ScanHistory.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    
    total_pages = max(1, (total_scans + limit - 1) // limit)
    
    return templates.TemplateResponse(
        request,
        "profile.html",
        {
            "active_page": "profile",
            "user": user,
            "scans": scans,
            "page": page,
            "total_pages": total_pages,
            "total_scans": total_scans
        }
    )

# --- Feature A: Enterprise RBAC & Admin Console Endpoints ---

class UserRoleUpdate(BaseModel):
    role: str = Field(..., pattern="^(admin|analyst)$")

class UserStatusUpdate(BaseModel):
    is_active: bool

class InquiryStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(pending|resolved|dismissed)$")

@app.get("/admin")
def admin_page(request: Request, user: User = Depends(require_admin)):
    return templates.TemplateResponse(request, "admin.html", {"active_page": "admin", "user": user})

@app.get("/api/admin/users")
def get_admin_users(admin: User = Depends(require_admin), db: Session = Depends(database.get_db)):
    users = db.query(User).order_by(User.id.asc()).all()
    user_list = []
    for u in users:
        scan_count = db.query(ScanHistory).filter(ScanHistory.user_id == u.id).count()
        user_list.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": getattr(u, "role", "analyst"),
            "is_active": getattr(u, "is_active", True),
            "scan_count": scan_count,
            "created_at": u.created_at.isoformat() if u.created_at else None
        })
    return user_list

@app.post("/api/admin/users/{user_id}/role")
def update_user_role(
    user_id: int,
    payload: UserRoleUpdate,
    admin: User = Depends(require_admin),
    db: Session = Depends(database.get_db)
):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == admin.id and payload.role != "admin":
        raise HTTPException(status_code=400, detail="Admins cannot demote their own account.")
    
    old_role = getattr(target, "role", "analyst")
    target.role = payload.role
    
    log = AuditLog(
        admin_id=admin.id,
        action="update_role",
        target=f"User #{target.id} ({target.username})",
        details=f"Changed role from {old_role} to {payload.role}"
    )
    db.add(log)
    db.commit()
    return {"status": "success", "message": f"User #{target.id} role updated to {payload.role}"}

@app.post("/api/admin/users/{user_id}/status")
def update_user_status(
    user_id: int,
    payload: UserStatusUpdate,
    admin: User = Depends(require_admin),
    db: Session = Depends(database.get_db)
):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == admin.id and not payload.is_active:
        raise HTTPException(status_code=400, detail="Admins cannot suspend their own account.")
    
    target.is_active = payload.is_active
    action_name = "reactivate_account" if payload.is_active else "suspend_account"
    log = AuditLog(
        admin_id=admin.id,
        action=action_name,
        target=f"User #{target.id} ({target.username})",
        details=f"Account status set to {'ACTIVE' if payload.is_active else 'SUSPENDED'}"
    )
    db.add(log)
    db.commit()
    return {"status": "success", "message": f"User #{target.id} status updated."}

@app.get("/api/admin/metrics")
def get_admin_metrics(admin: User = Depends(require_admin), db: Session = Depends(database.get_db)):
    total_users = db.query(User).count()
    total_admins = db.query(User).filter(User.role == "admin").count()
    total_scans = db.query(ScanHistory).count()
    pending_inquiries = db.query(ContactMessage).filter(ContactMessage.status == "pending").count()
    return {
        "total_users": total_users,
        "total_admins": total_admins,
        "total_scans": total_scans,
        "pending_inquiries": pending_inquiries
    }

@app.get("/api/admin/inquiries")
def get_admin_inquiries(
    status: str = Query(default="all"),
    admin: User = Depends(require_admin),
    db: Session = Depends(database.get_db)
):
    query = db.query(ContactMessage)
    if status != "all":
        query = query.filter(ContactMessage.status == status)
    messages = query.order_by(ContactMessage.timestamp.desc()).limit(100).all()
    return [
        {
            "id": m.id,
            "name": m.name,
            "email": m.email,
            "subject": m.subject,
            "inquiry_type": m.inquiry_type,
            "message": m.message,
            "status": getattr(m, "status", "pending"),
            "timestamp": m.timestamp.isoformat() if m.timestamp else None
        }
        for m in messages
    ]

@app.post("/api/admin/inquiries/{message_id}/status")
def update_inquiry_status(
    message_id: int,
    payload: InquiryStatusUpdate,
    admin: User = Depends(require_admin),
    db: Session = Depends(database.get_db)
):
    msg = db.query(ContactMessage).filter(ContactMessage.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Inquiry message not found")
    msg.status = payload.status
    log = AuditLog(
        admin_id=admin.id,
        action="update_inquiry_status",
        target=f"Inquiry #{msg.id} ({msg.subject[:30]})",
        details=f"Status set to {payload.status}"
    )
    db.add(log)
    db.commit()
    return {"status": "success", "message": f"Inquiry status updated to {payload.status}"}

@app.get("/api/admin/audit-logs")
def get_admin_audit_logs(admin: User = Depends(require_admin), db: Session = Depends(database.get_db)):
    results = (
        db.query(AuditLog, User.username)
        .outerjoin(User, AuditLog.admin_id == User.id)
        .order_by(AuditLog.timestamp.desc())
        .limit(100)
        .all()
    )
    return [
        {
            "id": log.id,
            "admin_id": log.admin_id,
            "admin_username": username if username else "System",
            "action": log.action,
            "target": log.target,
            "details": log.details,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None
        }
        for log, username in results
    ]

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 8000))
    reload = os.environ.get("DEBUG", "false").lower() == "true"
    uvicorn.run("app:app", host=host, port=port, reload=reload)

