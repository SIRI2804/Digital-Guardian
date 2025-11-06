from flask import Flask, render_template, request, jsonify, send_file
from urllib.parse import urlparse
from difflib import SequenceMatcher
import io, re

app = Flask(__name__)

# ------------------------- CONFIG -------------------------
OFFICIAL_DOMAINS = {
    "google": ["google.com", "googleapis.com", "gstatic.com"],
    "openai": ["openai.com", "chatgpt.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com"],
    "apple": ["apple.com", "icloud.com", "me.com"]
}

ALL_OFFICIAL_DOMAINS = {d for v in OFFICIAL_DOMAINS.values() for d in v}
BRAND_KEYWORDS = {d.split('.')[-2] for d in ALL_OFFICIAL_DOMAINS if '.' in d}

PHISHING_BLOCKLIST = {"br-icloud.com.br", "retajconsultancy.com"}
LOOKALIKE_MAP = str.maketrans({'0':'o','1':'l','3':'e','5':'s','7':'t','@':'a','$':'s','!':'i','8':'b','2':'z','4':'a','6':'g','9':'g'})
SUSPICIOUS_TLDS = {'.tk','.xyz','.cf','.ga','.gq','.top','.ml','.pw'}
SUSPICIOUS_PREFIXES = ('secure-','login-','account-','signin-','update-','verify-')

def normalize_lookalikes(text): return re.sub(r'[^a-z0-9]','', text.translate(LOOKALIKE_MAP).lower())
def similarity_ratio(a,b): return SequenceMatcher(None,a,b).ratio()
def extract_domain(url):
    if not url.startswith(('http://','https://')): url='https://'+url
    p=urlparse(url); d=p.netloc.lower().split('@')[-1]
    if d.startswith('www.'): d=d[4:]
    return d.split(':')[0],p
def is_ip_address(d): return bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$',d))

def analyze_url(url):
    u=url.strip()
    if not u: return {"url":url,"status":"Malicious","confidence":100,"issues":["Empty or invalid URL"]}
    if any(ph in u.lower() for ph in PHISHING_BLOCKLIST):
        return {"url":url,"status":"Malicious","confidence":100,"issues":["Domain in phishing blocklist"]}
    try: d,_=extract_domain(u)
    except: return {"url":url,"status":"Malicious","confidence":100,"issues":["Invalid URL format"]}
    issues=[]; risk=0
    if is_ip_address(d): risk+=40; issues.append("Uses IP address instead of domain")
    if d in ALL_OFFICIAL_DOMAINS: return {"url":url,"status":"Safe","confidence":100,"issues":["Verified official domain"]}
    for part in re.split(r'[\.-]',d):
        n=normalize_lookalikes(part)
        for kw in BRAND_KEYWORDS:
            nk=normalize_lookalikes(kw)
            if n==nk: risk+=70; issues.append(f'Lookalike: "{part}" ~ "{kw}"'); break
            sim=similarity_ratio(n,nk)
            if sim>0.85: risk+=55; issues.append(f'"{part}" similar to "{kw}" ({sim:.2f})'); break
    if any(d.endswith(t) for t in SUSPICIOUS_TLDS):
        risk+=30; issues.append("Suspicious TLD detected")
    if not issues: issues=["No suspicious indicators found"]
    status="Malicious" if risk>=40 else "Safe"
    conf=min(100,max(50,50+int(risk*0.6)))
    return {"url":url,"status":status,"confidence":conf,"issues":issues}

@app.route('/')
def index(): return render_template('index.html')

@app.route('/analyze-bulk',methods=['POST'])
def analyze_bulk():
    data=request.get_json() or {}; urls=data.get("urls",[])
    res=[analyze_url(u) for u in urls]
    summary={"total":len(res),"safe":sum(r['status']=="Safe" for r in res),"malicious":sum(r['status']=="Malicious" for r in res)}
    return jsonify({"results":res,"summary":summary})

@app.route('/export-results',methods=['POST'])
def export_results():
    data=request.get_json() or {}; results=data.get('results',[])
    html="<html><head><meta charset='UTF-8'><title>Results</title><style>body{font-family:Arial;padding:20px;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #00ffff;padding:8px;}th{background:#00ffff;color:#000;}</style></head><body><h2>URL Analysis Results</h2><table><tr><th>URL</th><th>Status</th><th>Confidence</th><th>Issues</th></tr>"
    for r in results:
        html+=f"<tr><td>{r['url']}</td><td>{r['status']}</td><td>{r['confidence']}%</td><td>{'; '.join(r['issues'])}</td></tr>"
    html+="</table></body></html>"
    return send_file(io.BytesIO(html.encode()),mimetype='text/html',as_attachment=True,download_name='url_analysis_results.html')

if __name__=="__main__":
    app.run(host='0.0.0.0', port=8080)

