from flask import Flask, render_template, request, jsonify, make_response
from urllib.parse import urlparse, urljoin
import requests, re, ipaddress, socket, json, time, os
from bs4 import BeautifulSoup
from collections import Counter

app = Flask(__name__)
UA = "Focus360BlogSEOAudit/1.0 (+public-page SEO diagnostics)"
TIMEOUT = 18
MAX_BYTES = 2_500_000
ALLOWED_ORIGINS = {x.strip() for x in os.environ.get("ALLOWED_ORIGINS", "https://www.focus360blog.online,https://focus360blog.online").split(",") if x.strip()}

def validate_public_url(raw):
    try:
        u=urlparse(raw.strip())
        if u.scheme not in ("http","https") or not u.hostname:
            raise ValueError("Enter a full http:// or https:// URL.")
        if u.username or u.password:
            raise ValueError("URLs containing credentials are not allowed.")
        host=u.hostname.lower()
        if host=="localhost" or host.endswith(".local"):
            raise ValueError("Local/private hosts are not allowed.")
        # Resolve and reject private/reserved IPs to reduce SSRF risk.
        infos=socket.getaddrinfo(host, u.port or (443 if u.scheme=="https" else 80), type=socket.SOCK_STREAM)
        for info in infos:
            ip=ipaddress.ip_address(info[4][0])
            if not ip.is_global:
                raise ValueError("Private or non-public addresses are not allowed.")
        return raw.strip()
    except ValueError:
        raise
    except Exception as e:
        raise ValueError("URL could not be validated. Check the domain and try again.") from e

def fetch(url, max_bytes=MAX_BYTES):
    headers={"User-Agent":UA,"Accept":"text/html,application/xhtml+xml,*/*"}
    current=url
    # Validate every redirect destination to reduce SSRF risk.
    for _ in range(6):
        validate_public_url(current)
        with requests.get(current,headers=headers,timeout=TIMEOUT,stream=True,allow_redirects=False) as r:
            if r.is_redirect or r.is_permanent_redirect:
                location=r.headers.get("Location")
                if not location: raise ValueError("Redirect response had no Location header.")
                current=urljoin(current,location)
                continue
            r.raise_for_status()
            chunks=[]; total=0
            for chunk in r.iter_content(65536):
                if not chunk: continue
                total+=len(chunk)
                if total>max_bytes: raise ValueError("Page is too large (limit 2.5 MB).")
                chunks.append(chunk)
            return current,b"".join(chunks),r.headers.get("Content-Type",""),r.status_code
    raise ValueError("Too many redirects (maximum 5).")

@app.after_request
def add_cors_headers(response):
    origin=request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS, GET"
    return response

@app.route("/api/audit",methods=["OPTIONS"])
def api_audit_options():
    return make_response("",204)

@app.route("/health")
def health():
    return jsonify({"status":"ok","service":"Focus360Blog SEO Checker"})

def get_text(el):
    return el.get_text(" ",strip=True) if el else ""

def audit_url(raw):
    url=validate_public_url(raw)
    final_url,body,ctype,status=fetch(url)
    if "html" not in ctype.lower() and not body.lstrip().startswith(b"<"):
        raise ValueError("The URL did not return HTML.")
    soup=BeautifulSoup(body,"html.parser")
    pagehost=urlparse(final_url).hostname
    checks=[]
    def check(name, category, weight, state, detail, recommendation=""):
        checks.append({"name":name,"category":category,"weight":weight,"status":state,"detail":detail,"recommendation":recommendation})
    title=get_text(soup.title)
    desc=soup.find("meta",attrs={"name":re.compile("^description$",re.I)})
    description=(desc.get("content","").strip() if desc else "")
    canonical_tag=soup.find("link",rel=lambda x:x and "canonical" in ([v.lower() for v in x] if isinstance(x,list) else str(x).lower().split()))
    canonical=urljoin(final_url,canonical_tag.get("href","").strip()) if canonical_tag and canonical_tag.get("href") else ""
    robots_meta=" ".join(m.get("content","") for m in soup.find_all("meta",attrs={"name":re.compile("^(robots|googlebot)$",re.I)})).lower()
    h1=[get_text(x) for x in soup.find_all("h1") if get_text(x)]
    h2=len(soup.find_all("h2")); h3=len(soup.find_all("h3"))
    imgs=soup.find_all("img"); missing_alt=[i for i in imgs if not i.has_attr("alt") or not i.get("alt","").strip()]
    anchors=soup.find_all("a",href=True); internal=[]; external=[]
    for a in anchors:
        target=urljoin(final_url,a["href"])
        if urlparse(target).hostname==pagehost: internal.append(target)
        elif urlparse(target).scheme in ("http","https"): external.append(target)
    jsonld=soup.find_all("script",type=re.compile("ld\\+json",re.I)); valid_json=0; schema_types=[]
    for script in jsonld:
        try:
            data=json.loads(script.string or script.get_text())
            valid_json+=1
            stack=data if isinstance(data,list) else [data]
            while stack:
                obj=stack.pop()
                if isinstance(obj,dict):
                    typ=obj.get("@type")
                    if typ: schema_types += typ if isinstance(typ,list) else [typ]
                    graph=obj.get("@graph")
                    if isinstance(graph,list): stack.extend(graph)
                elif isinstance(obj,list): stack.extend(obj)
        except Exception: pass
    viewport=bool(soup.find("meta",attrs={"name":re.compile("^viewport$",re.I)}))
    lang=bool(soup.html and soup.html.get("lang"))
    og_title=bool(soup.find("meta",attrs={"property":"og:title"}))
    og_image=bool(soup.find("meta",attrs={"property":"og:image"}))
    word_count=len(re.findall(r"\b[\w'-]+\b",soup.get_text(" ",strip=True)))
    canonical_match=bool(canonical and urlparse(canonical).scheme in ("http","https") and urlparse(canonical).hostname==pagehost)
    noindex=bool(re.search(r"\bnoindex\b",robots_meta))
    # weighted findings: each check can score partial via status
    check("HTTP response", "Technical", 4, "pass" if status==200 else "warning", f"HTTP {status}")
    check("Title tag", "On-page", 8, "pass" if title else "fail", f"{len(title)} characters: {title or 'missing'}", "Add one unique, descriptive <title>.")
    check("Title length", "On-page", 4, "pass" if 30<=len(title)<=60 else "warning", f"{len(title)} characters (guide: 30–60)", "Keep the title concise and distinctive.")
    check("Meta description", "On-page", 7, "pass" if description else "fail", f"{len(description)} characters: {description or 'missing'}", "Add a page-specific meta description.")
    check("Meta description length", "On-page", 3, "pass" if 120<=len(description)<=160 else "warning", f"{len(description)} characters (guide: 120–160)", "Write a concise description; Google may rewrite snippets.")
    check("H1 heading", "Content", 6, "pass" if len(h1)==1 else ("warning" if len(h1)>1 else "fail"), f"{len(h1)} H1(s): {' | '.join(h1[:3]) or 'none'}", "Use one clear main heading.")
    check("Subheadings", "Content", 3, "pass" if h2+h3 else "warning", f"{h2} H2 and {h3} H3 headings", "Structure long content with meaningful H2/H3 headings.")
    check("Canonical tag", "Technical", 7, "pass" if canonical else "warning", canonical or "No canonical link detected", "Set a canonical URL where duplicate or alternate URLs exist.")
    check("Canonical host", "Technical", 3, "pass" if canonical_match else ("warning" if canonical else "fail"), canonical or "Not available", "Confirm canonical points to the preferred public URL.")
    check("Robots meta", "Technical", 6, "fail" if noindex else "pass", robots_meta or "No robots meta directive detected", "Remove unintended noindex from pages meant to appear in search.")
    check("HTTPS", "Technical", 4, "pass" if urlparse(final_url).scheme=="https" else "warning", final_url, "Use HTTPS.")
    check("Image ALT coverage", "Images", 6, "pass" if not missing_alt else "warning", f"{len(imgs)-len(missing_alt)}/{len(imgs)} images have non-empty ALT; {len(missing_alt)} missing", "Add useful ALT text to informative images; decorative images may use alt=\"\".")
    check("Internal links", "Links", 4, "pass" if internal else "warning", f"{len(internal)} internal links", "Link to relevant supporting pages.")
    check("External links", "Links", 2, "pass" if external else "warning", f"{len(external)} external links", "Include external links only where useful.")
    check("JSON-LD structured data", "Structured data", 6, "pass" if valid_json else "warning", f"{valid_json} valid JSON-LD block(s); types: {', '.join(sorted(set(schema_types))) or 'not detected'}", "Use appropriate valid structured data; validate with Rich Results Test.")
    check("Viewport meta", "Mobile", 3, "pass" if viewport else "warning", "Present" if viewport else "Missing", "Include a responsive viewport meta tag.")
    check("HTML language", "Accessibility", 2, "pass" if lang else "warning", soup.html.get("lang","missing") if soup.html else "Missing html element", "Declare the document language.")
    check("Open Graph title", "Social", 1, "pass" if og_title else "warning", "Present" if og_title else "Missing", "Add OG title if social previews matter.")
    check("Open Graph image", "Social", 1, "pass" if og_image else "warning", "Present" if og_image else "Missing", "Add a suitable OG image for sharing.")
    check("Content text length", "Content", 4, "pass" if word_count>=500 else "warning", f"About {word_count} words in fetched HTML", "Ensure content fully answers the reader's query; word count alone is not a ranking factor.")
    # robots + sitemap checks
    origin=f"{urlparse(final_url).scheme}://{urlparse(final_url).netloc}"
    robots_url=urljoin(origin,"/robots.txt")
    robots_text=""; robots_status=None
    try:
        _,rb,_,robots_status=fetch(robots_url,200000); robots_text=rb.decode("utf-8","replace")
    except Exception as e: robots_text=str(e)
    check("robots.txt", "Crawlability", 4, "pass" if robots_status==200 else "warning", f"HTTP {robots_status if robots_status else 'unavailable'} at {robots_url}", "Check robots.txt does not block important Blogger paths.")
    sitemap_candidates=[]
    for line in robots_text.splitlines():
        if line.lower().startswith("sitemap:"): sitemap_candidates.append(line.split(":",1)[1].strip())
    sitemap_candidates += [urljoin(origin,"/sitemap.xml"),urljoin(origin,"/sitemap_index.xml")]
    sitemap_found=None; sitemap_note=""
    for sm in dict.fromkeys(sitemap_candidates):
        try:
            _,sb,st,ss=fetch(sm,500000)
            if ss==200 and (b"<urlset" in sb.lower() or b"<sitemapindex" in sb.lower() or "xml" in st.lower()):
                sitemap_found=sm;break
        except Exception: pass
    check("Sitemap availability", "Crawlability", 4, "pass" if sitemap_found else "warning", sitemap_found or "No sitemap found at standard/robots-listed locations", "Confirm Blogger sitemap is submitted in Search Console; this check cannot verify submission.")
    earned=0; total=0
    for c in checks:
        total+=c["weight"]
        earned+=c["weight"]*(1 if c["status"]=="pass" else .5 if c["status"]=="warning" else 0)
    score=round(100*earned/total)
    return {"url":url,"finalUrl":final_url,"score":score,"label":"Technical/on-page diagnostic score (not Google's ranking score)","checks":checks,
            "summary":{"pass":sum(c["status"]=="pass" for c in checks),"warning":sum(c["status"]=="warning" for c in checks),"fail":sum(c["status"]=="fail" for c in checks)},
            "details":{"title":title,"titleLength":len(title),"description":description,"descriptionLength":len(description),"canonical":canonical,"h1":h1,"h2":h2,"h3":h3,"images":len(imgs),"missingAlt":len(missing_alt),"internalLinks":len(internal),"externalLinks":len(external),"schemaTypes":sorted(set(schema_types)),"wordCount":word_count,"robotsTxt":robots_url,"sitemap":sitemap_found}}

@app.route("/")
def home(): return render_template("index.html")

@app.route("/api/audit",methods=["POST"])
def api_audit():
    data=request.get_json(silent=True) or {}
    try: return jsonify(audit_url(data.get("url","")))
    except ValueError as e: return jsonify({"error":str(e)}),400
    except requests.RequestException as e: return jsonify({"error":f"Could not fetch page: {e}"}),502
    except Exception as e: return jsonify({"error":"Audit failed: "+str(e)}),500

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5050)),debug=False)
