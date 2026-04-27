from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import whois
from fuzzywuzzy import fuzz
from urllib.parse import urlparse
import datetime

app = Flask(__name__)
CORS(app)

OFFICIAL_DOMAINS = ["nafath.sa", "splonline.com.sa", "saudi.gov.sa", "iam.gov.sa", "Absher.sa", "tawakkalna.adaia.gov.sa",
                     "najiz.sa", "portal.ca.gov.sa", "Sakani.sa", "Sehaty.sa", "moh.gov.sa", "jadarat.sa", "qiwa.sa", 
                     "mudad.com.sa", "etimad.sa", "balady.gov.sa", "ehsan.sa", "ejar.sa", "rega.gov.sa", "noor.moe.gov.sa",
                     "schools.madrasati.sa", "safeer2.moe.gov.sa", "masar.sa", "visa.mofa.gov.sa", "gosi.gov.sa", "hrsd.gov.sa",
                     "saber.sa", "fasah.sa", "zatca.gov.sa", "sbc.gov.sa", "joodeskan.sa", "nusuk.sa", "hawi.gov.sa", "hhrdf.org.sa", 
                     "doroob.sa", "sdb.gov.sa", "sfda.gov.sa", "portal.scfhs.org.sa", "saso.gov.sa", "investsaudi.sa",
                     "sama.gov.sa", "gac.gov.sa", "cma.org.sa", "nvg.gov.sa", "freelance.sa", "muqawil.org", "etec.gov.sa", "e-services.qiyas.sa", 
                     "sdaia.gov.sa", "spa.gov.sa", "stats.gov.sa", "gaca.gov.sa", "gea.gov.sa", "moia.gov.sa", "mrn.sa", "sidf.gov.sa", "momrah.gov.sa",
                     "maroof.sa", "saip.gov.sa", "ncm.gov.sa", "riyadbank.com", "alinma.com", "alahli.com", "alrajhibank.com.sa", "sab.com",
                     "anb.com.sa", "bankalbilad.com.sa", "bsf.sa", "aljazirabank.com.sa", "saib.com.sa", "gib.com", "stcbank.com.sa", "d360.com", "naama.sa"]

def get_clean_domain(domain):
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def analyze_url(url):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        parsed_url = urlparse(url)
        domain = get_clean_domain(parsed_url.netloc)
        
        official_domains_lower = [get_clean_domain(d) for d in OFFICIAL_DOMAINS]

        if domain in official_domains_lower:
            return {"status": "آمن", "details": "تطمن، الرابط موثوق"}

        for official in official_domains_lower:
            ratio = fuzz.ratio(domain, official)
            if 70 <= ratio < 100:
                return {"status": "غير آمن", "details": f"انتبه! محاولة انتحال"}

        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            if creation_date:
                age_days = (datetime.datetime.now() - creation_date).days
                if age_days < 180:
                    return {"status": "مشبوه", "details": f"النطاق حديث جداً (عمره {age_days} يوم)، احذر منه"}
        except:
            pass

        return {"status": "غير معروف", "details": "الرابط لا يتبع للجهات الرسمية في نظامنا. يرجى الحذر"}
            
    except Exception as e:
        return {"status": "Error", "details": "حدث خطأ أثناء فحص الرابط"}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({"status": "Error", "details": "لم يتم إرسال رابط"}), 400
        
    result = analyze_url(url)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, port=5000)