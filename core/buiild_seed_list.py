import re
import sqlite3
from pathlib import Path
from requests_tor import RequestsTor
import sys

sys.path.append(str(Path(__file__).resolve().parent.parent))
from core.crawler import crawl_onion
from core.identity import rotate_identity

# --- Constants ---
ONION_REGEX = r"http[s]?://[a-zA-Z0-9\-\.]{10,100}\.onion"
HEADERS = {"User-Agent": "GhostcrawlerBot/1.0"}
SAVE_PATH = Path("../data/seed_onions.txt")
DB_PATH = Path("../data/onion_sources.db")
ROTATE_INTERVAL = 20

# --- Verified Onion Sources ---
sources = {
    "SysLeaks": "http://wa2y26bd7vw4xpy6hglnrnsrk54ouveaqxiuutjkejccqqnwgcryvuqd.onion/",
    "StrongholdPaste": "http://strongerw2ise74v3duebgsvug4mehyhlpa7f6kfwnas7zofs3kov7yd.onion/all",
    "dark.fail": "http://darkfailenbsdla5mal2mxn2uz66od5vtzd5qozslagrfzachha3f3id.onion/",
    "tor66": "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/",
    "ahmia": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/",
    "deeplinksdump": "http://deepqelxz6iddqi5obzla2bbwh5ssyqqobxin27uzkr624wtubhto3ad.onion/",
    "bobby": "http://bobby64o755x3gsuznts6hf6agxqjcz5bop6hs7ejorekbm7omes34ad.onion/",
    "torch": "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion/cgi-bin/omega/omega",
    "haystack": "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/",
    "deepsearch": "http://search7tdrcvri22rieiwgi5g46qnwsesvnubqav2xakhezv4hjzkkad.onion/",
    "tordex": "http://tordexpmg4xy32rfp4ovnz7zq5ujoejwq2u26uxxtkscgo5u3losmeid.onion/",
    "vormweb": "http://volkancfgpi4c7ghph6id2t7vcntenuly66qjt6oedwtjmyj4tkk5oqd.onion/",
    "excavator": "http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion/",
    "torland": "http://torlgu6zhhtwe73fdu76uiswgnkfvukqfujofxjfo7vzoht2rndyhxyd.onion/",
    "onionlinksv3": "http://s4k4ceiapwwgcm3mkb6e4diqecpo7kvdnfr5gg7sph7jjppqkvwwqtyd.onion/ ",
    "darkpug": "http://jgwe5cjqdbyvudjqskaajbfibfewew4pndx52dye7ug3mt3jimmktkid.onion/",
    "darksearch-fresh": "http://darkzqtmbdeauwq5mzcmgeeuhet42fhfjj4p5wbak3ofx2yqgecoeqyd.onion/fresh.php",
    "darksearch": "http://darkzqtmbdeauwq5mzcmgeeuhet42fhfjj4p5wbak3ofx2yqgecoeqyd.onion/",
    "darksearch-top": "http://darkzqtmbdeauwq5mzcmgeeuhet42fhfjj4p5wbak3ofx2yqgecoeqyd.onion/top-onions.php",
    "riddlersstash": "http://rstashbrabv5ezel76m2vdzet4szdzncwvgd2q5y3kbsdw3q6spcglid.onion",
    "riddlersstash-latest": "http://rstashbrabv5ezel76m2vdzet4szdzncwvgd2q5y3kbsdw3q6spcglid.onion/dashboard/latest-bases",
    "blackcloud": "http://bcloudwenjxgcxjh6uheyt72a5isimzgg4kv5u74jb2s22y3hzpwh6id.onion/",
    "zerobin": "http://zerobinftagjpeeebbvyzjcqyjpmjvynj5qlexwyxe7l3vqejxnqv5qd.onion/",
    "onionarchive": "http://x4ijfwy76n6jl7rs4qyhe6qi5rv6xyuos3kaczgjpjcajigjzk3k7wqd.onion/",
    "oss": "http://3fzh7yuupdfyjhwt3ugzqqof6ulbcl27ecev33knxe3u7goi3vfn2qqd.onion/oss/",
    "torgle": "http://iy3544gmoeclh5de6gez2256v6pjh4omhpqdh2wpeeppjtvqmjhkfwad.onion/torgle/",
    "darkdir": "http://l7vh56hxm3t4tzy75nxzducszppgi45fyx2wy6chujxb2rhy7o5r62ad.onion/",
    "hoodle": "http://nr2dvqdot7yw6b5poyjb7tzot7fjrrweb2fhugvytbbio7ijkrvicuid.onion/",
    "tastyonions": "http://22tojepqmpah32fkeuurutki7o5bmb45uhmgzdg4l2tk34fkdafgt7id.onion/",
    "trustwiki": "http://wiki6dtqpuvwtc5hopuj33eeavwa6sik7sy57cor35chkx5nrbmmolqd.onion/",
    "wikipage": "http://uquroyobsaquslaunwkz6bmc3wutpzvwe7mv62xeq64645a57bugnsyd.onion/",
    "gdark": "http://zb2jtkhnbvhkya3d46twv3g7lkobi4s62tjffqmafjibixk6pmq75did.onion/gdark/search.php",
    "metager": "http://metagerv65pwclop2rsfzg4jwowpavpwd6grhhlvdgsswvo6ii4akgyd.onion/",
    "onion.taxi": "http://taxiwgvywwmvcd63cwvq4m5ubsgxtjl2hzkjdpfhjvwcslgy2rmmuoid.onion/",
    "amnesia": "http://amnesia7u5odx5xbwtpnqk3edybgud5bmiagu75bnqx2crntw5kry7ad.onion/",
    "nexus": "http://nexus3xpq52kd7fnobiwwndytystymajamfwoawhppn2wqgqetoucoyd.onion/",
    "tortop": "http://tortopaik2kzc277jfuxmzvc74ekpdvfd7b3bkftkfvku2qiinbzlhid.onion/",
    "navigator": "http://navigatorf3jbtpd65e6dobehgbcz6erpzwhzffuylgiqg4hcornygad.onion/",
    "tormarks": "http://tormarksq5pj5sbdxilm24xpjupsn6t5ntz2gsiiy4xufukna5eno7id.onion/tormarks-online.html",
    "torjet": "http://torjetp2atnulvrrhbbo6sidoxsvgxf4li5h3n2vu3uudn3tcoxl4ayd.onion/",
    "onionking": "http://onionkimes2trn6zj73lvc2gd2myrphtp42zyctrqw7oyyuc7rbgj2ad.onion/",

    # Add more as needed
}

# --- Setup ---
SAVE_PATH.parent.mkdir(parents=True, exist_ok=True)
SAVE_PATH.touch(exist_ok=True)

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS onions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE,
    source TEXT,
    tag TEXT DEFAULT 'unknown',
    live INTEGER DEFAULT 1,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

session = RequestsTor(tor_ports=(9050,), autochange_id=False)
counter = 0

# --- Utilities ---
def extract_onions(text):
    return list(set(re.findall(ONION_REGEX, text)))

def classify_onion(url):
    if any(x in url for x in ["hub", "forum", "dread"]):
        return "forum"
    if "paste" in url:
        return "paste"
    if "market" in url or "store" in url:
        return "market"
    if "leak" in url or "dump" in url:
        return "leak"
    return "unknown"

# --- Crawl Sources ---
result = crawl_onion(url, depth=3, max_depth=4)
try:
    if result.get("found_onions"):
        print(f'Crawling {result} onion')
        for onion_url in result["found_onions"]:
            tag = classify_onion(onion_url)
            cursor.execute("INSERT OR IGNORE INTO onions (url, source, tag) VALUES (?, ?, ?)",
                           (onion_url, source_name, tag))
            with SAVE_PATH.open("a", encoding="utf-8") as f:
                f.write(onion_url + "\n")

except Exception as e:
    print(f'[!] Error Crawling onion: {e}')
# --- Wrap-up ---
conn.commit()
conn.close()
print("✓ Verified onion list updated.")
