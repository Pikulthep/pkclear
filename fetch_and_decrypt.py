import time
import urllib.request
import binascii
import base64
import json
import os
import sys
from Crypto.Cipher import AES

sys.stdout.reconfigure(encoding="utf-8")

# 1. โหลด Configuration (ให้ความสำคัญกับ Environment Variables ของ GitHub ก่อน)
config_path = "config.json"
profile = {}
if os.path.exists(config_path):
    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)
    active_name = os.environ.get("ACTIVE_SOURCE", config.get("active_source", "cricfy"))
    profile = config.get("sources", {}).get(active_name, {})
else:
    print(f"Warning: {config_path} not found. Relying strictly on Environment Variables.")

# ดึงค่า Secrets จาก GitHub Actions หรือไฟล์ config
genz_url = os.environ.get("GENZ_URL", profile.get("genz_url", ""))
token = os.environ.get("CRICFY_TOKEN", profile.get("token", ""))
aes_key = os.environ.get("CRICFY_AES_KEY", profile.get("aes_key", ""))
aes_iv = os.environ.get("CRICFY_AES_IV", profile.get("aes_iv", ""))
xor_key_val = int(os.environ.get("XOR_KEY", profile.get("xor_key", 90)))

# ตรวจสอบว่ามี Key ครบหรือไม่
if not token or not aes_key or not aes_iv:
    print("Error: Missing critical secrets (Token, AES Key, or AES IV). Please set them in GitHub Secrets.")
    sys.exit(1)

aes_key_bytes = aes_key.encode('utf-8')
aes_iv_bytes = aes_iv.encode('utf-8')

# Fallback keys หากไม่มีใน config.json
default_keys = {
    "event_cats.json": "2c68753f2c3f342e05393b2e29742e222e",
    "events.json": "2c68753f2c3f342e29742e222e",
    "channels.json": "2c687539323b34343f3629750f69182c39340820131f322c380d0f3d0f12102c170e3968150e0b6a170e1769151e036a171b742e222e"
}
keys = profile.get("keys", default_keys)

# ตั้งค่า Base Pages URL ให้ทำงานกับ GitHub Pages อัตโนมัติ
github_user = os.environ.get("GITHUB_REPOSITORY_OWNER", "mdjamsad9")
github_repo_full = os.environ.get("GITHUB_REPOSITORY", "mdjamsad9/api")
github_repo = github_repo_full.split("/")[-1]
base_pages_url = f"https://{github_user}.github.io/{github_repo}/public_decrypted/"

print(f"Base Pages URL: {base_pages_url}")

# ================= Crypto Functions =================
def encrypt_xor_hex(text):
    data = text.encode('utf-8')
    encrypted = bytes([b ^ xor_key_val for b in data])
    return binascii.hexlify(encrypted).decode('utf-8')

def cfgMaterial():
    bArr = [29, 88, 17, 104, 66, 7, 91, 34, 113, 5, 47, 96]
    bArr2 = [71, 12, 83, 44, 9, 121, 36, 58, 101, 22, 63]
    bArr3 = [6, 39, 95, 14, 74, 52, 117, 27, 68, 3, 86, 41, 109]
    bArr4 = bytearray(32)
    for i in range(32):
        i10 = bArr[i % 12] & 255
        i11 = bArr2[((i * 3) + 1) % 11] & 255
        i12 = i & 7
        term1 = (i11 & 0xffffffff) >> (8 - i12)
        term2 = (i11 << i12) & 0xffffffff
        rotated = (term1 | term2) & 255
        val = (((i10 ^ rotated) ^ (bArr3[((i * 5) + 2) % 13] & 255)) ^ 90) ^ i
        bArr4[i] = val & 255
    return bArr4

def decrypt_cfj1(str_val):
    str_val = str_val.strip()
    if str_val.startswith("cfj1:"):
        str_val = str_val[5:]
    str_val = str_val.replace("\r", "").replace("\n", "").replace("\t", "").replace(" ", "")
    bArrDecode = base64.b64decode(str_val)
    bArrCfgMaterial = cfgMaterial()
    bArr = bytearray(len(bArrDecode))
    for i in range(len(bArrDecode)):
        val = (((bArrCfgMaterial[i % len(bArrCfgMaterial)] & 255) ^ bArrDecode[i]) ^ (((i * 29) + 71) & 255)) & 255
        bArr[len(bArrDecode) - 1 - i] = val
    return bArr.decode('utf-8', errors='ignore')

def swap_pairs(chars):
    for i in range(0, len(chars) - 1, 2):
        chars[i], chars[i+1] = chars[i+1], chars[i]
    return chars

def reverse_chars(chars):
    return chars[::-1]

def clean_base64(s):
    sb = [c for c in s if ('A' <= c <= 'Z') or ('a' <= c <= 'z') or ('0' <= c <= '9') or c == '+' or c == '/']
    s_cleaned = "".join(sb)
    while len(s_cleaned) % 4 != 0:
        s_cleaned += '='
    return s_cleaned

def decrypt_aes_v2(ciphertext):
    cipher = AES.new(aes_key_bytes, AES.MODE_CBC, aes_iv_bytes)
    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    if 1 <= pad_len <= 16 and all(x == pad_len for x in decrypted[-pad_len:]):
        decrypted = decrypted[:-pad_len]
    return decrypted

def decode_v2(encoded_str):
    try:
        decoded_bytes = base64.b64decode(encoded_str)
        char_array = list(decoded_bytes.decode('utf-8', errors='ignore'))
        char_array = reverse_chars(swap_pairs(char_array))
        decoded_str2 = "".join(char_array)
        
        if not decoded_str2.endswith("abcdefghijklmnop"):
            return f"Error: Decoded stage 1 does not end with abcdefghijklmnop."
        
        sub_bytes = base64.b64decode(decoded_str2[:-16])
        decrypted_aes = decrypt_aes_v2(sub_bytes)
        
        char_array_aes = list(decrypted_aes.decode('utf-8', errors='ignore'))
        cleaned_b64 = clean_base64("".join(reverse_chars(swap_pairs(char_array_aes))))
        return base64.b64decode(cleaned_b64).decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Decoding error: {e}"

def make_request(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 Cricfy2/1.0'})
    return urllib.request.urlopen(req, timeout=15).read().decode('utf-8').strip()

# ================= Main Execution =================

out_dir = "public_decrypted"
categories_dir = os.path.join(out_dir, "categories")
events_dir = os.path.join(out_dir, "events")
channels_dir = os.path.join(out_dir, "channels")

for d in [out_dir, categories_dir, events_dir, channels_dir]:
    os.makedirs(d, exist_ok=True)

# 1. Decrypt genzdev config
if genz_url:
    print("Processing URL 1 (GenzDev)...")
    try:
        raw_genz = make_request(genz_url)
        parsed_genz = json.loads(decrypt_cfj1(raw_genz))
        parsed_genz.update({
            "api_url": base_pages_url,
            "api2": base_pages_url,
            "categories_api": f"{base_pages_url}categories.json",
            "events_api": f"{base_pages_url}events.json",
            "channels_api_base": f"{base_pages_url}channels/"
        })
        with open(os.path.join(out_dir, "genzdev_config.json"), "w", encoding="utf-8") as f:
            json.dump(parsed_genz, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print("-> Failed URL 1:", e)

# Token for HMAC
fresh_hmac_encrypted = encrypt_xor_hex(f"{int(time.time())}|{token}")

# 2. Fetch Category List
categories_key = encrypt_xor_hex("v2/categories.txt")
categories_url = f"https://cricyplayers.com/data/getData.php?key={categories_key}&hmac={fresh_hmac_encrypted}"
parsed_cats = []
try:
    parsed_cats = json.loads(decode_v2(make_request(categories_url)))
    with open(os.path.join(out_dir, "categories.json"), "w", encoding="utf-8") as f:
        json.dump(parsed_cats, f, indent=2, ensure_ascii=False)
except Exception as e:
    print("-> Failed categories processing:", e)

# 3. Iterate and fetch category channels
if parsed_cats:
    for cat_item in parsed_cats:
        cat_name = "Unknown"
        try:
            table_name = cat_item.get("table_name")
            cat_id = cat_item.get("id")
            cat_meta = cat_item.get("cat", "{}")
            if isinstance(cat_meta, str): cat_meta = json.loads(cat_meta)
            
            clean_cat = {"id": cat_id, "table_name": table_name, "order_index": cat_item.get("order_index", 0), "cat": cat_meta}
            cat_name = cat_meta.get("name", "Unknown")
            
            if cat_id is not None:
                with open(os.path.join(categories_dir, f"{cat_id}.json"), "w", encoding="utf-8") as f:
                    json.dump(clean_cat, f, indent=2, ensure_ascii=False)
            
            if table_name:
                chan_url = f"https://cricyplayers.com/data/getData.php?key={encrypt_xor_hex(f'v2/channels/{table_name}.txt')}&hmac={fresh_hmac_encrypted}"
                raw_chan = make_request(chan_url)
                if raw_chan not in ["Not Found", ""]:
                    with open(os.path.join(channels_dir, f"{table_name}.json"), "w", encoding="utf-8") as f:
                        json.dump(json.loads(decode_v2(raw_chan)), f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"-> Failed processing category '{cat_name}': {e}")

# 4. Fetch additional keys (events, channels, etc.)
parsed_channels, parsed_events = [], []
for filename, key in keys.items():
    if not key: continue
    url = f"https://cricyplayers.com/data/getData.php?key={key}&hmac={fresh_hmac_encrypted}"
    try:
        parsed_res = json.loads(decode_v2(make_request(url)))
        with open(os.path.join(out_dir, filename), "w", encoding="utf-8") as f:
            json.dump(parsed_res, f, indent=2, ensure_ascii=False)
        if filename == "channels.json": parsed_channels = parsed_res
        elif filename == "events.json": parsed_events = parsed_res
    except Exception as e:
        print(f"-> Failed {filename}: {e}")

# ==============================================================================
# สวิตช์เปิด-ปิด การสร้างไฟล์ย่อย (เพื่อป้องกัน GitHub Repository ไฟล์ล้น/บวม)
# ตั้งค่า EXTRACT_INDIVIDUAL = true ใน GitHub Actions Environment หากจำเป็นต้องใช้ไฟล์ย่อย
# ==============================================================================
extract_individual = os.environ.get("EXTRACT_INDIVIDUAL", "false").lower() == "true"

if extract_individual:
    # 5. Extract Individual Channels
    if parsed_channels:
        for ch in parsed_channels:
            if "id" in ch:
                try:
                    ch_meta = json.loads(ch["channel"]) if isinstance(ch.get("channel"), str) else ch.get("channel", {})
                    l_meta = json.loads(ch["links"]) if isinstance(ch.get("links"), str) else ch.get("links", [])
                    clean_obj = {
                        "id": ch["id"], "order_index": ch.get("order_index", 0),
                        "name": ch_meta.get("name"), "logo": ch_meta.get("logo"),
                        "visible": ch_meta.get("visible", True), "is_playlist": ch_meta.get("is_playlist", False),
                        "links_metadata_path": ch_meta.get("links"), "links": l_meta
                    }
                    with open(os.path.join(channels_dir, f"{ch['id']}.json"), "w", encoding="utf-8") as f:
                        json.dump(clean_obj, f, indent=2, ensure_ascii=False)
                except Exception: pass

    # 6. Extract Individual Events
    if parsed_events:
        for ev in parsed_events:
            if "id" in ev:
                try:
                    ev_meta = json.loads(ev["event"]) if isinstance(ev.get("event"), str) else ev.get("event", {})
                    l_meta = json.loads(ev["links"]) if isinstance(ev.get("links"), str) else ev.get("links", [])
                    clean_evt = {
                        "id": ev["id"], "order_index": ev.get("order_index", 0),
                        "eventDetails": ev_meta.get("eventDetails", {}), "teamA": ev_meta.get("teamA", {}),
                        "teamB": ev_meta.get("teamB", {}), "visible": ev_meta.get("visible", True),
                        "priority": ev_meta.get("priority", -1), "date": ev_meta.get("date"),
                        "time": ev_meta.get("time"), "links_metadata_path": ev_meta.get("links"),
                        "links": l_meta
                    }
                    with open(os.path.join(events_dir, f"{ev['id']}.json"), "w", encoding="utf-8") as f:
                        json.dump(clean_evt, f, indent=2, ensure_ascii=False)
                except Exception: pass
else:
    print("Skipped extracting individual channel/event JSON files to prevent repo bloat.")

# 7. Generate API Spec
api_spec = { "api_name": "Decrypted API Gateway", "base_url": base_pages_url.rstrip("/") }
try:
    with open(os.path.join(out_dir, "api_spec.json"), "w", encoding="utf-8") as f:
        json.dump(api_spec, f, indent=2, ensure_ascii=False)
except Exception: pass

print("\nDone! Decrypted files written to:", os.path.abspath(out_dir))