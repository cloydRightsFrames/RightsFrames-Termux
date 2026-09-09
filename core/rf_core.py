"""Portable RightsFrames core -- no Termux/Android dependencies."""
import sqlite3, hashlib, hmac, json, os, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

DATA_DIR = os.environ.get("RF_DATA_DIR", "/data")
LEDGER_DB = os.path.join(DATA_DIR, "ledger.db")
ANCHOR_LOG = os.path.join(DATA_DIR, "anchors.jsonl")
PRIV_KEY_PATH = os.path.join(DATA_DIR, "signing_key.pem")
PUB_KEY_PATH = os.path.join(DATA_DIR, "signing_key.pub.pem")

def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(LEDGER_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS ledger_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, entry_type TEXT NOT NULL,
        payload TEXT NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL)""")
    conn.commit(); conn.close()

def load_or_create_keypair():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(PRIV_KEY_PATH):
        priv = Ed25519PrivateKey.generate()
        open(PRIV_KEY_PATH, "wb").write(priv.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        os.chmod(PRIV_KEY_PATH, 0o600)
        open(PUB_KEY_PATH, "wb").write(priv.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        return priv
    return serialization.load_pem_private_key(open(PRIV_KEY_PATH, "rb").read(), password=None)

def append_entry(entry_type, payload_dict):
    payload = json.dumps(payload_dict, sort_keys=True)
    conn = sqlite3.connect(LEDGER_DB); cur = conn.cursor()
    cur.execute("SELECT id, entry_hash FROM ledger_entries ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    last_id, prev_hash = (0, "0"*64) if row is None else row
    new_id = last_id + 1
    ts = time.strftime("%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime())
    entry_hash = hashlib.sha256(f"{new_id}|{prev_hash}|{ts}|{entry_type}|{payload}".encode()).hexdigest()
    cur.execute("INSERT INTO ledger_entries (id,ts,entry_type,payload,prev_hash,entry_hash) VALUES (?,?,?,?,?,?)",
                (new_id, ts, entry_type, payload, prev_hash, entry_hash))
    conn.commit(); conn.close()
    return new_id, entry_hash

def verify_chain():
    conn = sqlite3.connect(f"file:{LEDGER_DB}?mode=ro", uri=True)
    cur = conn.cursor()
    cur.execute("SELECT id,ts,entry_type,payload,prev_hash,entry_hash FROM ledger_entries ORDER BY id")
    rows = cur.fetchall(); conn.close()
    expected_prev = "0"*64
    for rid, ts, etype, payload, prev_hash, stored in rows:
        if len(prev_hash) != 64 or len(stored) != 64:
            return False, f"id={rid} invalid hash length"
        if not hmac.compare_digest(prev_hash, expected_prev):
            return False, f"id={rid} chain broken"
        calc = hashlib.sha256(f"{rid}|{prev_hash}|{ts}|{etype}|{payload}".encode()).hexdigest()
        if not hmac.compare_digest(calc, stored):
            return False, f"id={rid} content tampered"
        expected_prev = stored
    return True, f"{len(rows)} rows valid"

def chain_state():
    conn = sqlite3.connect(f"file:{LEDGER_DB}?mode=ro", uri=True); cur = conn.cursor()
    cur.execute("SELECT id, entry_hash FROM ledger_entries ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    cur.execute("SELECT count(*) FROM ledger_entries"); n = cur.fetchone()[0]
    conn.close()
    return (row[0] if row else 0, row[1] if row else "0"*64, n)

def read_anchors():
    if not os.path.exists(ANCHOR_LOG): return []
    return [json.loads(l) for l in open(ANCHOR_LOG) if l.strip()]

def create_anchor():
    ok, msg = verify_chain()
    if not ok: return False, f"refusing to anchor -- {msg}"
    head_id, head_hash, n = chain_state()
    anchors = read_anchors()
    seq = anchors[-1]["seq"] + 1 if anchors else 0
    prev_anchor_hash = anchors[-1]["anchor_hash"] if anchors else "0"*64
    core = {"seq": seq, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "row_count": n, "head_id": head_id, "head_hash": head_hash, "prev_anchor_hash": prev_anchor_hash}
    anchor_hash = hashlib.sha256(json.dumps(core, sort_keys=True).encode()).hexdigest()
    priv = load_or_create_keypair()
    sig = priv.sign(anchor_hash.encode())
    record = {**core, "anchor_hash": anchor_hash, "signature_hex": sig.hex()}
    open(ANCHOR_LOG, "a").write(json.dumps(record, sort_keys=True) + "\n")
    return True, f"anchor seq={seq} created"

def verify_anchors():
    if not os.path.exists(PUB_KEY_PATH): return True, "no anchors/keys yet"
    pub = serialization.load_pem_public_key(open(PUB_KEY_PATH, "rb").read())
    anchors = read_anchors()
    expected_prev = "0"*64
    for a in anchors:
        core = {k: a[k] for k in ("seq","ts","row_count","head_id","head_hash","prev_anchor_hash")}
        recomputed = hashlib.sha256(json.dumps(core, sort_keys=True).encode()).hexdigest()
        if recomputed != a["anchor_hash"]: return False, f"seq={a['seq']} anchor record altered"
        try:
            pub.verify(bytes.fromhex(a["signature_hex"]), recomputed.encode())
        except Exception:
            return False, f"seq={a['seq']} SIGNATURE INVALID"
        if a["prev_anchor_hash"] != expected_prev: return False, f"seq={a['seq']} anchor chain broken"
        expected_prev = recomputed
    if anchors:
        _, _, n = chain_state()
        if n < anchors[-1]["row_count"]:
            return False, f"TRUNCATION -- anchor recorded {anchors[-1]['row_count']} rows, ledger has {n}"
    return True, f"{len(anchors)} anchors valid"
