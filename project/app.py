import os
import json
import uuid
import shutil

from flask import Flask, request, jsonify, render_template, send_from_directory

from crypto.keygen import generate_keys, save_keys, load_private_key, load_public_key
from crypto.hasher import compute_hash
from crypto.signer import sign_document
from crypto.verifier import verify_document
from analysis.avalanche import compute_avalanche_from_bytes
from analysis.attack_sim import get_security_levels, tamper_file
from audit.logger import init_db, log_operation, get_all_logs

BASE_DIR = os.path.dirname(__file__)
KEYS_DIR = os.path.join(BASE_DIR, "keys")
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
SIGS_DIR = os.path.join(BASE_DIR, "signatures")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB


def _ensure_dirs():
    for d in [KEYS_DIR, UPLOADS_DIR, SIGS_DIR]:
        os.makedirs(d, exist_ok=True)


def _ensure_keys():
    for user, size in [("userA", 2048), ("userB", 2048)]:
        if not os.path.exists(os.path.join(KEYS_DIR, f"{user}_private.pem")):
            priv, pub = generate_keys(size)
            save_keys(priv, pub, user, KEYS_DIR)


def _save_upload(file_obj) -> str:
    filename = f"{uuid.uuid4().hex}_{file_obj.filename}"
    path = os.path.join(UPLOADS_DIR, filename)
    file_obj.save(path)
    return path


# ── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/analysis")
def analysis_page():
    return render_template("analysis.html")


@app.route("/audit")
def audit_page():
    logs = get_all_logs()
    return render_template("audit.html", logs=logs)


@app.route("/api/sign", methods=["POST"])
def api_sign():
    file = request.files.get("file")
    user = request.form.get("user", "userA")
    key_size = int(request.form.get("key_size", 2048))
    hash_algo = request.form.get("hash_algo", "SHA-256")

    if not file:
        return jsonify({"error": "No file provided"}), 400

    path = _save_upload(file)
    try:
        # If a non-default key size is requested, generate a fresh keypair
        if key_size not in (1024, 2048):
            return jsonify({"error": "Only 1024 or 2048-bit keys for signing"}), 400

        # Reload or use stored keys depending on requested size
        stored_size = _get_stored_key_size(user)
        if stored_size != key_size:
            priv, pub = generate_keys(key_size)
            save_keys(priv, pub, user, KEYS_DIR)
        else:
            priv = load_private_key(user, KEYS_DIR)

        file_hash = compute_hash(path, hash_algo.lower().replace("-", ""))
        sig_dict = sign_document(path, priv, user, hash_algo)
        sig_dict["original_filename"] = file.filename

        sig_id = uuid.uuid4().hex
        sig_path = os.path.join(SIGS_DIR, f"{sig_id}.sig")
        with open(sig_path, "w") as f:
            json.dump(sig_dict, f, indent=2)

        log_operation("SIGN", file.filename, file_hash, user, key_size, "SUCCESS")

        return jsonify({
            "status": "signed",
            "sig_id": sig_id,
            "file_hash": file_hash,
            "sig_info": sig_dict,
            "pipeline": _build_pipeline("sign", file_hash, sig_dict, None),
        })
    except Exception as e:
        log_operation("SIGN", file.filename, "", user, key_size, "ERROR", str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        if os.path.exists(path):
            os.unlink(path)


@app.route("/api/verify", methods=["POST"])
def api_verify():
    file = request.files.get("file")
    sig_file = request.files.get("sig_file")
    sig_id = request.form.get("sig_id")
    verifier_user = request.form.get("verifier_user", "userA")
    hash_algo = request.form.get("hash_algo", "SHA-256")

    if not file:
        return jsonify({"error": "No file provided"}), 400

    path = _save_upload(file)
    sig_path = None
    try:
        # Load sig dict
        if sig_file:
            sig_path = _save_upload(sig_file)
            with open(sig_path) as f:
                sig_dict = json.load(f)
        elif sig_id:
            stored = os.path.join(SIGS_DIR, f"{sig_id}.sig")
            if not os.path.exists(stored):
                return jsonify({"error": "Signature not found"}), 404
            with open(stored) as f:
                sig_dict = json.load(f)
        else:
            return jsonify({"error": "No signature provided"}), 400

        pub = load_public_key(verifier_user, KEYS_DIR)
        file_hash = compute_hash(path, hash_algo.lower().replace("-", ""))
        valid = verify_document(path, sig_dict, pub)
        result = "VALID" if valid else "INVALID"

        log_operation("VERIFY", file.filename, file_hash,
                      sig_dict.get("signer", "?"), sig_dict.get("key_size", 0),
                      result, f"verifier={verifier_user}")

        return jsonify({
            "status": result,
            "valid": valid,
            "file_hash": file_hash,
            "sig_info": sig_dict,
            "pipeline": _build_pipeline("verify", file_hash, sig_dict, valid),
        })
    except Exception as e:
        log_operation("VERIFY", file.filename, "", verifier_user, 0, "ERROR", str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        if os.path.exists(path):
            os.unlink(path)
        if sig_path and os.path.exists(sig_path):
            os.unlink(sig_path)


@app.route("/api/tamper", methods=["POST"])
def api_tamper():
    file = request.files.get("file")
    sig_id = request.form.get("sig_id")
    verifier_user = request.form.get("verifier_user", "userA")

    if not file:
        return jsonify({"error": "No file provided"}), 400

    path = _save_upload(file)
    try:
        with open(path, "rb") as f:
            orig_data = f.read()

        tamper_info = tamper_file(path)

        with open(path, "rb") as f:
            tampered_data = f.read()

        avalanche = compute_avalanche_from_bytes(orig_data, tampered_data)

        result = {"tamper_info": tamper_info, "avalanche": avalanche}

        if sig_id:
            stored = os.path.join(SIGS_DIR, f"{sig_id}.sig")
            if os.path.exists(stored):
                with open(stored) as f:
                    sig_dict = json.load(f)
                pub = load_public_key(verifier_user, KEYS_DIR)
                valid = verify_document(path, sig_dict, pub)
                file_hash = compute_hash(path, "sha256")
                result["verify_result"] = "INVALID" if not valid else "VALID"
                result["file_hash"] = file_hash
                result["pipeline"] = _build_pipeline("verify", file_hash, sig_dict, valid)

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if os.path.exists(path):
            os.unlink(path)


@app.route("/api/compare", methods=["POST"])
def api_compare():
    file1 = request.files.get("file1")
    file2 = request.files.get("file2")

    if not file1 or not file2:
        return jsonify({"error": "Two files required"}), 400

    path1 = _save_upload(file1)
    path2 = _save_upload(file2)
    try:
        with open(path1, "rb") as f:
            data1 = f.read()
        with open(path2, "rb") as f:
            data2 = f.read()

        hash1 = compute_hash(path1, "sha256")
        hash2 = compute_hash(path2, "sha256")

        # Byte-level diff
        diff_positions = [i for i in range(min(len(data1), len(data2))) if data1[i] != data2[i]]
        hamming = sum(bin(a ^ b).count("1") for a, b in zip(data1, data2))

        avalanche = compute_avalanche_from_bytes(data1, data2)

        return jsonify({
            "hash1": hash1,
            "hash2": hash2,
            "match": hash1 == hash2,
            "diff_byte_count": len(diff_positions),
            "hamming_distance": hamming,
            "first_diff_positions": diff_positions[:20],
            "avalanche": avalanche,
        })
    finally:
        for p in [path1, path2]:
            if os.path.exists(p):
                os.unlink(p)


@app.route("/api/performance", methods=["POST"])
def api_performance():
    mode = request.json.get("mode", "file_size") if request.is_json else "file_size"
    key_size = int(request.json.get("key_size", 2048)) if request.is_json else 2048
    try:
        from analysis.performance import benchmark_by_file_size, benchmark_by_key_size
        if mode == "key_size":
            data = benchmark_by_key_size()
        else:
            data = benchmark_by_file_size(key_size)
        return jsonify({"results": data})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/attack_sim")
def api_attack_sim():
    return jsonify({"levels": get_security_levels()})


@app.route("/api/audit")
def api_audit():
    return jsonify({"logs": get_all_logs()})


@app.route("/api/download_sig/<sig_id>")
def download_sig(sig_id):
    return send_from_directory(SIGS_DIR, f"{sig_id}.sig", as_attachment=True)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _get_stored_key_size(user: str) -> int:
    try:
        priv = load_private_key(user, KEYS_DIR)
        return priv.key_size
    except Exception:
        return 2048


def _build_pipeline(operation: str, file_hash: str, sig_dict: dict, valid) -> list:
    steps = [
        {"id": "upload", "label": "Document Upload", "value": sig_dict.get("original_filename", "file"), "status": "done"},
        {"id": "hash", "label": "SHA-256 Hash", "value": file_hash[:32] + "...", "status": "done"},
    ]
    if operation == "sign":
        steps += [
            {"id": "sign", "label": "RSA-PSS Sign", "value": f"{sig_dict.get('key_size', '?')}-bit key", "status": "done"},
            {"id": "output", "label": "Signature Output", "value": sig_dict.get("algorithm", "RSA-PSS-SHA256"), "status": "success"},
        ]
    else:
        status = "success" if valid else "failure"
        steps += [
            {"id": "sig_hash", "label": "Signature Hash", "value": sig_dict.get("algorithm", "?"), "status": "done"},
            {"id": "compare", "label": "Hash Comparison", "value": "Match" if valid else "MISMATCH", "status": status},
            {"id": "result", "label": "Result", "value": "✅ VALID" if valid else "❌ INVALID", "status": status},
        ]
    return steps


if __name__ == "__main__":
    _ensure_dirs()
    _ensure_keys()
    init_db()
    app.run(debug=True, port=5000)
