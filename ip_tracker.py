import json
import os
import time

LEVELS = {
    "green": 0,
    "yellow": 20,
    "red": 50,
    "black": 100,
}

RED_BAN_DURATION = 7 * 24 * 60 * 60
RESET_WINDOW = 24 * 60 * 60
SPAM_LIMIT = 50
BOT_HIT_LIMIT = 3

BOT_KEYWORDS = (
    "bot", "crawl", "spider", "monitor",
    "python", "wget", "curl", "scanner",
    "nmap", "scrape", "fetch"
)

SUSPICIOUS_PATHS = {
    "/.env", "/.env.local", "/xmlrpc.php",
    "/wp-login.php", "/admin", "/backup",
    "/backup.zip", "/database.sql", "/openapi.json"
}


class IPTracker:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.banned_ips_file = os.path.join(data_dir, "banned_ips.json")
        self.suspicious_ips_file = os.path.join(data_dir, "suspicious_ips.json")
        self.ip_state = {}
        self.blacklist = set()
        self.load_all()

    def load_all(self):
        self.blacklist = self.load_blacklist()
        self.load_suspicious_ips()

    def load_blacklist(self):
        os.makedirs(self.data_dir, exist_ok=True)
        try:
            with open(self.banned_ips_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return set(data if isinstance(data, list) else [])
        except (FileNotFoundError, json.JSONDecodeError):
            return set()

    def save_blacklist(self):
        os.makedirs(self.data_dir, exist_ok=True)
        with open(self.banned_ips_file, "w", encoding="utf-8") as f:
            json.dump(sorted(self.blacklist), f)

    def load_suspicious_ips(self):
        os.makedirs(self.data_dir, exist_ok=True)
        try:
            with open(self.suspicious_ips_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    self.ip_state.update(data)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def save_suspicious_ips(self):
        os.makedirs(self.data_dir, exist_ok=True)
        with open(self.suspicious_ips_file, "w", encoding="utf-8") as f:
            json.dump(self.ip_state, f, indent=2)

    def get_state(self, ip):
        if ip not in self.ip_state:
            self.ip_state[ip] = {
                "score": 0,
                "hits": 0,
                "suspicious_hits": 0,
                "bot_hits": 0,
                "level": "green",
                "red_until": None,
                "blacklisted": False,
                "last_seen": None,
                "last_reset": None,
            }
        return self.ip_state[ip]

    def is_bot(self, ua_string):
        ua = (ua_string or "").lower()
        return any(keyword in ua for keyword in BOT_KEYWORDS)

    def reset_old_state(self, state, now):
        last_reset = state.get("last_reset")
        if last_reset is None or now - last_reset > RESET_WINDOW:
            if not state.get("blacklisted"):
                state["score"] = 0
                state["hits"] = 0
                state["bot_hits"] = 0
                state["suspicious_hits"] = 0
                state["level"] = "green"
            state["last_reset"] = now

    def update_level(self, state):
        if state["blacklisted"]:
            state["level"] = "black"
            return

        score = state["score"]
        if score >= LEVELS["black"]:
            state["level"] = "black"
            state["blacklisted"] = True
            return
        if score >= LEVELS["red"]:
            state["level"] = "red"
            return
        if score >= LEVELS["yellow"]:
            state["level"] = "yellow"
            return
        state["level"] = "green"

    def evaluate_ip(self, ip, path, ua_string, method=None):
        state = self.get_state(ip)
        now = time.time()
        self.reset_old_state(state, now)
        state["hits"] += 1
        state["last_seen"] = now

        is_upload_post = path == "/files" and method == "POST"

        if not is_upload_post and self.is_bot(ua_string):
            state["bot_hits"] += 1
            if state["bot_hits"] >= BOT_HIT_LIMIT:
                state["score"] += 1

        if not is_upload_post and path in SUSPICIOUS_PATHS:
            state["suspicious_hits"] += 1
            state["score"] += 6

        if state["hits"] > SPAM_LIMIT:
            state["score"] += 1

        self.update_level(state)

        if state["level"] == "red" and state["red_until"] is None:
            state["red_until"] = time.time() + RED_BAN_DURATION

        if state["level"] == "black":
            self.blacklist.add(ip)
            self.save_blacklist()
        
        self.save_suspicious_ips()

    def check_block(self, ip):
        state = self.get_state(ip)
        if ip in self.blacklist or state.get("blacklisted"):
            return "black"

        if state["level"] == "red":
            red_until = state.get("red_until")
            if red_until and time.time() < red_until:
                return "red"
            state["level"] = "yellow"
            state["score"] = LEVELS["yellow"]
        return None

    def set_ip_level(self, ip, level):
        state = self.get_state(ip)

        if level == "green":
            state["score"] = 0
            state["level"] = "green"
            state["red_until"] = None
            state["blacklisted"] = False
            if ip in self.blacklist:
                self.blacklist.discard(ip)
                self.save_blacklist()
        elif level == "yellow":
            state["level"] = "yellow"
            state["blacklisted"] = False
            state["red_until"] = None
            if ip in self.blacklist:
                self.blacklist.discard(ip)
                self.save_blacklist()
        elif level == "red":
            state["level"] = "red"
            state["blacklisted"] = False
            state["red_until"] = time.time() + RED_BAN_DURATION
            if ip in self.blacklist:
                self.blacklist.discard(ip)
                self.save_blacklist()
        elif level == "black":
            state["level"] = "black"
            state["blacklisted"] = True
            state["red_until"] = None
            self.blacklist.add(ip)
            self.save_blacklist()

        self.save_suspicious_ips()
        return state

    def get_admin_list(self):
        admin_ips = {}
        admin_ips.update(self.ip_state)
        for ip in self.blacklist:
            if ip not in admin_ips:
                admin_ips[ip] = {
                    "score": 0,
                    "hits": 0,
                    "suspicious_hits": 0,
                    "bot_hits": 0,
                    "level": "black",
                    "red_until": None,
                    "blacklisted": True,
                    "last_seen": None,
                    "last_reset": None,
                }
        return sorted(admin_ips.items(), key=lambda item: item[0])

    def clear_state(self):
        self.ip_state.clear()
        self.save_suspicious_ips()

    def clear_blacklist(self):
        self.blacklist.clear()
        self.save_blacklist()
