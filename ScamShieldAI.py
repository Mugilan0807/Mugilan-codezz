"""
Scam Shield AI — Tkinter desktop prototype
Local-first message risk assessment. No external API calls.
Python 3.10+ recommended. Tkinter is included with most Python installations.
"""

from __future__ import annotations

import csv
import os
import re
import sqlite3
import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "scamshield_history.db"

BG = "#0B1220"
PANEL = "#111C2E"
PANEL_ALT = "#17253A"
BORDER = "#26374F"
TEXT = "#F1F5F9"
MUTED = "#9FB0C6"
TEAL = "#63E6BE"
BLUE = "#8AB4F8"
AMBER = "#F5C66A"
RED = "#FF7B85"
GREEN = "#73D99B"

SUSPICIOUS_TERMS = {
    "urgent": 2, "immediately": 2, "act now": 2, "account suspended": 3,
    "blocked": 1, "verify your account": 3, "verify account": 3,
    "otp": 2, "one time password": 3, "password": 2, "pin": 2,
    "cvv": 3, "card details": 3, "bank details": 2, "click here": 1,
    "claim now": 2, "won a prize": 3, "congratulations": 1,
    "limited time": 1, "refund": 1, "kyc": 2, "suspended": 2,
    "pay a fee": 3, "processing fee": 3, "send money": 2,
    "gift card": 3, "remote access": 3, "install this app": 2,
    "police case": 3, "arrest warrant": 3, "parcel held": 2,
    "delivery failed": 1, "unusual activity": 2, "security alert": 1,
    "bitcoin": 1, "crypto investment": 2, "guaranteed returns": 3,
    "double your money": 3, "work from home": 1, "earn daily": 1,
    "anydesk": 3, "teamviewer": 3, "screen sharing": 3, "digital arrest": 3,
    "fake payment": 3, "payment screenshot": 2, "transaction screenshot": 2,
    "release item": 2, "pending approval": 2
}
SAFE_CONTEXT_TERMS = {
    "out for delivery": -1, "tracking number": -1, "order confirmation": -1,
    "appointment reminder": -1, "thank you for your purchase": -1,
}
URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)\S+|\b[a-z0-9-]+\.(?:com|net|org|in|co|io|xyz|top|site|info|biz)(?:/\S*)?")
SHORTENER_RE = re.compile(r"(?i)\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|shorturl\.at|rb\.gy)/\S*")
AMOUNT_RE = re.compile(r"(?i)(?:₹|rs\.?|inr)\s?[\d,]+(?:\.\d{1,2})?")
CREDENTIAL_RE = re.compile(r"(?i)\b(otp|password|pin|cvv|card number|bank details|login details)\b")
THREAT_RE = re.compile(r"(?i)\b(account (?:will be|is) (?:blocked|suspended)|arrest|police|legal action|within \d+ hours|last warning|digital arrest)\b")


def rule_assess(content: str, mode: str = "Message", extra_meta: dict = None) -> dict:
    """Explainable local heuristic assessment across modes."""
    text = content.strip()
    low = text.lower()
    score, reasons, tips = 0, [], []
    
    urls = URL_RE.findall(text)
    short_link = bool(SHORTENER_RE.search(text))
    has_link = bool(urls)
    
    if mode == "Calls":
        num = extra_meta.get("number", "").strip()
        in_contacts = extra_meta.get("in_contacts", "No")
        starts_140 = extra_meta.get("starts_140", "No")
        claim = extra_meta.get("claim", "").lower()
        call_type = extra_meta.get("call_type", "Unknown")
        combined = f"{claim} {text}"
        low = combined.lower()
        
        score += 2
        reasons.append(f"Phone number evaluated: {num if num else 'Unspecified number'}.")
        reasons.append(f"Saved in contacts: {in_contacts}.")
        reasons.append(f"Starts with commercial prefix 140 (Telemarketer range): {starts_140}.")
        reasons.append(f"Reported nature of call: {call_type}.")
        reasons.append(f"Caller's claim / premise: {claim or 'Not specified'}.")
        
        if in_contacts == "No":
            score += 1
            reasons.append("The phone number is NOT saved in your contacts.")
        if starts_140 == "Yes" or "140" in num:
            score += 1
            reasons.append("The number uses or starts with a 140 commercial/telemarketing prefix, which can be easily spoofed by scam call centers.")
        
        vishing_indicator = bool(re.search(r"(?i)\b(anydesk|teamviewer|screen share|remote app|customer care call|police video|digital arrest)\b", low))
        threat = bool(THREAT_RE.search(low))
        
        if vishing_indicator or any(term in low for term in ["anydesk", "teamviewer", "screen share", "digital arrest"]):
            score += 4
            reasons.append("Call mentions high-risk vishing indicators (remote desktop software or digital arrest threats).")
            tips.append("Hang up immediately. Legitimate authorities or banks never investigate matters over video calls or remote access tools.")
        if threat:
            score += 3
            reasons.append("The caller used aggressive, high-pressure, or threatening language.")
            
    elif mode == "Payments":
        sender = extra_meta.get("sender", "").strip()
        amt = extra_meta.get("amount", "").strip()
        unknown_sender = extra_meta.get("unknown_sender", "Yes")
        urgent_release = extra_meta.get("urgent_release", "Yes")
        combined = f"sender: {sender}, amount: {amt}, details: {text}"
        low = combined.lower()
        
        score += 2
        reasons.append(f"Payment sender: {sender or 'Unknown'}, Claimed amount: {amt or 'Unspecified'}.")
        reasons.append(f"Is sender unknown/new?: {unknown_sender}.")
        reasons.append(f"Demanding immediate item release?: {urgent_release}.")
        
        if unknown_sender == "Yes":
            score += 1
            reasons.append("The payment notification or transfer proof is from an unverified or unknown sender.")
        if urgent_release == "Yes":
            score += 2
            reasons.append("The sender is rushing you to release products or funds before you can independently cross-verify bank settlement.")
            
        fake_payment_indicator = bool(re.search(r"(?i)\b(fake payment|transfer screenshot|payment screenshot|upi screenshot|sent money screenshot|fake alert|pending approval)\b", low))
        if fake_payment_indicator or "screenshot" in low:
            score += 4
            reasons.append("Contains indicators typical of edited UPI screenshots or fake payment confirmation popups.")
            tips.append("Do not release items based purely on screenshots or SMS alerts. Always confirm balance credit directly inside your bank merchant app.")
            
    else:  # Standard Message Mode
        delivery = bool(re.search(r"(?i)\b(out for delivery|delivery|parcel|shipment|tracking|order|courier)\b", text))
        company = bool(re.search(r"(?i)\b(?:pvt\.?\s*ltd|private limited|limited|ltd\.?)\b", text))
        sender_mismatch = delivery and company and bool(re.search(r"(?i)\b(securities|investments|capital markets)\b", text))
        payment_request = bool(re.search(r"(?i)\b(pay now|make payment|transfer money|payment required|pay the fee|processing fee|send payment|deposit now|pay to release)\b", text))
        credential_request = bool(re.search(r"(?i)\b(share|send|enter|reply with|provide|confirm|submit)\b.{0,40}\b(otp|one[- ]time password|password|pin|cvv|card number|bank details|login details)\b", text))
        credential_mention = bool(CREDENTIAL_RE.search(text))
        threat = bool(THREAT_RE.search(text))
        prize = bool(re.search(r"(?i)\b(won|winner|lottery|prize|claim your reward|free gift)\b", text))
        urgency = bool(re.search(r"(?i)\b(urgent|immediately|act now|last chance|within \d+ minutes)\b", text))

        if short_link:
            score += 3
            reasons.append("A shortened link hides the final destination.")
            tips.append("Open the retailer or courier's official app/site directly instead of using the shortened link.")
        elif has_link:
            score += 1
            reasons.append("The message contains a link; its destination has not been checked.")
            tips.append("Check the full domain independently before opening the link.")
        if sender_mismatch:
            score += 2
            reasons.append("The message mentions a delivery but names a company whose name suggests a different business; the relationship is unclear.")
        if payment_request:
            score += 2
            reasons.append("The message appears to request payment or a fee.")
            tips.append("Verify payment requests through the retailer or courier's official channel.")
        if credential_request:
            score += 4
            reasons.append("The wording appears to request sensitive login or banking information.")
            tips.append("Never share an OTP, password, PIN, or CVV in response to a message.")
        elif credential_mention:
            score += 1
            reasons.append("A sensitive credential is mentioned; check whether you are being asked to disclose it.")
        if threat:
            score += 3
            reasons.append("The message uses threatening or high-pressure language.")
        if prize and re.search(r"(?i)(fee|pay|claim|click|link|send)", text):
            score += 2
            reasons.append("Prize or reward wording is combined with an action request.")
        if urgency:
            score += 1
            reasons.append("The wording creates urgency that may pressure the recipient.")

        skip = {"otp", "one time password", "password", "pin", "cvv", "card details", "bank details", "pay a fee", "processing fee", "send money", "urgent", "immediately", "act now", "account suspended", "suspended", "blocked", "won a prize", "congratulations", "guaranteed returns", "double your money", "remote access", "install this app", "anydesk", "teamviewer"}
        for term in SUSPICIOUS_TERMS:
            if term in low and term not in skip:
                score += 1
                reasons.append(f"Contains a phrase worth checking: “{term}”.")
        for term in SAFE_CONTEXT_TERMS:
            if term in low:
                reasons.append(f"Contains ordinary notification wording: “{term}”.")

    if AMOUNT_RE.search(text):
        reasons.append("An amount is mentioned.")
    if not reasons:
        reasons.append("No strong warning phrase was detected by the local rule checker.")

    if score >= 7:
        verdict, risk, color = "Likely Scam", "High", RED
    elif score >= 3:
        verdict, risk, color = "Suspicious", "Medium", AMBER
    else:
        verdict, risk, color = "Likely Genuine", "Low", GREEN
        
    if not tips:
        tips.append("If requested to act, verify independently using official apps, websites, or customer service numbers.")
    tips.append("Local prototype assessment; does not guarantee absolute fraud determination.")
    
    return {"verdict": verdict, "risk": risk, "color": color, "score": score,
            "confidence": "Rule-based estimate", "reasons": reasons, "tips": tips, "urls": urls}


class ScamShieldApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Scam Shield AI | Message & Threat Protection")
        self.geometry("1120x860")
        self.minsize(900, 720)
        self.configure(bg=BG)
        self.current_mode = "Message"
        self._init_db()
        self._style()
        self._build_ui()
        self.show_page("Scan")

    def _init_db(self):
        with sqlite3.connect(DB_PATH) as con:
            con.execute("""CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL, message TEXT NOT NULL,
                verdict TEXT NOT NULL, risk TEXT NOT NULL, score INTEGER NOT NULL,
                category TEXT NOT NULL, reasons TEXT NOT NULL
            )""")

    def _style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", background=PANEL, foreground=TEXT, fieldbackground=PANEL, rowheight=32, borderwidth=0)
        style.configure("Treeview.Heading", background=PANEL_ALT, foreground=TEXT, relief="flat")
        style.map("Treeview", background=[("selected", "#244968")])

    def _build_ui(self):
        header = tk.Frame(self, bg="#102A43", padx=24, pady=18)
        header.pack(fill="x")
        logo = tk.Label(header, text="⬡", font=("Segoe UI Symbol", 30, "bold"), fg=TEAL, bg="#102A43")
        logo.pack(side="left", padx=(0, 14))
        titlebox = tk.Frame(header, bg="#102A43")
        titlebox.pack(side="left", fill="x", expand=True)
        tk.Label(titlebox, text="SCAM SHIELD AI", font=("Segoe UI", 20, "bold"), fg="#FFFFFF", bg="#102A43").pack(anchor="w")
        tk.Label(titlebox, text="Smart local threat screening • Multi-vector protection", font=("Segoe UI", 10), fg="#C5D9E8", bg="#102A43").pack(anchor="w", pady=(3, 0))
        self.status_label = tk.Label(header, text="Local Rules Engine", font=("Segoe UI", 9, "bold"), fg=TEAL, bg="#193B50", padx=12, pady=8)
        self.status_label.pack(side="right", anchor="n")

        shell = tk.Frame(self, bg=BG)
        shell.pack(fill="both", expand=True)
        nav = tk.Frame(shell, bg=PANEL, width=200, padx=14, pady=18)
        nav.pack(side="left", fill="y")
        nav.pack_propagate(False)
        tk.Label(nav, text="WORKSPACE", font=("Segoe UI", 9, "bold"), fg=MUTED, bg=PANEL).pack(anchor="w", padx=8, pady=(4, 12))
        self.nav_buttons = {}
        for name, symbol in [("Scan", "⌕"), ("Inbox", "▤"), ("Review", "◷"), ("Trash", "▧"), ("About", "ⓘ")]:
            btn = tk.Button(nav, text=f"  {symbol}   {name}", anchor="w", font=("Segoe UI", 11, "bold"),
                            fg=TEXT, bg=PANEL, activebackground=PANEL_ALT, activeforeground=TEXT,
                            relief="flat", bd=0, padx=10, pady=12, cursor="hand2",
                            command=lambda n=name: self.show_page(n))
            btn.pack(fill="x", pady=3)
            self.nav_buttons[name] = btn
        tk.Frame(nav, bg=BORDER, height=1).pack(fill="x", pady=18)
        tk.Label(nav, text="PRIVACY FIRST", font=("Segoe UI", 9, "bold"), fg=TEAL, bg=PANEL).pack(anchor="w", padx=8)
        tk.Label(nav, text="Processed locally on your device. No data sent to online APIs.", wraplength=160, justify="left",
                 font=("Segoe UI", 9), fg=MUTED, bg=PANEL).pack(anchor="w", padx=8, pady=(7, 0))
        self.content = tk.Frame(shell, bg=BG, padx=24, pady=22)
        self.content.pack(side="left", fill="both", expand=True)

    def _clear_content(self):
        for child in self.content.winfo_children():
            child.destroy()

    def _card(self, parent, **kwargs):
        return tk.Frame(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=1, padx=18, pady=16, **kwargs)

    def show_page(self, name):
        self._clear_content()
        for nav_name, btn in self.nav_buttons.items():
            btn.configure(bg="#244968" if nav_name == name else PANEL, fg=TEAL if nav_name == name else TEXT)
        if name == "Scan":
            self._show_scan()
        elif name in ("Inbox", "Review", "Trash"):
            self._show_history(name)
        else:
            self._show_about()

    def _show_scan(self):
        tk.Label(self.content, text="Threat & Scam Screening", font=("Segoe UI", 22, "bold"), fg=TEXT, bg=BG).pack(anchor="w")
        tk.Label(self.content, text="Select the threat vector tab below to screen incoming messages, phone calls, or payments.", font=("Segoe UI", 10), fg=MUTED, bg=BG).pack(anchor="w", pady=(4, 14))

        mode_bar = tk.Frame(self.content, bg=BG)
        mode_bar.pack(fill="x", pady=(0, 14))

        self.mode_buttons = {}
        for mode_name in ["Message", "Calls", "Payments"]:
            btn = tk.Button(mode_bar, text=f"  {mode_name.upper()}  ", font=("Segoe UI", 10, "bold"),
                            command=lambda m=mode_name: self._switch_mode(m), relief="flat", padx=18, pady=8, cursor="hand2")
            btn.pack(side="left", padx=(0, 8))
            self.mode_buttons[mode_name] = btn
        self._update_mode_styling()

        self.scan_card = self._card(self.content)
        self.scan_card.pack(fill="x")
        
        self._build_dynamic_inputs()

        self.result_area = tk.Frame(self.content, bg=BG)
        self.result_area.pack(fill="both", expand=True, pady=(16, 0))

    def _switch_mode(self, mode):
        self.current_mode = mode
        self._update_mode_styling()
        for widget in self.scan_card.winfo_children():
            widget.destroy()
        self._build_dynamic_inputs()

    def _update_mode_styling(self):
        for m, btn in self.mode_buttons.items():
            if m == self.current_mode:
                btn.configure(bg=TEAL, fg="#09251D")
            else:
                btn.configure(bg=PANEL_ALT, fg=TEXT)

    def _build_dynamic_inputs(self):
        if self.current_mode == "Message":
            tk.Label(self.scan_card, text="PASTE SUSPICIOUS MESSAGE / SMS", font=("Segoe UI", 9, "bold"), fg=BLUE, bg=PANEL).pack(anchor="w")
            
            text_container = tk.Frame(self.scan_card, bg=PANEL_ALT, highlightthickness=1, highlightbackground=BORDER)
            text_container.pack(fill="x", pady=(10, 10))

            self.msg_input = tk.Text(text_container, height=6, wrap="word", font=("Consolas", 11), bg=PANEL_ALT, fg=TEXT,
                                       insertbackground=TEXT, relief="flat", padx=12, pady=12, bd=0)
            self.msg_input.pack(side="left", fill="both", expand=True)

            scrollbar = ttk.Scrollbar(text_container, orient="vertical", command=self.msg_input.yview)
            self.msg_input.configure(yscrollcommand=scrollbar.set)
            scrollbar.pack(side="right", fill="y")

        elif self.current_mode == "Calls":
            tk.Label(self.scan_card, text="PHONE CALL / VISHING RISK CHECKER", font=("Segoe UI", 9, "bold"), fg=BLUE, bg=PANEL).pack(anchor="w", pady=(0, 8))
            
            # Row 1: Phone number
            r1 = tk.Frame(self.scan_card, bg=PANEL)
            r1.pack(fill="x", pady=3)
            tk.Label(r1, text="Caller Phone Number:", fg=TEXT, bg=PANEL, font=("Segoe UI", 9), width=28, anchor="w").pack(side="left")
            self.call_num_input = tk.Entry(r1, font=("Consolas", 10), bg=PANEL_ALT, fg=TEXT, insertbackground=TEXT, relief="flat", highlightthickness=1, highlightbackground=BORDER)
            self.call_num_input.pack(side="left", fill="x", expand=True, padx=4, ipady=3)

            # Row 2: In contacts?
            r2 = tk.Frame(self.scan_card, bg=PANEL)
            r2.pack(fill="x", pady=3)
            tk.Label(r2, text="Is number saved in your contacts?", fg=TEXT, bg=PANEL, font=("Segoe UI", 9), width=28, anchor="w").pack(side="left")
            self.call_contacts_var = tk.StringVar(value="No")
            ttk.Combobox(r2, textvariable=self.call_contacts_var, values=["Yes", "No"], state="readonly", width=12).pack(side="left", padx=4)

            # Row 3: Starts with 140 prefix?
            r3 = tk.Frame(self.scan_card, bg=PANEL)
            r3.pack(fill="x", pady=3)
            tk.Label(r3, text="Does number start with 140 prefix?", fg=TEXT, bg=PANEL, font=("Segoe UI", 9), width=28, anchor="w").pack(side="left")
            self.call_140_var = tk.StringVar(value="No")
            ttk.Combobox(r3, textvariable=self.call_140_var, values=["No", "Yes"], state="readonly", width=12).pack(side="left", padx=4)

            # Row 4: Call Category dropdown
            r4 = tk.Frame(self.scan_card, bg=PANEL)
            r4.pack(fill="x", pady=3)
            tk.Label(r4, text="Claimed identity / Premise:", fg=TEXT, bg=PANEL, font=("Segoe UI", 9), width=28, anchor="w").pack(side="left")
            self.call_type_var = tk.StringVar(value="Bank / Credit Card Support")
            types = ["Bank / Credit Card Support", "Police / Cyber Crime Cell", "Courier / Customs Parcel", "Telecom / SIM Block", "Utility (Electricity/Water)", "Prize / Lottery Offer", "Other"]
            ttk.Combobox(r4, textvariable=self.call_type_var, values=types, state="readonly", width=32).pack(side="left", padx=4)

            # Row 5: Call claim detail
            r5 = tk.Frame(self.scan_card, bg=PANEL)
            r5.pack(fill="x", pady=3)
            tk.Label(r5, text="Specific call instruction / threat:", fg=TEXT, bg=PANEL, font=("Segoe UI", 9), width=28, anchor="w").pack(side="left")
            self.call_claim_input = tk.Entry(r5, font=("Segoe UI", 10), bg=PANEL_ALT, fg=TEXT, insertbackground=TEXT, relief="flat", highlightthickness=1, highlightbackground=BORDER)
            self.call_claim_input.pack(side="left", fill="x", expand=True, padx=4, ipady=3)

            tk.Label(self.scan_card, text="Detailed conversation notes or transcript remarks:", font=("Segoe UI", 9), fg=MUTED, bg=PANEL).pack(anchor="w", pady=(6, 2))
            
            text_container = tk.Frame(self.scan_card, bg=PANEL_ALT, highlightthickness=1, highlightbackground=BORDER)
            text_container.pack(fill="x", pady=(2, 6))
            self.call_notes_input = tk.Text(text_container, height=3, wrap="word", font=("Consolas", 10), bg=PANEL_ALT, fg=TEXT, insertbackground=TEXT, relief="flat", padx=8, pady=8, bd=0)
            self.call_notes_input.pack(side="left", fill="both", expand=True)
            
            scrollbar = ttk.Scrollbar(text_container, orient="vertical", command=self.call_notes_input.yview)
            self.call_notes_input.configure(yscrollcommand=scrollbar.set)
            scrollbar.pack(side="right", fill="y")

        elif self.current_mode == "Payments":
            tk.Label(self.scan_card, text="FAKE PAYMENT & RECEIPT RISK CHECKER", font=("Segoe UI", 9, "bold"), fg=BLUE, bg=PANEL).pack(anchor="w", pady=(0, 8))
            
            # Row 1: Sender name
            r1 = tk.Frame(self.scan_card, bg=PANEL)
            r1.pack(fill="x", pady=3)
            tk.Label(r1, text="Customer / Payer Name:", fg=TEXT, bg=PANEL, font=("Segoe UI", 9), width=28, anchor="w").pack(side="left")
            self.pay_sender_input = tk.Entry(r1, font=("Consolas", 10), bg=PANEL_ALT, fg=TEXT, insertbackground=TEXT, relief="flat", highlightthickness=1, highlightbackground=BORDER)
            self.pay_sender_input.pack(side="left", fill="x", expand=True, padx=4, ipady=3)

            # Row 2: Amount
            r2 = tk.Frame(self.scan_card, bg=PANEL)
            r2.pack(fill="x", pady=3)
            tk.Label(r2, text="Claimed Transaction Amount (₹):", fg=TEXT, bg=PANEL, font=("Segoe UI", 9), width=28, anchor="w").pack(side="left")
            self.pay_amt_input = tk.Entry(r2, font=("Consolas", 10), bg=PANEL_ALT, fg=TEXT, insertbackground=TEXT, relief="flat", highlightthickness=1, highlightbackground=BORDER)
            self.pay_amt_input.pack(side="left", fill="x", expand=True, padx=4, ipady=3)

            # Row 3: Unknown sender?
            r3 = tk.Frame(self.scan_card, bg=PANEL)
            r3.pack(fill="x", pady=3)
            tk.Label(r3, text="Is sender/customer completely unknown?", fg=TEXT, bg=PANEL, font=("Segoe UI", 9), width=28, anchor="w").pack(side="left")
            self.pay_unknown_var = tk.StringVar(value="Yes")
            ttk.Combobox(r3, textvariable=self.pay_unknown_var, values=["Yes", "No"], state="readonly", width=12).pack(side="left", padx=4)

            # Row 4: Urging to release item immediately?
            r4 = tk.Frame(self.scan_card, bg=PANEL)
            r4.pack(fill="x", pady=3)
            tk.Label(r4, text="Pressuring to release item/funds urgently?", fg=TEXT, bg=PANEL, font=("Segoe UI", 9), width=28, anchor="w").pack(side="left")
            self.pay_urgent_var = tk.StringVar(value="Yes")
            ttk.Combobox(r4, textvariable=self.pay_urgent_var, values=["Yes", "No"], state="readonly", width=12).pack(side="left", padx=4)

            tk.Label(self.scan_card, text="Paste screenshot alert text / SMS text / transaction details:", font=("Segoe UI", 9), fg=MUTED, bg=PANEL).pack(anchor="w", pady=(6, 2))
            
            text_container = tk.Frame(self.scan_card, bg=PANEL_ALT, highlightthickness=1, highlightbackground=BORDER)
            text_container.pack(fill="x", pady=(2, 6))
            self.pay_notes_input = tk.Text(text_container, height=3, wrap="word", font=("Consolas", 10), bg=PANEL_ALT, fg=TEXT, insertbackground=TEXT, relief="flat", padx=8, pady=8, bd=0)
            self.pay_notes_input.pack(side="left", fill="both", expand=True)
            
            scrollbar = ttk.Scrollbar(text_container, orient="vertical", command=self.pay_notes_input.yview)
            self.pay_notes_input.configure(yscrollcommand=scrollbar.set)
            scrollbar.pack(side="right", fill="y")

        # Action Buttons
        actions = tk.Frame(self.scan_card, bg=PANEL)
        actions.pack(fill="x", pady=(10, 0))
        
        tk.Button(actions, text="Analyze Threat  →", command=self.analyze, bg=TEAL, fg="#09251D", activebackground="#8BF0D1",
                  relief="flat", font=("Segoe UI", 10, "bold"), padx=18, pady=10, cursor="hand2").pack(side="right")
        tk.Button(actions, text="Clear", command=self._clear_inputs, bg=PANEL_ALT, fg=TEXT,
                  activebackground=BORDER, relief="flat", padx=14, pady=10, cursor="hand2").pack(side="right", padx=8)

    def _clear_inputs(self):
        if self.current_mode == "Message":
            self.msg_input.delete("1.0", "end")
        elif self.current_mode == "Calls":
            self.call_num_input.delete(0, "end")
            self.call_claim_input.delete(0, "end")
            self.call_notes_input.delete("1.0", "end")
        elif self.current_mode == "Payments":
            self.pay_sender_input.delete(0, "end")
            self.pay_amt_input.delete(0, "end")
            self.pay_notes_input.delete("1.0", "end")

    def analyze(self):
        extra_meta = {}
        if self.current_mode == "Message":
            content = self.msg_input.get("1.0", "end").strip()
        elif self.current_mode == "Calls":
            extra_meta["number"] = self.call_num_input.get().strip()
            extra_meta["in_contacts"] = self.call_contacts_var.get()
            extra_meta["starts_140"] = self.call_140_var.get()
            extra_meta["call_type"] = self.call_type_var.get()
            extra_meta["claim"] = self.call_claim_input.get().strip()
            content = self.call_notes_input.get("1.0", "end").strip()
        else: # Payments
            extra_meta["sender"] = self.pay_sender_input.get().strip()
            extra_meta["amount"] = self.pay_amt_input.get().strip()
            extra_meta["unknown_sender"] = self.pay_unknown_var.get()
            extra_meta["urgent_release"] = self.pay_urgent_var.get()
            content = self.pay_notes_input.get("1.0", "end").strip()

        if not content and self.current_mode == "Message":
            messagebox.showinfo("Missing Content", "Please paste a message before analyzing.")
            return

        result = rule_assess(content, mode=self.current_mode, extra_meta=extra_meta)
        
        with sqlite3.connect(DB_PATH) as con:
            con.execute("INSERT INTO scans (created_at,message,verdict,risk,score,category,reasons) VALUES (?,?,?,?,?,?,?)",
                        (datetime.now().isoformat(timespec="seconds"), content or f"[{self.current_mode} assessment]", result["verdict"], result["risk"], result["score"], f"Mode: {self.current_mode}", " | ".join(result["reasons"])))

        self._render_result(result)
        self._show_result_popup(result)

    def _show_result_popup(self, result):
        popup = tk.Toplevel(self)
        popup.title("Threat Analysis Result")
        popup.geometry("540x440")
        popup.configure(bg=PANEL)
        popup.transient(self)
        popup.grab_set()

        x = self.winfo_x() + (self.winfo_width() // 2) - 270
        y = self.winfo_y() + (self.winfo_height() // 2) - 220
        popup.geometry(f"+{x}+{y}")

        header_frame = tk.Frame(popup, bg=PANEL_ALT, padx=20, pady=15)
        header_frame.pack(fill="x")

        tk.Label(header_frame, text=result["verdict"].upper(), font=("Segoe UI", 16, "bold"), fg=result["color"], bg=PANEL_ALT).pack(side="left")
        tk.Label(header_frame, text=f"{result['risk']} Risk", font=("Segoe UI", 10, "bold"), fg=BG, bg=result["color"], padx=10, pady=4).pack(side="right")

        body = tk.Frame(popup, bg=PANEL, padx=20, pady=15)
        body.pack(fill="both", expand=True)

        tk.Label(body, text="Assessment Findings:", font=("Segoe UI", 10, "bold"), fg=BLUE, bg=PANEL).pack(anchor="w", pady=(0, 6))

        for reason in result["reasons"][:4]:
            tk.Label(body, text="• " + reason, font=("Segoe UI", 9), fg=TEXT, bg=PANEL, justify="left", wraplength=480, anchor="w").pack(fill="x", pady=2)

        tk.Label(body, text="Safety Recommendations:", font=("Segoe UI", 10, "bold"), fg=BLUE, bg=PANEL).pack(anchor="w", pady=(12, 6))
        for tip in result["tips"][:2]:
            tk.Label(body, text="→ " + tip, font=("Segoe UI", 9), fg=MUTED, bg=PANEL, justify="left", wraplength=480, anchor="w").pack(fill="x", pady=2)

        tk.Button(popup, text="Acknowledge & Close", command=popup.destroy, bg=TEAL, fg="#09251D", font=("Segoe UI", 10, "bold"),
                  relief="flat", padx=16, pady=8, cursor="hand2").pack(pady=(0, 15))

    def _render_result(self, result):
        for child in self.result_area.winfo_children():
            child.destroy()
        card = self._card(self.result_area)
        card.pack(fill="both", expand=True)
        top = tk.Frame(card, bg=PANEL)
        top.pack(fill="x")
        tk.Label(top, text=result["verdict"], font=("Segoe UI", 16, "bold"), fg=result["color"], bg=PANEL).pack(side="left")
        tk.Label(top, text=f"  {result['risk'].upper()} RISK", font=("Segoe UI", 9, "bold"), fg=BG, bg=result["color"], padx=10, pady=5).pack(side="right")
        tk.Label(card, text=result["confidence"], font=("Segoe UI", 9), fg=MUTED, bg=PANEL).pack(anchor="w", pady=(4, 12))
        tk.Label(card, text="WHY THIS RESULT?", font=("Segoe UI", 9, "bold"), fg=BLUE, bg=PANEL).pack(anchor="w")
        reasons_box = tk.Frame(card, bg=PANEL)
        reasons_box.pack(fill="x", pady=(5, 10))
        for reason in result["reasons"][:8]:
            tk.Label(reasons_box, text="•  " + reason, font=("Segoe UI", 10), fg=TEXT, bg=PANEL, justify="left", wraplength=780, anchor="w").pack(fill="x", pady=2)
        tk.Label(card, text="SAFER NEXT STEPS", font=("Segoe UI", 9, "bold"), fg=BLUE, bg=PANEL).pack(anchor="w", pady=(4, 4))
        for tip in result["tips"]:
            tk.Label(card, text="→  " + tip, font=("Segoe UI", 10), fg=MUTED, bg=PANEL, justify="left", wraplength=780, anchor="w").pack(fill="x", pady=2)

    def _show_history(self, page):
        tk.Label(self.content, text=page, font=("Segoe UI", 22, "bold"), fg=TEXT, bg=BG).pack(anchor="w")
        
        sub_bar = tk.Frame(self.content, bg=BG)
        sub_bar.pack(fill="x", pady=(4, 12))
        tk.Label(sub_bar, text=f"Saved {page.lower()} scans stored on this device.", font=("Segoe UI", 10), fg=MUTED, bg=BG).pack(side="left")
        
        btn_frame = tk.Frame(sub_bar, bg=BG)
        btn_frame.pack(side="right")
        
        tk.Button(btn_frame, text="Export CSV", command=lambda: self._export_csv(page), bg=PANEL_ALT, fg=BLUE,
                  activebackground=BORDER, relief="flat", padx=10, pady=4, font=("Segoe UI", 9), cursor="hand2").pack(side="left", padx=(0, 8))
        tk.Button(btn_frame, text="Clear History", command=lambda: self._clear_history_category(page), bg=PANEL_ALT, fg=RED,
                  activebackground=BORDER, relief="flat", padx=10, pady=4, font=("Segoe UI", 9), cursor="hand2").pack(side="left")

        card = self._card(self.content)
        card.pack(fill="both", expand=True)

        tree_frame = tk.Frame(card, bg=PANEL)
        tree_frame.pack(fill="both", expand=True)

        cols = ("date", "verdict", "risk", "message")
        tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
        
        for col, label, width in [("date", "Date", 145), ("verdict", "Verdict", 125), ("risk", "Risk", 80), ("message", "Preview", 480)]:
            tree.heading(col, text=label)
            tree.column(col, width=width, anchor="w")

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)

        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        mapping = {"Inbox": ("Likely Genuine",), "Review": ("Suspicious",), "Trash": ("Likely Scam",)}
        self.history_store = {}

        with sqlite3.connect(DB_PATH) as con:
            rows = con.execute("SELECT id, created_at, verdict, risk, message FROM scans ORDER BY id DESC").fetchall()
        
        for row_id, date, verdict, risk, msg in rows:
            if verdict in mapping[page]:
                item_id = tree.insert("", "end", values=(date.replace("T", " "), verdict, risk, msg[:100].replace("\n", " ")))
                self.history_store[item_id] = {"id": row_id, "date": date, "verdict": verdict, "risk": risk, "message": msg}

        if not tree.get_children():
            tk.Label(card, text=f"No entries in {page} yet.", fg=MUTED, bg=PANEL, font=("Segoe UI", 10)).pack(pady=15)

        def open_selected(_event=None):
            selection = tree.selection()
            if not selection:
                return
            item = self.history_store.get(selection[0])
            if item:
                messagebox.showinfo(item["verdict"], f"Full Details:\n\n{item['message']}\n\nVerdict: {item['verdict']}\nRisk Level: {item['risk']}\nDate: {item['date'].replace('T', ' ')}")

        tree.bind("<Double-1>", open_selected)

    def _clear_history_category(self, page):
        mapping = {"Inbox": ("Likely Genuine",), "Review": ("Suspicious",), "Trash": ("Likely Scam",)}
        targets = mapping[page]
        if not messagebox.askyesno("Confirm", f"Are you sure you want to clear all items from {page}?"):
            return
        with sqlite3.connect(DB_PATH) as con:
            for v in targets:
                con.execute("DELETE FROM scans WHERE verdict = ?", (v,))
        self._show_history(page)

    def _export_csv(self, page):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")], title=f"Export {page} History")
        if not file_path:
            return
        mapping = {"Inbox": ("Likely Genuine",), "Review": ("Suspicious",), "Trash": ("Likely Scam",)}
        targets = mapping[page]
        with sqlite3.connect(DB_PATH) as con:
            rows = con.execute("SELECT created_at, verdict, risk, category, message, reasons FROM scans ORDER BY id DESC").fetchall()
        
        try:
            with open(file_path, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Date", "Verdict", "Risk", "Category", "Content", "Reasons"])
                for r in rows:
                    if r[1] in targets:
                        writer.writerow(r)
            messagebox.showinfo("Success", f"History exported successfully to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export CSV: {e}")

    def _show_about(self):
        tk.Label(self.content, text="About Scam Shield AI", font=("Segoe UI", 22, "bold"), fg=TEXT, bg=BG).pack(anchor="w")
        card = self._card(self.content)
        card.pack(fill="x", pady=(18, 0))
        paragraphs = [
            ("Purpose", "Screen suspicious SMS messages, inbound phone call claims/vishing (including contact status and 140 prefix checks), and fake payment receipts before taking action."),
            ("Local-First", "App runs completely offline. Scans are logged to a local SQLite database for your review history."),
        ]
        for heading, body in paragraphs:
            tk.Label(card, text=heading, font=("Segoe UI", 11, "bold"), fg=TEAL, bg=PANEL).pack(anchor="w", pady=(8, 3))
            tk.Label(card, text=body, font=("Segoe UI", 10), fg=TEXT, bg=PANEL, justify="left", wraplength=800).pack(anchor="w")

if __name__ == "__main__":
    app = ScamShieldApp()
    app.mainloop()
