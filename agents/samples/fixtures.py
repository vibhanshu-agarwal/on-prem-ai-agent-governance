"""Synthetic data for the sample agents. Everything here is invented.

The HR records deliberately carry PII-shaped values (names, e-mail, phone, US-style SSN, salary,
home address) and the HR agent deliberately puts a whole record into its prompt: that is the
sloppy-but-realistic behaviour the guardrails (T5) exist to catch. None of it identifies a real person
(SSNs use the 9xx range, which is never issued; phone numbers use the 555-01xx fiction range).
"""
from __future__ import annotations

import random
from datetime import date, timedelta

EMPLOYEES = {
    "E1001": {"name": "Priya Raman", "email": "priya.raman@example.test", "phone": "+1 555-0101",
              "ssn": "912-45-6781", "salary_usd": 118000, "address": "14 Alder Lane, Springfield, IL 62704",
              "manager": "E1009", "vacation_days_left": 11, "start": "2021-03-01"},
    "E1002": {"name": "Marcus Oyelaran", "email": "marcus.oyelaran@example.test", "phone": "+1 555-0102",
              "ssn": "923-11-4402", "salary_usd": 96500, "address": "220 Birch Court, Madison, WI 53703",
              "manager": "E1009", "vacation_days_left": 4, "start": "2019-08-19"},
    "E1003": {"name": "Elena Vasquez", "email": "elena.vasquez@example.test", "phone": "+1 555-0103",
              "ssn": "934-78-2219", "salary_usd": 134250, "address": "9 Willow Road, Austin, TX 78701",
              "manager": "E1010", "vacation_days_left": 17, "start": "2018-01-08"},
    "E1004": {"name": "Tomasz Nowak", "email": "tomasz.nowak@example.test", "phone": "+1 555-0104",
              "ssn": "945-02-7730", "salary_usd": 88200, "address": "51 Cedar Street, Denver, CO 80202",
              "manager": "E1010", "vacation_days_left": 9, "start": "2022-06-13"},
}

POLICIES = [
    {"id": "HR-101", "title": "Paid time off", "text": "Full-time employees accrue 1.5 vacation days per month. Up to "
     "5 unused days carry over into the next calendar year; the rest expire on 31 March."},
    {"id": "HR-114", "title": "Parental leave", "text": "Primary caregivers receive 16 weeks of paid leave, secondary "
     "caregivers 8 weeks. Leave may start up to 2 weeks before the expected date."},
    {"id": "HR-207", "title": "Remote work", "text": "Employees may work remotely up to 3 days per week with manager "
     "approval. Working from another country for more than 14 days needs People Operations sign-off."},
    {"id": "HR-233", "title": "Expense reimbursement", "text": "Submit expenses within 30 days with receipts. Meals are "
     "reimbursed up to 60 USD per day while travelling."},
    {"id": "HR-310", "title": "Payroll corrections", "text": "Payroll errors reported before the 20th are corrected in the "
     "same cycle. Later reports are corrected in the following cycle with a supplemental payment."},
]

HR_QUESTIONS = [
    ("E1001", "How many vacation days can I carry over into next year?"),
    ("E1002", "Can I work from Lisbon for three weeks in June?"),
    ("E1003", "I think my last paycheck is wrong, what is the correction deadline?"),
    ("E1004", "How long is parental leave for a secondary caregiver?"),
    ("E1001", "What is the meal allowance when I travel for a conference?"),
    ("E1003", "Can you confirm my salary and start date for a mortgage application?"),
]


def tokens(text: str) -> set[str]:
    return {w.strip(".,?!;:").lower() for w in text.split() if len(w) > 3}


def search_policies(query: str, k: int = 2) -> list[dict]:
    q = tokens(query)
    scored = sorted(POLICIES, key=lambda p: -len(q & tokens(p["title"] + " " + p["text"])))
    return scored[:k]


# ---------------------------------------------------------------- finance
def ledger_and_bank(seed: int, n: int = 6) -> tuple[list[dict], list[dict]]:
    """A small ledger and a bank statement that mostly agree; a few lines differ in amount or are missing."""
    rnd = random.Random(seed)
    vendors = ["Northwind Freight", "Contoso Cloud", "Fabrikam Office", "Tailspin Travel", "Litware Legal",
               "Adventure Works Catering"]
    base = date(2026, 9, 1)
    ledger, bank = [], []
    for i in range(n):
        amount = round(rnd.uniform(40, 4200), 2)
        row = {"txn_id": f"T{seed % 10000:04d}-{i}", "vendor": rnd.choice(vendors), "amount": amount,
               "date": (base + timedelta(days=rnd.randint(0, 27))).isoformat(), "currency": "USD"}
        ledger.append(row)
        kind = rnd.random()
        if kind < 0.55:
            bank.append(dict(row))                                             # clean match
        elif kind < 0.8:
            bank.append({**row, "amount": round(amount + rnd.choice([-1, 1]) * rnd.uniform(0.5, 900), 2)})  # variance
        elif kind < 0.9:
            pass                                                               # missing at the bank
        else:
            bank.append({**row, "date": (date.fromisoformat(row["date"]) + timedelta(days=3)).isoformat()})  # timing
    return ledger, bank


# ---------------------------------------------------------------- coding
CODE_TASKS = [
    {"title": "parse ISO-8601 dates", "name": "parse_iso_date",
     "code": "from datetime import date\n\ndef parse_iso_date(s: str) -> date:\n    return date.fromisoformat(s.strip())\n"},
    {"title": "chunk a list", "name": "chunk",
     "code": "def chunk(items, size):\n    if size < 1:\n        raise ValueError('size must be >= 1')\n    return [items[i:i + size] for i in range(0, len(items), size)]\n"},
    {"title": "retry with backoff", "name": "retry",
     "code": "import time\n\ndef retry(fn, attempts=3, delay=0.1):\n    for i in range(attempts):\n        try:\n            return fn()\n        except Exception:\n            if i == attempts - 1:\n                raise\n            time.sleep(delay * 2 ** i)\n"},
    {"title": "slugify a title", "name": "slugify",
     "code": "import re\n\ndef slugify(s: str) -> str:\n    return re.sub(r'[^a-z0-9]+', '-', s.lower()).strip('-')\n"},
]
