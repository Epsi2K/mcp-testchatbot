"""
db.py — Read-only SQLite database access.
- URI mode with ?mode=ro — any write attempt raises OperationalError
- Parameterized queries ONLY — no string formatting or f-strings in SQL
- Column allowlist enforced at function level
- No credentials or secrets stored in the database
"""

import sqlite3
import os
from pathlib import Path

DB_PATH = os.environ.get("DB_PATH", "./data/company.db")

# Column allowlist — the ONLY columns the chatbot tool may return
EMPLOYEE_SAFE_COLUMNS = {"name", "department", "role"}
DOCUMENT_SAFE_COLUMNS = {"title", "content"}


def get_readonly_connection() -> sqlite3.Connection:
    """Returns a strictly read-only SQLite connection."""
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


# ─────────────────────────────────────────────────────────────
# Schema initialization (run once at startup with a writeable connection)
# ─────────────────────────────────────────────────────────────

def initialize_database() -> None:
    """
    Creates the database schema and seeds data.
    Uses a regular (writeable) connection — called once at startup.
    The DB_PATH must point to a writable location.
    """
    db_path = Path(DB_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Create employees table — intentionally NO salary, NO notes, NO credentials
    cur.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL,
            department TEXT NOT NULL,
            role       TEXT NOT NULL
        )
    """)

    # Create internal_docs table — classification column enforces PUBLIC-only rule
    cur.execute("""
        CREATE TABLE IF NOT EXISTS internal_docs (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            title          TEXT NOT NULL,
            content        TEXT NOT NULL,
            classification TEXT NOT NULL DEFAULT 'PUBLIC'
        )
    """)

    # Seed employees only if table is empty
    if cur.execute("SELECT COUNT(*) FROM employees").fetchone()[0] == 0:
        employees = [
            # Engineering (25)
            ("Alice Nguyen",        "Engineering", "Senior Software Engineer"),
            ("Bob Okafor",          "Engineering", "DevOps Engineer"),
            ("Eve Johansson",       "Engineering", "QA Lead"),
            ("Marcus Tran",         "Engineering", "Software Engineer"),
            ("Priya Sharma",        "Engineering", "Software Engineer"),
            ("Liam O'Brien",        "Engineering", "Senior DevOps Engineer"),
            ("Yuki Tanaka",         "Engineering", "Frontend Engineer"),
            ("Carlos Mendez",       "Engineering", "Backend Engineer"),
            ("Amara Diallo",        "Engineering", "Machine Learning Engineer"),
            ("Noah Fischer",        "Engineering", "Site Reliability Engineer"),
            ("Sofia Rossi",         "Engineering", "Full Stack Engineer"),
            ("James Osei",          "Engineering", "Software Engineer"),
            ("Elena Volkova",       "Engineering", "QA Engineer"),
            ("Daniel Park",         "Engineering", "Senior Backend Engineer"),
            ("Fatima Al-Rashid",    "Engineering", "Security Engineer"),
            ("Ethan Brooks",        "Engineering", "Data Engineer"),
            ("Mei Lin",             "Engineering", "Frontend Engineer"),
            ("Kwame Asante",        "Engineering", "Platform Engineer"),
            ("Isla MacLeod",        "Engineering", "Software Engineer"),
            ("Ravi Patel",          "Engineering", "Senior Machine Learning Engineer"),
            ("Hana Kobayashi",      "Engineering", "QA Automation Engineer"),
            ("Omar Hassan",         "Engineering", "Backend Engineer"),
            ("Zara Ahmed",          "Engineering", "Cloud Engineer"),
            ("Tomás García",        "Engineering", "Software Engineer"),
            ("Nina Petrov",         "Engineering", "Engineering Manager"),
            # HR (10)
            ("Carol Martínez",      "HR", "HR Manager"),
            ("Grace Adeyemi",       "HR", "HR Business Partner"),
            ("Samuel Levy",         "HR", "Recruiter"),
            ("Ingrid Holm",         "HR", "Senior Recruiter"),
            ("Patrick Okonkwo",     "HR", "People Operations Specialist"),
            ("Lily Chen",           "HR", "HR Coordinator"),
            ("Marcus Webb",         "HR", "Talent Acquisition Lead"),
            ("Anika Müller",        "HR", "Learning & Development Manager"),
            ("Tobias Renz",         "HR", "Compensation Analyst"),
            ("Nia Johnson",         "HR", "HR Generalist"),
            # Finance (12)
            ("David Kim",           "Finance", "Financial Analyst"),
            ("Rachel Goldstein",    "Finance", "Senior Financial Analyst"),
            ("Ahmed Farouq",        "Finance", "Finance Manager"),
            ("Camille Dubois",      "Finance", "Accountant"),
            ("Jason Whitfield",     "Finance", "Senior Accountant"),
            ("Leila Nazari",        "Finance", "FP&A Analyst"),
            ("Victor Santos",       "Finance", "Controller"),
            ("Hannah Schmidt",      "Finance", "Accounts Payable Specialist"),
            ("Chris Adeyemi",       "Finance", "Accounts Receivable Specialist"),
            ("Mia Andersson",       "Finance", "Payroll Specialist"),
            ("Derek Fung",          "Finance", "Financial Reporting Analyst"),
            ("Stella Nakamura",     "Finance", "Internal Auditor"),
            # Operations (10)
            ("Frank Patel",         "Operations", "Operations Manager"),
            ("Sandra Obi",          "Operations", "Operations Analyst"),
            ("Luke Harrison",       "Operations", "Supply Chain Coordinator"),
            ("Amelia Torres",       "Operations", "Process Improvement Specialist"),
            ("Ben Okafor",          "Operations", "Logistics Coordinator"),
            ("Chloe Martin",        "Operations", "Office Manager"),
            ("Diego Reyes",         "Operations", "Facilities Manager"),
            ("Emma Sullivan",       "Operations", "Business Analyst"),
            ("Finn Larsson",        "Operations", "Operations Coordinator"),
            ("Gina Romano",         "Operations", "Administrative Assistant"),
            # Product (10)
            ("Henry Blake",         "Product", "Product Manager"),
            ("Iris Yamamoto",       "Product", "Senior Product Manager"),
            ("Jack Nwosu",          "Product", "Product Analyst"),
            ("Karen Johansson",     "Product", "UX Designer"),
            ("Leo Bernstein",       "Product", "Senior UX Designer"),
            ("Maya Singh",          "Product", "Product Designer"),
            ("Nathan Cruz",         "Product", "UX Researcher"),
            ("Olivia Bennett",      "Product", "Product Manager"),
            ("Paul Eze",            "Product", "Technical Product Manager"),
            ("Quinn Zhao",          "Product", "Product Operations Manager"),
            # Sales (12)
            ("Rosa Ferreira",       "Sales", "Account Executive"),
            ("Steve Kimani",        "Sales", "Senior Account Executive"),
            ("Tina Holst",          "Sales", "Sales Development Representative"),
            ("Uma Krishnan",        "Sales", "Regional Sales Manager"),
            ("Vince Marchetti",     "Sales", "Enterprise Account Executive"),
            ("Wendy Otieno",        "Sales", "Account Executive"),
            ("Xavier Blanc",        "Sales", "Sales Operations Analyst"),
            ("Yara Hussain",        "Sales", "Sales Engineer"),
            ("Zack Morgan",         "Sales", "Business Development Manager"),
            ("Abby Liu",            "Sales", "Account Executive"),
            ("Bruno Alves",         "Sales", "Sales Development Representative"),
            ("Clara Schmidt",       "Sales", "Customer Success Manager"),
            # Marketing (10)
            ("Dan O'Sullivan",      "Marketing", "Marketing Manager"),
            ("Ella Bergström",      "Marketing", "Content Strategist"),
            ("Felix Oduya",         "Marketing", "Growth Marketing Manager"),
            ("Gabi Sousa",          "Marketing", "Brand Designer"),
            ("Hugo Petit",          "Marketing", "SEO Specialist"),
            ("Irene Castillo",      "Marketing", "Social Media Manager"),
            ("Joel Andersen",       "Marketing", "Performance Marketing Analyst"),
            ("Kira Nair",           "Marketing", "Email Marketing Specialist"),
            ("Lars Eriksson",       "Marketing", "Product Marketing Manager"),
            ("Mona El-Amin",        "Marketing", "Marketing Coordinator"),
            # Legal & Compliance (6)
            ("Nadia Popov",         "Legal", "General Counsel"),
            ("Oscar Thornton",      "Legal", "Legal Counsel"),
            ("Paula Ferreira",      "Legal", "Compliance Manager"),
            ("Quincy Adams",        "Legal", "Privacy Officer"),
            ("Rita Chukwu",         "Legal", "Contract Specialist"),
            ("Simon Lau",           "Legal", "Compliance Analyst"),
            # Customer Support (8)
            ("Tara Okonjo",         "Customer Support", "Support Manager"),
            ("Ulrich Bauer",        "Customer Support", "Senior Support Specialist"),
            ("Vera Molina",         "Customer Support", "Support Specialist"),
            ("Will Nakamura",       "Customer Support", "Support Specialist"),
            ("Xena Papadopoulos",   "Customer Support", "Technical Support Engineer"),
            ("Yvonne Tremblay",     "Customer Support", "Support Specialist"),
            ("Zachary Osei",        "Customer Support", "Customer Success Specialist"),
            ("Amy Brandt",          "Customer Support", "Support Specialist"),
        ]
        cur.executemany(
            "INSERT INTO employees (name, department, role) VALUES (?, ?, ?)",
            employees
        )

    # Seed internal docs only if table is empty
    if cur.execute("SELECT COUNT(*) FROM internal_docs").fetchone()[0] == 0:
        docs = [
            (
                "Remote Work Policy",
                "Employees may work remotely up to 3 days per week with manager approval. "
                "All remote work must be conducted over the company VPN.",
                "PUBLIC",
            ),
            (
                "Engineering Onboarding Guide",
                "Welcome to the Engineering team! Your first week includes: "
                "1) IT setup on Day 1, 2) codebase walkthrough with your buddy on Day 2, "
                "3) first PR by Day 5. Reach out to your manager for any questions.",
                "PUBLIC",
            ),
            (
                "Office Hours & Locations",
                "Main office: 123 Tech Ave, Suite 400. "
                "Hours: Monday–Friday, 8 AM – 6 PM. "
                "Visitor parking is available in Lot B.",
                "PUBLIC",
            ),
            (
                "Benefits Overview",
                "Full-time employees receive: health, dental, and vision insurance; "
                "15 days PTO per year (accrued monthly); 401(k) with 4% company match; "
                "annual learning stipend of $1,500.",
                "PUBLIC",
            ),
        ]
        cur.executemany(
            "INSERT INTO internal_docs (title, content, classification) VALUES (?, ?, ?)",
            docs
        )

    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────
# Read-only query functions — parameterized queries only
# ─────────────────────────────────────────────────────────────

def get_employees_by_department(department: str) -> list[dict]:
    """Parameterized. Returns only safe columns."""
    conn = get_readonly_connection()
    try:
        rows = conn.execute(
            "SELECT name, department, role FROM employees WHERE department = ?",
            (department,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_all_employees() -> list[dict]:
    """Returns all employees with only safe columns."""
    conn = get_readonly_connection()
    try:
        rows = conn.execute(
            "SELECT name, department, role FROM employees"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def search_employees(name_fragment: str) -> list[dict]:
    """Parameterized LIKE search. Returns only safe columns."""
    conn = get_readonly_connection()
    try:
        rows = conn.execute(
            "SELECT name, department, role FROM employees WHERE name LIKE ?",
            (f"%{name_fragment}%",)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_public_documents() -> list[dict]:
    """Returns all PUBLIC-classified documents."""
    conn = get_readonly_connection()
    try:
        rows = conn.execute(
            "SELECT title, content FROM internal_docs WHERE classification = 'PUBLIC'"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_document_by_title(title: str) -> dict | None:
    """Returns a single PUBLIC document by exact title match."""
    conn = get_readonly_connection()
    try:
        row = conn.execute(
            "SELECT title, content FROM internal_docs "
            "WHERE classification = 'PUBLIC' AND title = ?",
            (title,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()
