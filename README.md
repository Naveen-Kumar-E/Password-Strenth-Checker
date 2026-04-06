# 🔐 Password Strength Analyzer & Cracker Simulator

Analyzes password strength using entropy, hashing, and crack-time simulation.

## Features
- Shannon entropy calculation
- MD5, SHA-1, SHA-256, SHA-512 hashing
- Brute-force, dictionary, and rainbow table attack simulation
- Pattern detection (common passwords, keyboard walks, dates, repeated chars)
- Web UI + REST API + CLI mode

## Setup

### 1. Open in VS Code
```
File → Open Folder → select password-analyzer/
```

### 2. Create a virtual environment (recommended)
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run

**Web app** (recommended):
```bash
python app.py
```
Then open → http://localhost:5000

**Or press F5 in VS Code** (uses .vscode/launch.json)

**CLI mode:**
```bash
python analyzer.py "MyPassword123!" "correct-horse-battery-staple"
```

## Project Structure

```
password-analyzer/
├── analyzer.py          # Core engine — entropy, hashing, crack simulation
├── app.py               # Flask web server
├── requirements.txt     # pip dependencies (just Flask)
├── templates/
│   └── index.html       # Web UI
└── .vscode/
    └── launch.json      # VS Code run configs (F5 to launch)
```

## API

```bash
# Analyze one password
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"password": "MyP@ssword!"}'

# Analyze multiple passwords
curl -X POST http://localhost:5000/batch \
  -H "Content-Type: application/json" \
  -d '{"passwords": ["password", "Tr0ub4dor&3", "X9#mK2$pL7"]}'
```

## Concepts Covered

| Concept | Where |
|---|---|
| Shannon entropy | `analyzer.py → calculate_entropy()` |
| MD5 hashing | `analyzer.py → compute_hashes()` |
| SHA-1/256/512 | `analyzer.py → compute_hashes()` |
| Brute-force math | `analyzer.py → simulate_brute_force()` |
| Dictionary attacks | `analyzer.py → simulate_dictionary_attack()` |
| Rainbow tables | `analyzer.py → simulate_rainbow_table()` |
| Pattern detection | `analyzer.py → detect_patterns()` |
