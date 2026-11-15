# Password Strength Checker

A beginner cybersecurity project in Python. It scores a password from 0-100 using
entropy, and flags common passwords, sequences and repeated characters.

## Run
```
python checker.py
```
Run tests (optional): `pip install pytest` then `pytest`

## Features
- Entropy estimate and rough brute-force crack time
- Common-password check (including leetspeak like `p@ssw0rd`)
- Detects sequences (`abc`, `123`, `qwe`) and repeats (`aaa`)
- Hidden input (`getpass`) so passwords aren't shown on screen

## What I learned
(Write your own notes here: entropy, why length beats complexity, etc.)

## Limitations
Entropy is an estimate. Real attackers use wordlists and patterns, so a high score
does not guarantee safety. Use a password manager and unique passwords.
