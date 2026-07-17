#!/usr/bin/env python3
import sys
import math
import random
import string

from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent

# -------------------------------------------------
# Load quadgrams
# -------------------------------------------------

def qload(fname):
    tbl = {}
    tot = 0
    with open(fname) as f:
        for line in f:
            p = line.split()
            if len(p) == 2:
                g, c = p
                c = int(c)
                tbl[g.lower()] = c
                tot += c

    for k in tbl:
        tbl[k] = math.log10(tbl[k] / tot)

    floor = math.log10(0.01 / tot)
    return tbl, floor


Q, FLOOR = qload(BASE_DIR / "english_quadgrams.txt")


def qscore(txt):
    s = 0.0
    t = txt.lower()
    for i in range(len(t) - 3):
        s += Q.get(t[i:i+4], FLOOR)
    return s


# -------------------------------------------------
# Cipher definitions
# -------------------------------------------------

CSET = list("1234567890@#$zyxwvutsrqpon")
ALPH = "abcdefghijklmnopqrstuvwxyz"


# -------------------------------------------------
# Core helpers
# -------------------------------------------------

def apply_key(text, k):
    mp = {CSET[i]: k[i] for i in range(26)}
    return "".join(mp.get(ch, ch) for ch in text)


def inv_key(k, used):
    out = ["x"] * 26
    for i, p in enumerate(k):
        if used[i]:
            out[ord(p) - 97] = CSET[i]
    return "".join(out)


# -------------------------------------------------
# Search routine
# -------------------------------------------------

def rand_key():
    a = list(ALPH)
    random.shuffle(a)
    return "".join(a)


def climb(txt):
    best = rand_key()
    best_pt = apply_key(txt, best)
    best_sc = qscore(best_pt)

    for _ in range(35):
        changed = False
        for _ in range(3500):
            k = list(best)
            i, j = random.sample(range(26), 2)
            k[i], k[j] = k[j], k[i]
            k = "".join(k)

            pt = apply_key(txt, k)
            sc = qscore(pt)

            if sc > best_sc:
                best = k
                best_sc = sc
                changed = True

        if not changed:
            break

    return best, best_sc


def crack(txt):
    used = [False] * 26
    for c in txt:
        if c in CSET:
            used[CSET.index(c)] = True

    top = None
    top_sc = -1e100

    for _ in range(55):
        k, s = climb(txt)
        if s > top_sc:
            top = k
            top_sc = s

    return top, used


# -------------------------------------------------
# Main
# -------------------------------------------------

def main():
    raw = sys.stdin.read().strip()

    if not raw:
        return

    k, used = crack(raw)
    plain = apply_key(raw, k)

    key_out = inv_key(k, used)

    plain = plain.translate(str.maketrans("", "", string.punctuation))
    plain = " ".join(plain.split())



    sys.stdout.write("Deciphered Plaintext: " + plain + "\n")
    sys.stdout.write("Deciphered Key: " + key_out)


if __name__ == "__main__":
    main()
