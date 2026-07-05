"""Baseline-driven filter core engine.

Loads per-class signature JSONs and applies rule-based scoring to CSV data.
"""
from __future__ import annotations

import json
import logging
import operator
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

DEFAULT_SIGNATURES_DIR = Path(__file__).resolve().parent / "signatures"
OPS = {">=": operator.ge, "<=": operator.le, ">": operator.gt,
       "<": operator.lt, "==": operator.eq}


def load_signature(class_name: str, signatures_dir: Optional[Path] = None) -> dict:
    """Load signatures/<class_name>.json and return parsed dict.

    Args:
        class_name: Class name matching JSON filename (case-sensitive).
        signatures_dir: Override signatures directory (default: ./signatures/).

    Returns:
        Parsed signature dict with keys: class_name, display_name, description,
        keep_columns, categorical_mode, signature.decisive, signature.support, scoring.

    Raises:
        FileNotFoundError: If signatures/<class_name>.json does not exist.
        ValueError: If JSON is malformed or missing required keys.
    """
    sig_dir = Path(signatures_dir) if signatures_dir else DEFAULT_SIGNATURES_DIR

    # Case-insensitive file lookup (filesystem may be case-sensitive)
    sig_path = sig_dir / f"{class_name}.json"
    if not sig_path.is_file():
        for p in sig_dir.glob("*.json"):
            if p.stem.lower() == class_name.lower():
                sig_path = p
                break
        else:
            raise FileNotFoundError(
                f"Signature file not found: {sig_path}. "
                f"Available: {sorted(p.stem for p in sig_dir.glob('*.json'))}"
            )

    with open(sig_path, "r", encoding="utf-8") as f:
        sig = json.load(f)

    required = ["class_name", "keep_columns", "signature", "scoring"]
    for key in required:
        if key not in sig:
            raise ValueError(f"Signature {sig_path} missing required key: {key}")

    if sig["class_name"] != class_name:
        raise ValueError(
            f"Signature {sig_path} class_name='{sig['class_name']}' "
            f"does not match requested '{class_name}'"
        )

    return sig


def evaluate_rule(rule: dict, value) -> bool:
    """Evaluate a single signature rule against a value.

    Args:
        rule: Dict with keys 'op' (one of >=, <=, >, <, ==) and 'threshold'.
        value: Value to compare (typically from a DataFrame row).

    Returns:
        True if rule passes, False otherwise.

    Raises:
        ValueError: If rule['op'] is not a recognized operator.
    """
    try:
        return OPS[rule["op"]](value, rule["threshold"])
    except KeyError:
        raise ValueError(f"Unknown op: {rule['op']!r}. Expected one of: >=, <=, >, <, ==")


def _evaluate_rule_vectorized(rule: dict, df: pd.DataFrame, missing_logged: set) -> np.ndarray:
    """Evaluate a rule against all rows of df. Return boolean numpy array.

    Skips rule (returns all-False) if feature is missing from df.
    """
    feature = rule["feature"]
    if feature not in df.columns:
        if feature not in missing_logged:
            logger.warning(f"Feature '{feature}' missing from DataFrame; skipping rule")
            missing_logged.add(feature)
        return np.zeros(len(df), dtype=bool)

    try:
        op_fn = OPS[rule["op"]]
    except KeyError:
        raise ValueError(f"Unknown op in rule: {rule['op']!r}")

    col = pd.to_numeric(df[feature], errors="coerce").fillna(0).values
    return op_fn(col, rule["threshold"])


def score(df: pd.DataFrame, signature: dict) -> pd.DataFrame:
    """Apply rule-based scoring to DataFrame.

    Args:
        df: Input DataFrame with NB15 features.
        signature: Parsed signature dict from load_signature().

    Returns:
        Copy of df with 2 new columns:
            - <class_name>_score (int): weighted score
            - predicted_class (str): class_name if score >= threshold else "Normal"
    """
    df = df.copy()
    class_name = signature["class_name"]
    scoring = signature["scoring"]
    w_dec = scoring["weight_decisive"]
    w_sup = scoring["weight_support"]
    min_dec = scoring["min_decisive_required"]
    threshold = scoring["threshold"]

    n = len(df)
    decisive_score = np.zeros(n, dtype=np.int64)
    support_score = np.zeros(n, dtype=np.int64)
    decisive_hits = np.zeros(n, dtype=np.int64)

    missing_logged: set = set()

    for rule in signature["signature"]["decisive"]:
        hits = _evaluate_rule_vectorized(rule, df, missing_logged)
        decisive_hits += hits.astype(np.int64)
        decisive_score += hits.astype(np.int64) * w_dec

    for rule in signature["signature"]["support"]:
        hits = _evaluate_rule_vectorized(rule, df, missing_logged)
        support_score += hits.astype(np.int64) * w_sup

    total_score = decisive_score + support_score
    # Apply min_decisive_required gate
    total_score = np.where(decisive_hits >= min_dec, total_score, 0)

    score_col = f"{class_name.lower()}_score"
    df[score_col] = total_score.astype(int)
    df["predicted_class"] = np.where(total_score >= threshold, class_name, "Normal")

    return df


def filter_columns(df: pd.DataFrame, keep_columns: list) -> pd.DataFrame:
    """Keep only columns in keep_columns. Case-insensitive match.

    Args:
        df: Input DataFrame.
        keep_columns: List of column names to keep (case-insensitive).
                       Order in result follows keep_columns order.

    Returns:
        DataFrame with only the requested columns (in original case from df).
        Missing columns are skipped silently (logged once).
    """
    # Build lowercase → original-name mapping
    df_cols_lower = {c.lower(): c for c in df.columns}

    selected = []
    missing = []
    for kc in keep_columns:
        col_orig = df_cols_lower.get(kc.lower())
        if col_orig is not None and col_orig not in selected:
            selected.append(col_orig)
        elif col_orig is None:
            missing.append(kc)

    if missing:
        logger.debug(f"Columns not found in DataFrame (skipped): {missing}")

    return df[selected].copy()


def normalize_categoricals(df: pd.DataFrame, columns: list) -> pd.DataFrame:
    """Strip whitespace + lowercase for each categorical column.

    Args:
        df: Input DataFrame.
        columns: List of categorical column names (case-insensitive).

    Returns:
        Copy of df with categorical columns normalized.
    """
    df = df.copy()
    df_cols_lower = {c.lower(): c for c in df.columns}

    for col in columns:
        col_orig = df_cols_lower.get(col.lower())
        if col_orig is None:
            continue
        # Convert to str, strip, lowercase; preserve NaN as empty string
        df[col_orig] = df[col_orig].astype(str).str.strip().str.lower()
        df[col_orig] = df[col_orig].replace({"nan": "", "none": ""}, regex=False)

    return df


def downcast_integers(df: pd.DataFrame, int_columns: list) -> pd.DataFrame:
    """Downcast integer columns via pandas built-in (Int64 → Int8/16/32/64)."""
    df = df.copy()
    df_cols_lower = {c.lower(): c for c in df.columns}

    for col in int_columns:
        col_orig = df_cols_lower.get(col.lower())
        if col_orig is None or df[col_orig].isna().any():
            continue
        try:
            df[col_orig] = pd.to_numeric(df[col_orig], downcast="integer")
        except (ValueError, TypeError) as e:
            logger.warning(f"Cannot downcast column '{col_orig}': {e}")

    return df


def copy_http_log(input_dir, output_dir, base_name: str) -> None:
    """Copy <base_name>_http.log from input_dir to output_dir if exists.

    Used to preserve Zeek HTTP log alongside filtered features CSV.
    """
    import shutil
    src = Path(input_dir) / f"{base_name}_http.log"
    if not src.is_file():
        return
    dest = Path(output_dir) / f"{base_name}_http.log"
    try:
        shutil.copy2(src, dest)
        logger.info(f"Copied http log: {src.name} → {dest}")
    except OSError as e:
        logger.warning(f"Failed to copy http log: {e}")


def run(class_name: str, input_path: str, output_path: Optional[str] = None) -> pd.DataFrame:
    """Main pipeline: load signature → filter → score → write CSV.

    Args:
        class_name: Attack class to filter for (e.g., "DoS").
        input_path: Path to input CSV (must contain NB15 features).
        output_path: Path to output CSV. If None, derived from input_path
                     by inserting <class>_features before .csv extension.

    Returns:
        Filtered + scored DataFrame.
    """
    in_path = Path(input_path)
    if not in_path.is_file():
        raise FileNotFoundError(f"Input CSV not found: {in_path}")

    # Load signature
    signature = load_signature(class_name)

    # Auto-derive output path if not provided
    if output_path is None:
        out_path = in_path.parent / f"{in_path.stem}_{class_name.lower()}_features.csv"
    else:
        out_path = Path(output_path)

    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Read CSV
    logger.info(f"Loading CSV: {in_path}")
    df = pd.read_csv(in_path)
    logger.info(f"  → {len(df)} rows, {len(df.columns)} columns")

    # Pipeline: filter → normalize → downcast → score
    df = filter_columns(df, signature["keep_columns"])
    logger.info(f"After filter_columns: {len(df.columns)} columns kept")

    df = normalize_categoricals(df, ["proto", "state", "service"])

    # Get integer columns from keep_columns (heuristic: exclude obvious floats)
    FLOAT_NAMES = {
        "rate", "dur", "sload", "dload", "smean", "dmean",
        "sjit", "djit", "sinpkt", "dinpkt",
        "tcprtt", "synack", "ackdat", "response_body_len",
    }
    int_columns = [c for c in signature["keep_columns"] if c.lower() not in FLOAT_NAMES]
    df = downcast_integers(df, int_columns)

    df = score(df, signature)

    # Write output
    df.to_csv(out_path, index=False)
    logger.info(f"Wrote output: {out_path} ({len(df)} rows)")

    # Copy http log if exists
    base_name = in_path.stem
    if base_name.endswith("_raw"):
        base_name = base_name[:-4]
    copy_http_log(in_path.parent, out_path.parent, base_name)

    return df
