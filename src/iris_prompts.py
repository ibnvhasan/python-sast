"""
IRIS-style prompts for API labelling (source, sink, taint-propagator).

This module builds the exact system and user prompts used to label API candidates
into one of three classes: source, sink, taint-propagator. It enforces a strict
JSON-only output contract and includes CWE-specific examples.
"""
from typing import Dict, Any, List, Tuple


def build_api_labeling_prompts(cwe_config: Dict[str, Any], batch: List[Dict[str, Any]]) -> Tuple[str, str]:
    """Create IRIS-style system and user prompts for a batch.

    Args:
        cwe_config: Dict with keys: cwe_id, desc, long_desc, examples (list of example dicts)
        batch: List of API candidates with keys: package, clazz, func, full_signature

    Returns:
        (system_prompt, user_prompt)
    """
    system_prompt = (
        "You are a security expert specializing in static analysis and taint analysis. "
        "Your job is to classify each API into exactly one of the following types: "
        "'source', 'sink', or 'taint-propagator'.\n\n"
        "Definitions:\n"
        "- source: returns or introduces attacker/external-controlled data (e.g., HTTP input, file, env)\n"
        "- sink: performs a dangerous operation if fed untrusted data (e.g., command exec, file write)\n"
        "- taint-propagator: passes tainted data from input to output without sanitization\n\n"
        "Rules:\n"
        "1) Analyze ALL listed APIs.\n"
        "2) Output MUST be a JSON array only, with same length and order as input.\n"
        "3) Each element must include keys: 'package','class','method','signature','sink_args','type'.\n"
        "4) 'type' must be one of: 'source' | 'sink' | 'taint-propagator'.\n"
        "5) If not a sink, set sink_args to [].\n"
        "6) NO explanations, NO markdown, NO code fences—JSON array only."
    )

    # Examples
    examples_text = ""
    for ex in cwe_config.get("examples", [])[:3]:
        examples_text += f"{ex.get('package','')},{ex.get('class','')},{ex.get('method','')},{ex.get('signature','')}\n"

    # Input methods
    methods_text = ""
    for cand in batch:
        package = cand.get("package", "")
        clazz = cand.get("clazz", "")
        method = cand.get("func", "")
        signature = cand.get("full_signature", method)
        methods_text += f"{package},{clazz},{method},{signature}\n"

    user_prompt = (
        f"VULNERABILITY CONTEXT: {cwe_config.get('desc','')} (CWE-{cwe_config.get('cwe_id','')})\n\n"
        f"{cwe_config.get('long_desc','')}\n\n"
        "EXAMPLE SOURCE/SINK/TAINT-PROPAGATOR METHODS:\n"
        f"{examples_text}\n"
        "APIS TO ANALYZE (keep order):\n"
        "Package,Class,Method,Signature\n"
        f"{methods_text}\n"
        f"Return ONLY a JSON array with exactly {len(batch)} objects, one per input line, same order."
    )

    return system_prompt, user_prompt
