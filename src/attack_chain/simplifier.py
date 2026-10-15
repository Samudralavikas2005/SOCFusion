"""
SOCFusion ATT&CK Technique Chain Simplifier

Provides reusable functions to convert an event-level attack chain into a simplified
ATT&CK technique narrative by keeping only the FIRST occurrence of each technique ID
in chronological order, ignoring duplicate and missing/null values.
"""

def simplify_technique_chain(events):
    """
    Simplifies an attack technique sequence by preserving only the FIRST occurrence
    of each technique ID in chronological order.

    Args:
        events: A sequence of events, technique ID strings, or event dictionaries.

    Returns:
        List[str]: Unique technique IDs in first-seen chronological order.
    """
    if not events:
        return []

    seen = set()
    simplified = []

    for item in events:
        technique = None
        if isinstance(item, dict):
            technique = (
                item.get("technique_id")
                or item.get("technique")
                or item.get("predicted_technique")
            )
        elif isinstance(item, str):
            technique = item
        elif hasattr(item, "technique_id"):
            technique = getattr(item, "technique_id")
        elif hasattr(item, "technique"):
            technique = getattr(item, "technique")

        if not technique or not isinstance(technique, str):
            continue

        technique_clean = technique.strip()
        if not technique_clean:
            continue

        if technique_clean not in seen:
            seen.add(technique_clean)
            simplified.append(technique_clean)

    return simplified
