from typing import Any, List

try:
    from sentence_transformers import SentenceTransformer

    SENTENCE_TRANSFORMERS_AVAILABLE = True
except Exception:
    SENTENCE_TRANSFORMERS_AVAILABLE = False

_MODEL = None


def get_model():
    global _MODEL
    if not SENTENCE_TRANSFORMERS_AVAILABLE:
        return None
    if _MODEL is None:
        # Load the lightweight MiniLM model for embeddings
        _MODEL = SentenceTransformer("all-MiniLM-L6-v2")
    return _MODEL


def deduplicate(findings: List[Any], epsilon: float = 0.15) -> List[Any]:
    """
    Deduplicates a list of findings (can be Finding objects or dicts)
    using sentence embeddings cosine similarity.
    If sentence-transformers is not available, returns the original list.
    """
    if not SENTENCE_TRANSFORMERS_AVAILABLE or not findings:
        return findings

    model = get_model()
    if model is None:
        return findings

    texts = []
    for f in findings:
        if isinstance(f, dict):
            desc = f.get("description") or ""
            title = f.get("title") or ""
        else:
            desc = getattr(f, "description", "") or ""
            title = getattr(f, "title", "") or ""

        desc_str = str(desc).strip()
        title_str = str(title).strip()
        text = desc_str if desc_str else title_str
        texts.append(text)

    try:
        import numpy as np

        embeddings = model.encode(texts, convert_to_numpy=True)
    except Exception as e:
        # If encoding fails (e.g. system issues or package issues), fallback gracefully
        import logging

        logging.getLogger(__name__).warning(
            f"Embedding encoding failed for deduplication: {e}"
        )
        return findings

    # Normalize embeddings to unit vectors for easy cosine similarity computation
    norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    normalized = embeddings / norms

    keep_indices = []
    for i in range(len(findings)):
        is_dup = False
        for j in keep_indices:
            sim = float(np.dot(normalized[i], normalized[j]))
            dist = 1.0 - sim
            if dist <= epsilon:
                is_dup = True
                break
        if not is_dup:
            keep_indices.append(i)

    return [findings[idx] for idx in keep_indices]
