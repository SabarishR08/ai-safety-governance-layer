import re
from typing import List, Dict, Any

HAS_DETOXIFY = False
try:
    from detoxify import Detoxify
    toxicity_model = Detoxify('original')
    HAS_DETOXIFY = True
except Exception:
    toxicity_model = None

# Mock detector since Presidio fails on Python 3.14
class PIIDetector:
    def __init__(self):
        # Basic regex patterns for demo purposes
        self.patterns = {
            "EMAIL_ADDRESS": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "PHONE_NUMBER": r"\b(?:\+?1[-.●]?)?\(?([0-9]{3})\)?[-.●]?([0-9]{3})[-.●]?([0-9]{4})\b",
            "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
            "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
            "AADHAAR": r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
            "PAN": r"\b[A-Z]{5}\d{4}[A-Z]\b",
            "API_KEY": r"(?:sk|pk|api|key|token|secret)[_\-]?[a-zA-Z0-9]{16,}"
        }

    def detect(self, text: str) -> List[Dict[str, Any]]:
        results = []
        for entity_type, pattern in self.patterns.items():
            for match in re.finditer(pattern, text):
                results.append({
                    "entity_type": entity_type,
                    "start": match.start(),
                    "end": match.end(),
                    "text": match.group(0),
                    "score": 0.95
                })
        if HAS_DETOXIFY and toxicity_model:
            try:
                scores = toxicity_model.predict(text)
                toxicity_score = scores['toxicity']
                if toxicity_score > 0.7:
                    results.append({
                        "entity_type": "TOXICITY",
                        "start": 0,
                        "end": len(text),
                        "text": "***",
                        "score": round(float(toxicity_score), 2)
                    })
            except Exception:
                pass

        return sorted(results, key=lambda x: x["start"])

    def mask(self, text: str, detections: List[Dict[str, Any]], policies: Dict[str, str]) -> str:
        # Replaces from the end to not mess up indices
        masked_text = text
        for det in reversed(detections):
            action = policies.get(det["entity_type"], "MASK").upper()
            if action == "ALLOW":
                continue
            elif action == "BLOCK":
                # In real scenario, might throw error, here we just replace with BLOCKED
                replacement = f"[BLOCKED:{det['entity_type']}]"
                masked_text = masked_text[:det["start"]] + replacement + masked_text[det["end"]:]
            else:
                # Mask
                replacement = f"[{det['entity_type']}]"
                masked_text = masked_text[:det["start"]] + replacement + masked_text[det["end"]:]
        
        return masked_text

detector = PIIDetector()
