from __future__ import annotations

import json
import os
from dataclasses import dataclass

from groq import Groq

from matcha.engine import Finding, MatchaError

DEFAULT_MODEL = "llama-3.3-70b-versatile"


@dataclass(slots=True)
class LLMVerdict:
    is_vulnerability: bool
    confidence: str
    reasoning: str


class GroqFindingFilter:
    def __init__(self, model: str = DEFAULT_MODEL) -> None:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise MatchaError("GROQ_API_KEY is required when --enable-llm is set")
        self.client = Groq(api_key=api_key)
        self.model = model

    def filter_findings(self, findings: list[Finding]) -> list[Finding]:
        filtered: list[Finding] = []
        for finding in findings:
            verdict = self._classify(finding)
            if verdict.is_vulnerability:
                finding.reasoning = verdict.reasoning
                finding.confidence = verdict.confidence
                filtered.append(finding)
        return filtered

    def _classify(self, finding: Finding) -> LLMVerdict:
        prompt = (
            "You are reviewing a static analysis finding.\n"
            f"Rule description: {finding.description}\n"
            f"Severity: {finding.severity}\n"
            f"Code snippet:\n{finding.snippet}\n\n"
            'Reply only with JSON: {"is_vulnerability": bool, "confidence": "high|medium|low", "reasoning": "string"}'
        )
        completion = self.client.chat.completions.create(
            model=self.model,
            temperature=0,
            response_format={"type": "json_object"},
            messages=[
                {
                    "role": "system",
                    "content": "You are a careful application security reviewer.",
                },
                {"role": "user", "content": prompt},
            ],
        )
        content = completion.choices[0].message.content or "{}"
        payload = json.loads(content)
        return LLMVerdict(
            is_vulnerability=bool(payload.get("is_vulnerability")),
            confidence=str(payload.get("confidence", finding.confidence)).lower(),
            reasoning=str(payload.get("reasoning", "")).strip(),
        )
