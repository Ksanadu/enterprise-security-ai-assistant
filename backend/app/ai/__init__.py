"""AI pipeline components.

Each stage is a separate, independently testable component rather than one large
prompt, so behaviour can be reasoned about and verified in isolation:

* :mod:`app.ai.prompt_guard` - prompt-injection detection and neutralisation
* :mod:`app.ai.intent_classifier` - what the user is asking about
* :mod:`app.ai.risk_classifier` - how serious the situation is, and whether a
  human must be involved
* :mod:`app.ai.response_generator` - a grounded answer from authorised context
* :mod:`app.ai.llm` - the model clients behind all of the above
"""

from app.ai.intent_classifier import IntentClassifier, IntentResult
from app.ai.llm import LLMClient, get_llm_client
from app.ai.prompt_guard import GuardResult, PromptGuard
from app.ai.response_generator import GeneratedAnswer, ResponseGenerator
from app.ai.risk_classifier import RiskAssessment, RiskClassifier, highest_level

__all__ = [
    "GeneratedAnswer",
    "GuardResult",
    "IntentClassifier",
    "IntentResult",
    "LLMClient",
    "PromptGuard",
    "ResponseGenerator",
    "RiskAssessment",
    "RiskClassifier",
    "get_llm_client",
    "highest_level",
]
