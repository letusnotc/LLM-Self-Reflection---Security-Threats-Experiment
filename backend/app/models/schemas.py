from pydantic import BaseModel


class AnalyzeRequest(BaseModel):
    input: str
    l0_model: str = "gemini-2.5-flash-lite"
    l1_model: str = "gemini-2.5-flash"
    l2_model: str = "gemini-2.5-flash"


class TokenUsage(BaseModel):
    input_tokens: int
    output_tokens: int
    cost_usd: float


class L0Result(BaseModel):
    label: str
    confidence: float
    reasoning: str
    indicators: list[str]
    model: str
    tokens: TokenUsage


class L1Result(BaseModel):
    label: str
    confidence: float
    changed: bool
    critique: str
    revised_reasoning: str
    model: str
    tokens: TokenUsage


class L2Round(BaseModel):
    round: int
    label: str
    confidence: float
    agreed: bool
    argument: str


class L2Result(BaseModel):
    label: str
    confidence: float
    rounds_taken: int
    round_details: list[L2Round]
    model: str
    tokens: TokenUsage


class CostBreakdown(BaseModel):
    level: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float


class CostSummary(BaseModel):
    total_cost_usd: float
    total_input_tokens: int
    total_output_tokens: int
    breakdown: list[CostBreakdown]
