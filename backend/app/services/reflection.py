import json
from google import genai
from google.genai import types
from openai import AsyncOpenAI, RateLimitError

from app.core.config import GEMINI_API_KEY, OPENROUTER_API_KEY, L0_MODEL, L1_MODEL, L2_MODEL, token_cost
from app.models.schemas import (
    L0Result, L1Result, L2Result, L2Round, TokenUsage
)
from app.services.prompts import L0_PROMPT, L1_PROMPT, L2_PROMPT

_gemini = genai.Client(api_key=GEMINI_API_KEY)

_GEMINI_CONFIG = types.GenerateContentConfig(
    temperature=0.1,
    response_mime_type="application/json",
)

_openrouter: AsyncOpenAI | None = None
if OPENROUTER_API_KEY:
    _openrouter = AsyncOpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=OPENROUTER_API_KEY,
    )


def _is_gemini(model: str) -> bool:
    return model.startswith("gemini-")


def _parse(text: str) -> dict:
    text = text.strip()
    if not text:
        raise ValueError("Model returned empty response")
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    return json.loads(text.strip())


def _gemini_usage(response, model: str) -> TokenUsage:
    meta = response.usage_metadata
    inp = meta.prompt_token_count or 0
    out = meta.candidates_token_count or 0
    return TokenUsage(input_tokens=inp, output_tokens=out, cost_usd=token_cost(model, inp, out))


async def _call_gemini(model: str, prompt: str):
    return await _gemini.aio.models.generate_content(
        model=model,
        contents=prompt,
        config=_GEMINI_CONFIG,
    )


async def _call_openrouter(model: str, prompt: str) -> tuple[str, TokenUsage]:
    if not _openrouter:
        raise RuntimeError("OPENROUTER_API_KEY not set — cannot use OpenRouter models")
    try:
        response = await _openrouter.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
        )
    except RateLimitError as e:
        retry = ""
        try:
            retry = f" Retry after {e.response.json()['error']['metadata']['retry_after_seconds']}s."
        except Exception:
            pass
        raise RuntimeError(f"'{model}' is rate-limited on the free tier.{retry} Switch to a Gemini model or try again shortly.") from None
    choice = response.choices[0]
    text = (choice.message.content or "").strip()
    if not text:
        finish = choice.finish_reason or "unknown"
        raise RuntimeError(
            f"Model '{model}' returned empty content (finish_reason={finish}). "
            "It may be rate-limited or unavailable on the free tier — try again or switch models."
        )
    inp = response.usage.prompt_tokens if response.usage else 0
    out = response.usage.completion_tokens if response.usage else 0
    return text, TokenUsage(input_tokens=inp, output_tokens=out, cost_usd=token_cost(model, inp, out))


async def run_l0(email: str, model: str = L0_MODEL) -> L0Result:
    prompt = L0_PROMPT.format(input=email)
    if _is_gemini(model):
        response = await _call_gemini(model, prompt)
        data = _parse(response.text)
        usage = _gemini_usage(response, model)
    else:
        text, usage = await _call_openrouter(model, prompt)
        data = _parse(text)
    return L0Result(
        label=data["label"],
        confidence=float(data["confidence"]),
        reasoning=data["reasoning"],
        indicators=data.get("indicators", []),
        model=model,
        tokens=usage,
    )


async def run_l1(email: str, l0: L0Result, model: str = L1_MODEL) -> L1Result:
    prompt = L1_PROMPT.format(
        input=email,
        label=l0.label,
        confidence=l0.confidence,
        reasoning=l0.reasoning,
        indicators=", ".join(l0.indicators),
    )
    if _is_gemini(model):
        response = await _call_gemini(model, prompt)
        data = _parse(response.text)
        usage = _gemini_usage(response, model)
    else:
        text, usage = await _call_openrouter(model, prompt)
        data = _parse(text)
    return L1Result(
        label=data["label"],
        confidence=float(data["confidence"]),
        changed=bool(data.get("changed", False)),
        critique=data["critique"],
        revised_reasoning=data["revised_reasoning"],
        model=model,
        tokens=usage,
    )


async def run_l2(email: str, l1: L1Result, model: str = L2_MODEL, max_rounds: int = 3) -> L2Result:
    rounds: list[L2Round] = []
    total_input = 0
    total_output = 0

    current_label = l1.label
    current_confidence = l1.confidence
    current_reasoning = l1.revised_reasoning

    for round_num in range(1, max_rounds + 1):
        prompt = L2_PROMPT.format(
            input=email,
            round=round_num,
            label=current_label,
            confidence=current_confidence,
            reasoning=current_reasoning,
        )
        if _is_gemini(model):
            response = await _call_gemini(model, prompt)
            data = _parse(response.text)
            meta = response.usage_metadata
            total_input += meta.prompt_token_count or 0
            total_output += meta.candidates_token_count or 0
        else:
            text, usage = await _call_openrouter(model, prompt)
            data = _parse(text)
            total_input += usage.input_tokens
            total_output += usage.output_tokens

        round_result = L2Round(
            round=round_num,
            label=data["label"],
            confidence=float(data["confidence"]),
            agreed=bool(data.get("agreed", False)),
            argument=data["argument"],
        )
        rounds.append(round_result)
        current_label = round_result.label
        current_confidence = round_result.confidence
        current_reasoning = round_result.argument

        if round_result.agreed:
            break

    return L2Result(
        label=rounds[-1].label,
        confidence=rounds[-1].confidence,
        rounds_taken=len(rounds),
        round_details=rounds,
        model=model,
        tokens=TokenUsage(
            input_tokens=total_input,
            output_tokens=total_output,
            cost_usd=token_cost(model, total_input, total_output),
        ),
    )
