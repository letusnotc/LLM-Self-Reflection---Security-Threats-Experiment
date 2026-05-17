import json
from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from app.models.schemas import AnalyzeRequest, CostBreakdown, CostSummary
from app.services.reflection import run_l0, run_l1, run_l2

router = APIRouter()


def _emit(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


async def _stream(email: str, l0_model: str, l1_model: str, l2_model: str):
    try:
        # ── L0 ──────────────────────────────────────────────
        yield _emit({"event": "l0_thinking", "message": "Running baseline classification..."})

        l0 = await run_l0(email, l0_model)

        yield _emit({
            "event": "l0_result",
            "label": l0.label,
            "confidence": l0.confidence,
            "reasoning": l0.reasoning,
            "indicators": l0.indicators,
            "model": l0.model,
            "tokens": l0.tokens.model_dump(),
        })

        # ── L1 ──────────────────────────────────────────────
        yield _emit({"event": "l1_thinking", "message": "Critiquing L0 analysis..."})

        l1 = await run_l1(email, l0, l1_model)

        yield _emit({
            "event": "l1_result",
            "label": l1.label,
            "confidence": l1.confidence,
            "changed": l1.changed,
            "critique": l1.critique,
            "revised_reasoning": l1.revised_reasoning,
            "model": l1.model,
            "tokens": l1.tokens.model_dump(),
        })

        # ── L2 ──────────────────────────────────────────────
        yield _emit({"event": "l2_thinking", "message": "Starting consensus loop (max 3 rounds)..."})

        l2 = await run_l2(email, l1, l2_model)

        for rd in l2.round_details:
            yield _emit({
                "event": "l2_round",
                "round": rd.round,
                "label": rd.label,
                "confidence": rd.confidence,
                "agreed": rd.agreed,
                "argument": rd.argument,
            })

        yield _emit({
            "event": "l2_result",
            "label": l2.label,
            "confidence": l2.confidence,
            "rounds_taken": l2.rounds_taken,
            "model": l2.model,
            "tokens": l2.tokens.model_dump(),
        })

        # ── Cost summary ────────────────────────────────────
        breakdown = [
            CostBreakdown(level="L0", model=l0.model,
                          input_tokens=l0.tokens.input_tokens,
                          output_tokens=l0.tokens.output_tokens,
                          cost_usd=l0.tokens.cost_usd),
            CostBreakdown(level="L1", model=l1.model,
                          input_tokens=l1.tokens.input_tokens,
                          output_tokens=l1.tokens.output_tokens,
                          cost_usd=l1.tokens.cost_usd),
            CostBreakdown(level="L2", model=l2.model,
                          input_tokens=l2.tokens.input_tokens,
                          output_tokens=l2.tokens.output_tokens,
                          cost_usd=l2.tokens.cost_usd),
        ]
        summary = CostSummary(
            total_cost_usd=sum(b.cost_usd for b in breakdown),
            total_input_tokens=sum(b.input_tokens for b in breakdown),
            total_output_tokens=sum(b.output_tokens for b in breakdown),
            breakdown=[b.model_dump() for b in breakdown],
        )
        yield _emit({"event": "cost_summary", **summary.model_dump()})

        yield _emit({"event": "done", "final_label": l2.label, "final_confidence": l2.confidence})

    except Exception as e:
        yield _emit({"event": "error", "message": str(e)})


@router.post("/analyze")
async def analyze(request: AnalyzeRequest):
    return StreamingResponse(
        _stream(request.input, request.l0_model, request.l1_model, request.l2_model),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
