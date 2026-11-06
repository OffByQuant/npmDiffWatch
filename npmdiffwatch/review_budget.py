"""Host-owned, cumulative model/context/tool admission for bounded reviews.

These primitives are transport independent and make no model calls. A request
must be admitted before dispatch. Failed/abandoned calls retain their reservation;
pagination, context eviction and repair cannot refresh cumulative allowances.
"""
from dataclasses import dataclass
import time


class BudgetExceeded(ValueError):
    pass


@dataclass(frozen=True)
class ReviewLimits:
    context_tokens: int
    total_input_tokens: int
    total_output_tokens: int
    output_tokens_per_call: int = 2048
    protocol_safety_tokens: int = 1024
    max_model_calls: int = 6
    max_tool_calls: int = 4
    max_tool_response_bytes: int = 4096
    total_tool_response_bytes: int = 16384
    total_scan_bytes: int = 16 * 1024 * 1024
    timeout_s: float = 120.0

    def __post_init__(self):
        for name, value in vars(self).items():
            if name == "timeout_s":
                if type(value) not in (int, float) or not 0 < value < float("inf"):
                    raise ValueError("timeout must be finite and positive")
            elif type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be an explicit positive integer")
        if self.output_tokens_per_call + self.protocol_safety_tokens >= self.context_tokens:
            raise ValueError("context does not leave space for policy and input")


@dataclass(frozen=True)
class RequestReservation:
    sequence: int
    input_tokens: int
    output_tokens: int
    timeout_s: float


def conservative_text_tokens(text: str) -> int:
    """UTF-8-byte upper estimate for supported byte-tokenizing text backends.

    Callers must serialize ALL sent instructions/schema/messages/tool envelopes,
    not just the latest source excerpt. Nontext/multimodal input is unsupported.
    Protocol and safety overhead are reserved separately. Usage is an estimate,
    not a fabricated provider billing count.
    """
    if not isinstance(text, str):
        raise ValueError("only serialized text requests are supported")
    return len(text.encode("utf-8"))


class ReviewBudget:
    def __init__(self, limits: ReviewLimits, *, clock=time.monotonic):
        self.limits, self.clock = limits, clock
        self.started = clock()
        self.model_calls = self.input_tokens = self.output_tokens = 0
        self.tool_calls = self.tool_bytes = self.scan_bytes = 0
        self._reservations: dict[int, RequestReservation] = {}
        self._completed: set[int] = set()
        self._blocked_reason = None

    def remaining_seconds(self) -> float:
        if self._blocked_reason:
            raise BudgetExceeded(self._blocked_reason)
        remaining = self.limits.timeout_s - (self.clock() - self.started)
        if remaining <= 0:
            raise BudgetExceeded("total review deadline exhausted")
        return remaining

    def reserve_request(self, input_tokens: int, output_tokens: int, *, final: bool,
                        final_input_tokens: int = 0, final_output_tokens: int = 0) -> RequestReservation:
        """Admit one turn plus explicitly sized final-answer headroom.

        The caller computes the final brief's size including policy. No growing
        transcript or tokenizer shortcut is silently granted extra capacity.
        """
        remaining = self.remaining_seconds()
        values = (input_tokens, output_tokens, final_input_tokens, final_output_tokens)
        if any(type(v) is not int or v < 0 for v in values) or type(final) is not bool or output_tokens == 0:
            raise ValueError("token reservations require nonnegative integers and positive output")
        if final and (final_input_tokens or final_output_tokens):
            raise ValueError("final turn cannot reserve an additional hidden turn")
        if not final and (final_input_tokens <= 0 or final_output_tokens <= 0):
            raise ValueError("nonfinal turn requires explicit final-answer headroom")
        overhead = self.limits.protocol_safety_tokens
        for ins, outs in ((input_tokens, output_tokens), (final_input_tokens, final_output_tokens)):
            if outs > self.limits.output_tokens_per_call or (outs and ins + outs + overhead > self.limits.context_tokens):
                raise BudgetExceeded("request would exceed effective context/output admission")
        calls = 1 if final else 2
        future_input = final_input_tokens + (overhead if not final else 0)
        if self.model_calls + calls > self.limits.max_model_calls:
            raise BudgetExceeded("model-call limit leaves no final-answer headroom")
        if self.input_tokens + input_tokens + overhead + future_input > self.limits.total_input_tokens:
            raise BudgetExceeded("cumulative input allowance exhausted")
        if self.output_tokens + output_tokens + final_output_tokens > self.limits.total_output_tokens:
            raise BudgetExceeded("cumulative output allowance exhausted")
        self.model_calls += 1
        self.input_tokens += input_tokens + overhead
        self.output_tokens += output_tokens
        reservation = RequestReservation(self.model_calls, input_tokens + overhead, output_tokens, remaining)
        self._reservations[reservation.sequence] = reservation
        return reservation

    def finish_request(self, reservation: RequestReservation, *, actual_input_tokens: int | None = None,
                       actual_output_tokens: int | None = None):
        """Record optional provider usage once; failed requests remain fully charged.

        Overruns consume budget and fail closed instead of retroactively blessing
        an under-admitted request. Unknown usage retains conservative reservations.
        """
        if (self._reservations.get(reservation.sequence) is not reservation
                or reservation.sequence in self._completed):
            raise ValueError("unknown or already completed request reservation")
        values = (actual_input_tokens, actual_output_tokens)
        if any(v is not None and (type(v) is not int or v < 0) for v in values):
            raise ValueError("invalid provider usage")
        self._completed.add(reservation.sequence)
        exceeded = False
        for attr, actual, reserved in (("input_tokens", actual_input_tokens, reservation.input_tokens),
                                       ("output_tokens", actual_output_tokens, reservation.output_tokens)):
            if actual is not None:
                # Never refund input: admission also reserves uncertain protocol overhead.
                if attr == "output_tokens":
                    setattr(self, attr, getattr(self, attr) + actual - reserved)
                elif actual > reserved:
                    self.input_tokens += actual - reserved
                exceeded |= actual > reserved
        if exceeded:
            self._blocked_reason = "provider usage exceeded admitted reservation"
            raise BudgetExceeded("provider usage exceeded admitted reservation")

    def reserve_tool(self, *, scan_bytes: int, response_bytes: int):
        """Charge upper bounds BEFORE search/read work, not after allocation.

        The tool must constrain its work and serialization to these reservations.
        No refunds on a failed call: repeated searches cannot scan without limit.
        """
        self.remaining_seconds()
        if any(type(v) is not int or v < 0 for v in (scan_bytes, response_bytes)):
            raise ValueError("tool reservations require nonnegative byte bounds")
        if self.tool_calls >= self.limits.max_tool_calls:
            raise BudgetExceeded("tool-call limit exhausted")
        if response_bytes > self.limits.max_tool_response_bytes or self.tool_bytes + response_bytes > self.limits.total_tool_response_bytes:
            raise BudgetExceeded("tool output byte allowance exhausted")
        if self.scan_bytes + scan_bytes > self.limits.total_scan_bytes:
            raise BudgetExceeded("tool scan byte allowance exhausted")
        self.tool_calls += 1
        self.scan_bytes += scan_bytes
        self.tool_bytes += response_bytes
