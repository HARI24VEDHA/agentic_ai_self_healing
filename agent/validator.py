# validator.py
from pydantic import BaseModel, Field, ValidationError, validator
from typing import List, Literal, Optional

class PlanStep(BaseModel):
    action: Literal["block_ip","throttle","add_rule","remove_rule","isolate_host"]
    ip: Optional[str] = None
    reason: Optional[str] = ""
    dry_run: bool = True

    @validator("ip", always=True)
    def ip_required_for_block(cls, v, values):
        if values.get("action") in ("block_ip","throttle","add_rule","remove_rule") and not v:
            raise ValueError("ip is required for this action")
        return v

class AgentPlan(BaseModel):
    confidence: float = Field(..., ge=0.0, le=1.0)
    severity: Literal["low","medium","high"]
    plan: List[PlanStep]
    explain: Optional[str] = ""

def validate_plan(obj):
    try:
        AgentPlan.parse_obj(obj)
        return True, None
    except ValidationError as e:
        return False, e.errors()
