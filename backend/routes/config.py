"""Config routes — whitelist management."""

import ipaddress
import json

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from models.schemas import SuccessResponse

router = APIRouter(prefix="/api/config", tags=["config"])


class WhitelistUpdate(BaseModel):
    cidrs: list[str]


@router.get("/whitelist", response_model=SuccessResponse[list[str]])
async def get_whitelist(request: Request) -> SuccessResponse[list[str]]:
    """Return the current whitelisted CIDRs."""
    return SuccessResponse(data=request.app.state.config.whitelist_cidrs)


@router.put("/whitelist", response_model=SuccessResponse[list[str]])
async def update_whitelist(body: WhitelistUpdate, request: Request) -> SuccessResponse[list[str]]:
    """Update the whitelist of allowed scan CIDRs."""
    # Validate each CIDR
    for cidr in body.cidrs:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Invalid CIDR: {cidr}")

    request.app.state.config.set("whitelist_cidrs", json.dumps(body.cidrs))
    return SuccessResponse(data=body.cidrs)
