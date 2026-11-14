"""A minimal resource server: one POST /refunds, guarded by Proof-Carrying Authority."""
import json

from fastapi import Depends, FastAPI
from pydantic import BaseModel

from atlas_pca import protect
from atlas_pca.fastapi import RequirePCA, add_pca_handler


class Refund(BaseModel):
    amount: int
    currency: str


def create_app(grant: dict, audience: str, mediators: list, now=None):
    """`grant` is the principal's grant, registered here by the server (never read from a request).
    `mediators` pins the keys of the components that record provenance (the `PCA-Provenance` header): a sensitive action
    runs only when its choice and its values derive from the principal. `now` fixes the clock (epoch ms); leave it out to
    use the wall clock."""
    p = protect(
        audience,
        [grant],
        # what this route executes, taken from the parsed body and the route, never from the proof
        operation=lambda request, body: {"verb": "payments.send", "resource": "payments/acme", "params": json.loads(body)},
        now=now,
        provenance_mediators=mediators,
    )
    app = FastAPI()
    add_pca_handler(app)  # refusals carry a sibling `doc` field next to `detail`

    @app.post("/refunds")
    async def refund(body: Refund, pca=Depends(RequirePCA(**p.options))):
        return {"refunded": body.amount, "currency": body.currency}

    app.state.protect = p  # p.revoke(grant["id"]) refuses every later action under that grant
    return app
