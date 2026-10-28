# FastAPI server guarded by Proof-Carrying Authority

One route, `POST /refunds`, protected with `protect()`. The server accepts the request only when it carries a valid
proof signed for exactly this operation (verb, resource and parameters) under a grant the server itself registered.

- `app.py`: the server (`create_app(grant, audience, now=None)`).
- `vectors.json`: a grant and two pre-signed proofs (a $50 payment the grant allows, a $400 one it does not), plus the fixed clock they are valid at.
- `smoke.py`: calls the server in-process and checks an allow, a refusal that carries a `doc` link, and an unauthenticated refusal.

Run it:

```
pip install "atlas-pca[fastapi]" httpx
python smoke.py
```

To serve it for real, build the app from your own grant and audience: `uvicorn` needs an app object, so wrap
`create_app(grant, "your-audience")` in a small module. Agents mint proofs with the PCA agent facade; the vectors here
exist only so the example runs without one.
