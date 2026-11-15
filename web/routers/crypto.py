from __future__ import annotations

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from mcp_server.crypto_ops import (
    analyze_ciphertext,
    crypto_aes,
    crypto_hash,
    encode_convert,
)

router = APIRouter(tags=["crypto"])


class AnalyzeBody(BaseModel):
    text: str = ""


class AesBody(BaseModel):
    op: Literal["encrypt", "decrypt"] = "decrypt"
    data: str = ""
    key: str = ""
    mode: str = "ECB"
    padding: str = "PKCS7"
    iv: str = ""
    fmt: str = Field(default="base64", description="base64 | hex")


class HashBody(BaseModel):
    algo: str = "md5"
    data: str = ""
    key: str = ""


class EncodeBody(BaseModel):
    op: str = "b64_encode"
    data: str = ""


@router.post("/api/crypto/analyze")
def api_analyze(body: AnalyzeBody):
    return {"ok": True, **analyze_ciphertext(body.text)}


@router.post("/api/crypto/aes")
def api_aes(body: AesBody):
    return crypto_aes(
        op=body.op,
        data=body.data,
        key=body.key,
        mode=body.mode,
        padding=body.padding,
        iv=body.iv,
        fmt=body.fmt,
    )


@router.post("/api/crypto/hash")
def api_hash(body: HashBody):
    return crypto_hash(body.algo, body.data, body.key)


@router.post("/api/crypto/encode")
def api_encode(body: EncodeBody):
    return encode_convert(op=body.op, data=body.data)
