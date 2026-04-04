"""
Aegis RAG Pipeline — Known Threat Signatures Database

Loads Vinod's threat signature library into ChromaDB.
The OpenClaw agent queries this to match incoming wireless logs
against known attack families and retrieve past mitigation approaches.
"""

import json
import os
from pathlib import Path

from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import FakeEmbeddings
from langchain_core.documents import Document

# ── Try to use real embeddings, fall back to fake for offline dev ──
def _get_embeddings():
    try:
        from langchain_openai import OpenAIEmbeddings
        from config import OPENAI_API_KEY
        if OPENAI_API_KEY and not OPENAI_API_KEY.startswith("sk-..."):
            return OpenAIEmbeddings(api_key=OPENAI_API_KEY)
    except Exception:
        pass
    # Fallback: FakeEmbeddings for local dev without API key
    return FakeEmbeddings(size=1536)


RAG_DATA_PATH = Path(__file__).parent.parent / "rag_data" / "threat_signatures.json"
CHROMA_PERSIST_DIR = Path(__file__).parent.parent / "rag_data" / "chroma_db"


def _load_threat_signatures() -> list[Document]:
    """Load threat signatures JSON into LangChain Documents."""
    with open(RAG_DATA_PATH, "r") as f:
        signatures = json.load(f)

    docs = []
    for sig in signatures:
        content = (
            f"Threat: {sig['name']}\n"
            f"Family: {sig['family']}\n"
            f"Attack Vector: {sig['attack_vector']}\n"
            f"Encoding: {sig['encoding']}\n"
            f"Target Field: {sig['target_field']}\n"
            f"Signature: {sig['signature']}\n"
            f"Description: {sig['description']}\n"
            f"Mitigation: {sig['mitigation']}\n"
            f"Vinod's Notes: {sig['vinod_notes']}\n"
            f"Severity: {sig['severity']}\n"
            f"CVE Ref: {sig['cve_ref']}"
        )
        docs.append(Document(
            page_content=content,
            metadata={
                "id": sig["id"],
                "name": sig["name"],
                "family": sig["family"],
                "severity": sig["severity"],
                "cve_ref": sig["cve_ref"],
            }
        ))
    return docs


def build_vectorstore() -> Chroma:
    """Build or load the ChromaDB vectorstore from threat signatures."""
    embeddings = _get_embeddings()
    CHROMA_PERSIST_DIR.mkdir(parents=True, exist_ok=True)

    # If DB already exists, load it
    if (CHROMA_PERSIST_DIR / "chroma.sqlite3").exists():
        return Chroma(
            persist_directory=str(CHROMA_PERSIST_DIR),
            embedding_function=embeddings,
        )

    # First run: build from JSON
    docs = _load_threat_signatures()
    vectorstore = Chroma.from_documents(
        documents=docs,
        embedding=embeddings,
        persist_directory=str(CHROMA_PERSIST_DIR),
    )
    return vectorstore


def query_threat_signatures(query: str, k: int = 3) -> str:
    """
    Query the RAG database for threats matching the given description.
    Returns formatted string of top-k matching threat signatures.
    Used by the OpenClaw agent when analyzing an incoming threat log.
    """
    try:
        vectorstore = build_vectorstore()
        results = vectorstore.similarity_search(query, k=k)
        if not results:
            return "No matching threat signatures found in database."

        output = f"TOP {len(results)} MATCHING THREAT SIGNATURES:\n{'=' * 50}\n\n"
        for i, doc in enumerate(results, 1):
            output += f"[Match {i}] {doc.metadata.get('name', 'Unknown')}\n"
            output += f"Severity: {doc.metadata.get('severity', 'UNKNOWN')}\n"
            output += f"{doc.page_content}\n\n{'─' * 40}\n\n"
        return output.strip()

    except Exception as e:
        return f"RAG query failed: {str(e)}. Proceeding with direct analysis."


# Expose as a LangChain tool
from langchain_core.tools import tool

@tool
def rag_threat_lookup(query: str) -> str:
    """
    Look up matching threat signatures from Vinod's Known Threat Signatures database.
    Use this when analyzing an incoming wireless edge log to identify the attack family,
    find past mitigations, and match the encoding technique.

    Args:
        query: Description of the observed payload or anomaly (e.g., 'base64 encoded string in telemetry field')

    Returns:
        Top matching threat signatures with mitigations and Vinod's personal notes.
    """
    return query_threat_signatures(query)
