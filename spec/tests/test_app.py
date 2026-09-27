from fastapi.testclient import TestClient

import app as webapp
from tests.fakes import EVIL_HASH, FakeJev
from tests.test_triage import agent


def client(token=None):
    webapp.settings.api_token = token
    c = TestClient(webapp.app)
    webapp.state["agent"] = agent(FakeJev())
    return c


def test_json_and_markdown_and_auth():
    c = client(token="s3cret")
    assert c.post("/triage", content='{"sha256":"%s"}' % EVIL_HASH).status_code == 401
    r = c.post("/triage", content='{"title":"beacon","sha256":"%s"}' % EVIL_HASH, headers={"x-api-key": "s3cret"})
    assert r.status_code == 200 and r.json()["verdict"] == "malicious"
    md = c.post("/triage?format=md", content=f"hash {EVIL_HASH}", headers={"authorization": "Bearer s3cret"})
    assert md.status_code == 200 and "Everything Jev was asked" in md.text
    assert c.get("/health").json()["ok"] is True
    assert "Jev alert triage" in c.get("/").text
    webapp.settings.api_token = None


def test_no_token_fails_closed():
    c = client(token=None)
    webapp.settings.allow_unauthenticated = False
    assert c.post("/triage", content='{"sha256":"%s"}' % EVIL_HASH).status_code == 503
    webapp.settings.allow_unauthenticated = True
    assert c.post("/triage", content='{"sha256":"%s"}' % EVIL_HASH).status_code == 200
    webapp.settings.allow_unauthenticated = False
