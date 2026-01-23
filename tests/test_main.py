def test_app_starts(client):
    response = client.get("/")
    assert response.status_code in [200, 404]
