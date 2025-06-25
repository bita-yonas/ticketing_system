import pytest
from app import app, init_db

@pytest.fixture
def client(tmp_path):
    # point to a temp DB
    app.config['DATABASE'] = str(tmp_path/'test.db')
    with app.app_context():
        init_db()
    return app.test_client()

def test_login_page(client):
    res = client.get('/login')
    assert res.status_code == 200
    assert b'<form' in res.data
