import pytest
from src.main import AntivirusApp

@pytest.fixture
def app():
    """Fixture to create an instance of AntivirusApp."""
    return AntivirusApp()

def test_app_initialization(app):
    """Test that the AntivirusApp initializes correctly."""
    assert app.root.title() == "Antivirus Project"
    assert app.server_thread is None
    assert app.server_running is False

def test_create_main_screen(app):
    """Test that the main screen is created without errors."""
    app.create_main_screen()
    assert app.root.winfo_children()