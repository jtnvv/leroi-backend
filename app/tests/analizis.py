import pytest
from fastapi.testclient import TestClient
from app.main import app  


client = TestClient(app)

def test_analyze_file():
    """
    Prueba el endpoint /analyze/ enviando un archivo PDF de prueba.
    """
    test_file_content = b"%PDF-1.4\n%Test PDF Content"  

    response = client.post(
        "/analyze/",
        files={"file": ("test.pdf", test_file_content, "application/pdf")},
        data={"email": "test@example.com"}
    )
    
    assert response.status_code in [200, 400, 408] 
    json_response = response.json()
    assert "filename" in json_response  
    assert "has_virus" in json_response 


@pytest.mark.parametrize("file_content, expected_status", [
    (b"%PDF-1.4\n%Valid PDF Content", 200),  # Caso válido
    (b"", 400),  # Archivo vacío
    (b"<script>alert('XSS');</script>", 400),  # Archivo con posible contenido malicioso
])
def test_analyze_file2(file_content, expected_status):
    """
    Prueba el endpoint /analyze/ con diferentes archivos para garantizar seguridad y privacidad.
    """
    response = client.post(
        "/analyze/",
        files={"file": ("test.pdf", file_content, "application/pdf")},
        data={"email": "test@example.com"}
    )
    
    assert response.status_code == expected_status
    
    if response.status_code == 200:
        json_response = response.json()
        assert "filename" in json_response  
        assert "has_virus" in json_response  
        assert isinstance(json_response["has_virus"], bool)  # Debe ser un valor booleano
        
        # Validar que la detección de malware es efectiva
        assert json_response["has_virus"] is False  # En este caso, asumimos que no hay virus

def test_analyze_file_no_email():
    """
    Prueba que la API maneje correctamente la ausencia de un correo electrónico.
    """
    test_file_content = b"%PDF-1.4\n%Valid PDF Content"

    response = client.post(
        "/analyze/",
        files={"file": ("test.pdf", test_file_content, "application/pdf")}
    )
    
    assert response.status_code == 400  # Debería fallar porque falta el email
    assert "detail" in response.json()

