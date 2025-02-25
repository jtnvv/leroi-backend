import pytest
from fastapi.testclient import TestClient
from app.main import app  


client = TestClient(app)
@pytest.mark.parametrize("file_size, expected_status", [
    (20, 200),     # Archivo pequeño válido
    (50_000_000, 200),  # Archivo grande de 50 MB
    (100_000_000, 400),  # Archivo demasiado grande (100 MB) para validar límites
])
def test_process_file(file_size, expected_status):
    """
    Prueba el endpoint /process-file con diferentes tamaños de archivos en base64.
    """
    test_payload = {
        "fileName": "test_file.txt",
        "fileType": "text/plain",  
        "fileSize": file_size, 
        "fileBase64": "VGhpcyBpcyBhIHRlc3QgZmlsZQ=="  
    }

    response = client.post("/process-file", json=test_payload)

    
    if response.status_code != expected_status:
        print(" ERROR:", response.status_code, response.json())

    assert response.status_code == expected_status

