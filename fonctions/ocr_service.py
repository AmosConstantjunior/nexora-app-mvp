import tempfile
from firebase_admin import storage
from PyPDF2 import PdfReader
import pytesseract
from PIL import Image

def extract_text_from_file(file_id):
    bucket = storage.bucket()
    blob = bucket.blob(file_id)
    suffix = file_id.split('.')[-1].lower()

    with tempfile.NamedTemporaryFile(suffix='.' + suffix, delete=True) as temp_file:
        blob.download_to_filename(temp_file.name)
        if suffix == "pdf":
            reader = PdfReader(temp_file.name)
            text = "\n".join([page.extract_text() or "" for page in reader.pages])
            return text.strip()
        elif suffix in ["png", "jpg", "jpeg", "bmp", "tiff"]:
            image = Image.open(temp_file.name)
            text = pytesseract.image_to_string(image)
            return text.strip()
        else:
            raise ValueError("Type de fichier non pris en charge")
