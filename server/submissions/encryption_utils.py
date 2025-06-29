# submissions/encryption_utils.py - Additional encryption utilities
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings
import base64
import json

class AdvancedEncryption:
    """Advanced encryption utilities for sensitive operations"""
    
    def __init__(self):
        self.key = self._get_encryption_key()
        self.fernet = Fernet(self.key)
    
    def _get_encryption_key(self):
        """Generate or retrieve encryption key"""
        password = settings.CRYPTOGRAPHY_KEY.encode()
        salt = b'stable_salt_for_formsite'  # In production, use random salt per record
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def encrypt_json(self, data):
        """Encrypt JSON data"""
        json_str = json.dumps(data, sort_keys=True)
        encrypted = self.fernet.encrypt(json_str.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt_json(self, encrypted_data):
        """Decrypt JSON data"""
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
        decrypted = self.fernet.decrypt(encrypted_bytes)
        return json.loads(decrypted.decode())
    
    def encrypt_file(self, file_path):
        """Encrypt file contents"""
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        encrypted_data = self.fernet.encrypt(file_data)
        
        encrypted_path = f"{file_path}.encrypted"
        with open(encrypted_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)
        
        # Securely delete original
        self._secure_delete(file_path)
        return encrypted_path
    
    def decrypt_file(self, encrypted_file_path, output_path):
        """Decrypt file contents"""
        with open(encrypted_file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()
        
        decrypted_data = self.fernet.decrypt(encrypted_data)
        
        with open(output_path, 'wb') as output_file:
            output_file.write(decrypted_data)
        
        return output_path
    
    def _secure_delete(self, file_path):
        """Securely delete file by overwriting"""
        if os.path.exists(file_path):
            # Overwrite with random data multiple times
            file_size = os.path.getsize(file_path)
            for _ in range(3):
                with open(file_path, 'rb+') as file:
                    file.write(os.urandom(file_size))
                    file.flush()
                    os.fsync(file.fileno())
            os.remove(file_path)
