__author__ = "Benjamin Mickler"
__copyright__ = "Copyright 2022, Benjamin Mickler"
__credits__ = ["Benjamin Mickler"]
__license__ = "GPLv3 or later"
__version__ = "12082022"
__maintainer__ = "Benjamin Mickler"
__email__ = "ben@benmickler.com"

"""
ldae format:
[symmetric encryption key encrypted with public key]?[encrypted data][format]


ldae is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

ldae is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along with
ldae. If not, see <https://www.gnu.org/licenses/>.
"""

import base64
import sys
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class key:
    def __init__(self, filename=None, public_key_filename=None, private_key_filename=None):
        self.public_key_filename = public_key_filename
        self.private_key_filename = private_key_filename
        self.filename = filename
        self.exists = False
        self.key = Fernet.generate_key()
        if filename != None or public_key_filename != None and private_key_filename != None:
            self.load()
    def load(self):
        if not self.filename:
            if os.path.isfile(self.private_key_filename) and os.path.isfile(self.public_key_filename):
                self.exists = True
                with open(self.private_key_filename, "rb") as key_file:
                    self.private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,
                        backend=default_backend()
                    )
                with open(self.public_key_filename, "rb") as key_file:
                    self.public_key = serialization.load_pem_public_key(
                        key_file.read(),
                        backend=default_backend()
                    )
        else:
            if os.path.isfile(self.filename):
                self.exists = True
                with open(self.filename, "rb") as key_file:
                    file_data = key_file.read()
                self.private_key = serialization.load_pem_private_key(
                    file_data.split(b"\r\n")[0],
                    password=None,
                    backend=default_backend()
                )
                self.public_key = serialization.load_pem_public_key(
                    file_data.split(b"\r\n")[1],
                    backend=default_backend()
                )
    def create(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        if self.public_key_filename and self.private_key_filename:
            self.exists = True
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(self.private_key_filename, 'wb') as f:
                f.write(private_pem)
            with open(self.public_key_filename, 'wb') as f:
                f.write(public_pem)
        elif self.filename:
            self.exists = True
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(self.filename, 'wb') as f:
                f.write(private_pem+b"\r\n"+public_pem)

class ldae:
    def __init__(self, key):
        self.key = key
    def encrypt(self, data):
        data_str = False
        if isinstance(data, str):
            data_str = True
            data = data.encode()
        message_key = self.key.public_key.encrypt(
            self.key.key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        f = Fernet(self.key.key)
        data = f.encrypt(data)
        data = base64.b64encode(message_key)+b"?"+base64.b64encode(data)+(b"1" if data_str else b"0")
        return data
    def decrypt(self, data, data_str=False):
        data_str = True if data[-1:] == b"1" else False
        data = data.decode()[:-1].encode()
        data = data.split(b"?")
        message_key = base64.b64decode(data[0])
        message = base64.b64decode(data[1])
        try:
            key = self.key.private_key.decrypt(
                message_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            f = Fernet(key)
            original_message = f.decrypt(message)
            if data_str:
                return original_message.decode()
            return original_message
        except:
            return False