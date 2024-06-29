from ctypes import CDLL, c_char_p, c_void_p

lib = CDLL('./enclib.so')

lib.Encrypt_new.restype = c_void_p
lib.encryptFile_C.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p, c_char_p]
lib.encryptFile_C.restype = None
lib.Encrypt_delete.argtypes = [c_void_p]
lib.Encrypt_delete.restype = None

lib.Decrypt_new.restype = c_void_p
lib.decryptFile_C.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p, c_char_p]
lib.decryptFile_C.restype = None
lib.Decrypt_delete.argtypes = [c_void_p]
lib.Decrypt_delete.restype = None

class Encrypt:
    def __init__(self):
        self.obj = lib.Encrypt_new()
    def encrypt_file(self, file_name, encrypt_file_name, public_key_file, private_key_file):
        file_name_c = c_char_p(file_name.encode('utf-8'))
        encrypt_file_name_c = c_char_p(encrypt_file_name.encode('utf-8'))
        public_key_file_c = c_char_p(public_key_file.encode('utf-8'))
        private_key_file_c = c_char_p(private_key_file.encode('utf-8'))
        lib.encryptFile_C(self.obj, file_name_c, encrypt_file_name_c, public_key_file_c, private_key_file_c)
    def __del__(self):
        lib.Encrypt_delete(self.obj)

class Decrypt:
    def __init__(self):
        self.obj = lib.Decrypt_new()
    def decrypt_file(self, encrypt_file_name, decrypt_file_name, public_key_file, private_key_file):
        encrypt_file_name_c = c_char_p(encrypt_file_name.encode('utf-8'))
        decrypt_file_name_c = c_char_p(decrypt_file_name.encode('utf-8'))
        public_key_file_c = c_char_p(public_key_file.encode('utf-8'))
        private_key_file_c = c_char_p(private_key_file.encode('utf-8'))
        lib.decryptFile_C(self.obj, encrypt_file_name_c, decrypt_file_name_c, public_key_file_c, private_key_file_c)
    def __del__(self):
        lib.Decrypt_delete(self.obj)

# TEST
enc = Encrypt()
filename = "test.txt"
encryptedFilename = "encryptedfile.bin"
masterPassword = "your-master-password"
privateKeyFile = "private.txt"
publicKeyFile = "public.txt"

enc.encrypt_file(filename, encryptedFilename, publicKeyFile, privateKeyFile)

dec = Decrypt()
decryptedFilename = "decryptedfile.txt"
dec.decrypt_file(encryptedFilename, decryptedFilename, publicKeyFile, privateKeyFile)
    
