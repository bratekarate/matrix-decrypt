#include "matrix_session_extract.h";

// Extract AES-256-CTR key with embedded python
const unsigned char *calc_aes_key(const char *passphrase, const size_t rounds,
                                  const char *salt) {
  Py_Initialize();
  PyObject *moduleMainString = PyUnicode_FromString("__main__");
  PyObject *moduleMain = PyImport_Import(moduleMainString);

  PyRun_SimpleString("import sys\nimport pbkdf2\n"
                     "from Crypto.Hash import SHA512\n"
                     "from Crypto.Hash import HMAC\n\n"
                     "def calc_key(passphrase, iterations, salt):\n"
                     "    key = pbkdf2.PBKDF2(passphrase, salt, iterations, "
                     "SHA512, HMAC).read(64)\n"
                     "    return key\n");

  PyObject *func = PyObject_GetAttrString(moduleMain, "calc_key");
  PyObject *args =
      PyTuple_Pack(3, PyUnicode_FromString(passphrase), PyLong_FromLong(rounds),
                   PyBytes_FromString(salt));

  PyObject *result = PyObject_CallObject(func, args);
  Py_Finalize();

  /*return (const unsigned char *)PyUnicode_AsUTF8(result);*/
  return (const unsigned char *)PyBytes_AsString(result);
}
