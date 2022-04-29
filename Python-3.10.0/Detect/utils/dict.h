#ifndef DETECT_UTILS_DICT_H
#define DETECT_UTILS_DICT_H

extern int dict_setitem_string_string(PyObject *op, const char *key, const char *value);
extern const char* dict_getitem_string_string(PyObject *op, const char *key);
extern int dict_setitem_string_long(PyObject *op, const char *key, long value);
extern int dict_setitem_string_object(PyObject *op, const char *key, PyObject *value);

#endif

