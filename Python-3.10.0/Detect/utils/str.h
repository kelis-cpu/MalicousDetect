#ifndef DETECT_UTILS_STR_H
#define DETECT_UTILS_STR_H

extern char *str_convert_wchar_to_string(const wchar_t *pSrc);
extern PyObject* str_copy_from_unicode_object(PyObject* obj);
extern bool str_compare_unicode_object_with_string(PyObject *uni_obj, const char *str);
extern Py_ssize_t str_unicode_object_find_string(PyObject *uni_obj, const char *str, Py_ssize_t start, 
										Py_ssize_t end, int direction);

#endif

