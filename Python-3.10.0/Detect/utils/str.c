/*
 * @Description: 与字符串操作相关的函数
 */

#include <stdbool.h>
#include <wchar.h>
#include "Python.h"

/**
 * @description: 将wchar_t字符串转换为char*, 只适用于内容为ascii字符的情况,
 *               申请的空间需要在外层释放
 * @param module_name 模块名字符串
 */
char *str_convert_wchar_to_string(const wchar_t *pSrc) {
	char *pDest;
	int src_len = 0;
	int index;

    src_len = wcslen(pSrc);

    if (src_len < 1) {
		return NULL;
    }

    pDest = PyMem_RawMalloc(src_len+1);

    for (index = 0; index < src_len; index++) {
		pDest[index] = (char)pSrc[index];
	}

	pDest[src_len] = '\0';

	return pDest;
}

/**
 * @description: 复制一个字符串对象
 * @param PyObject*
 */
PyObject* str_copy_from_unicode_object(PyObject* obj) {
	if (obj == NULL) {
		return NULL;
	}

	return _PyUnicode_Copy(obj);
}

/**
 * @description: 比较一个unicode对象和一个字符串
 * @param bool
 */
bool str_compare_unicode_object_with_string(PyObject *uni_obj, const char *str) {
	if (uni_obj == NULL || str == NULL) {
		return false;
	}

	if (PyUnicode_CompareWithASCIIString(uni_obj, str)) {
		return false;
	}

	return true;
}

/**
 * @description: 在一个unicode对象中找一个str
 */
Py_ssize_t str_unicode_object_find_string(PyObject *uni_obj, const char *str, Py_ssize_t start, 
										Py_ssize_t end, int direction) {
	PyObject *str_obj;
	Py_ssize_t pos;

	str_obj = PyUnicode_FromString(str);
	pos = PyUnicode_Find(uni_obj, str_obj, start, end, direction);
	Py_DECREF(str_obj);

	return pos;
}