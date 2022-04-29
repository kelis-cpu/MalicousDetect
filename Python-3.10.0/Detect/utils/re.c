/*
 * @Description: 与正则表达式相关的操作函数
 */

#include <stdbool.h>
#include <wchar.h>
#include "Python.h"

static PyObject* g_re_module = NULL;
static PyObject* g_re_search_method = NULL;

/**
 * @description: re的search实现
 * @param pattern 模式字符串
 * @param string 主串对象
 * @param flags
 */
PyObject* re_search(const char *pattern, PyObject *string, int flags) {
	PyObject *pattern_obj, *flags_obj;
	PyObject *searches;

	/* 获取sre模块和compile方法 */
	if (g_re_module == NULL) {
		g_re_module = PyImport_ImportModule("re");
	}
	if (g_re_search_method == NULL) {
		g_re_search_method = PyObject_GetAttrString(g_re_module, "search");
	}

	/* 执行search */
	pattern_obj = _PyUnicode_FromASCII(pattern, strlen(pattern));
	flags_obj = PyLong_FromLong(flags);
	searches = PyObject_CallFunctionObjArgs(
        g_re_search_method, pattern_obj, string, flags_obj, NULL);

    Py_DECREF(pattern_obj);
	Py_DECREF(flags_obj);

	return searches;
}
