/*
 * @Description: 与dict对象相关的操作函数
 */

#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "frameobject.h"

/**
 * @description: key和value都是字符串时的字典元素添加方法
 * @param key 字符串键
 * @param value 字符串值
 */
int dict_setitem_string_string(PyObject *op, const char *key, const char *value) {
	PyObject *key_obj   = PyUnicode_FromString(key);
	PyObject *value_obj = PyUnicode_FromString(value);

	PyDict_SetItem(op, key_obj, value_obj);

	Py_DECREF(key_obj);
	Py_DECREF(value_obj);

	return 0;
}

/**
 * @description: key和value都是字符串时的字典元素获取方法
 * @param key 字符串键
 * @return const char* 字符串值
 */
const char* dict_getitem_string_string(PyObject *op, const char *key) {
	PyObject *value = PyDict_GetItemString(op, key);
	if (NULL == value) {
		return NULL;
	}
	
	return PyUnicode_AsUTF8(value);
}

/**
 * @description: key是string，value是long时的字典元素添加方法
 * @param key 字符串键
 * @param value long型值
 * @return const char* 字符串值
 */
int dict_setitem_string_long(PyObject *op, const char *key, long value) {
	PyObject *key_obj = PyUnicode_FromString(key);
	PyObject *value_obj = PyLong_FromLong(value);

	PyDict_SetItem(op, key_obj, value_obj);

	Py_DECREF(key_obj);
	Py_DECREF(value_obj);
	
	return 0;
}


/**
 * @description: key为string, value为PyObject时的字典元素添加方法
 * @param key 键
 * @param value 值
 */
int dict_setitem_string_object(PyObject *op, const char *key, PyObject *value) {
	PyObject *key_obj = PyUnicode_FromString(key);

	PyDict_SetItem(op, key_obj, value);
	Py_DECREF(key_obj);
	
	return 0;
}

