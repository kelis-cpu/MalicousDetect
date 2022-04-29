/*
 * @Description: 与list对象相关的操作函数
 */

#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "frameobject.h"

/**
 * @description: 获取list的顶层元素
 * @param list_obj list对象
 * @return PyObject* 顶层元素
 */
PyObject* list_top(PyObject *list_obj) {
	return PyList_GetItem(list_obj, PyList_Size(list_obj)-1);
}

/**
 * @description: 删除list最后位置的元素并返回
 * @param list_obj list对象
 * @return PyObject* 顶层元素
 */
PyObject* list_pop(PyObject *list_obj) {
	PyObject *pop_func_obj, *args_tuple, *top_item;

	pop_func_obj = PyObject_GetAttrString((PyObject*)&PyList_Type, "pop");	
	if (pop_func_obj == NULL) {
		return NULL;
	}

	args_tuple = PyTuple_New(1);
	PyTuple_SetItem(args_tuple, 0, list_obj);
	Py_INCREF(list_obj);

	top_item = PyObject_Call(pop_func_obj, args_tuple, NULL);

	Py_DECREF(args_tuple);

	return top_item;
}

