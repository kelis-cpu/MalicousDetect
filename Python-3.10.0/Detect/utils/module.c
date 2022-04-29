/*
 * @Description: 与module对象相关的操作函数
 */

#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "frameobject.h"
#include "pycore_pyerrors.h"
#include "Detect/utils/module.h"

/**
 * @description: 根据模块名检查该模块是否已被导入
 * @param module_name 模块名字符串
 */
bool module_is_imported_by_name(PyObject *module_name) {
	PyObject *sys_modules = NULL;
	PyObject *module_object = NULL;

	/* 获取sys.modules字典 */
	sys_modules = PyImport_GetModuleDict();
	if (NULL == sys_modules) {
		return false;
	}

	/* 从sys.modules字典中查找模块名 */
	module_object = PyDict_GetItem(sys_modules, module_name);
	if (NULL == module_object) {
		return false;
	}

	return true;
}

/**
 * @description: 根据模块名获取该模块的__dict__属性字典，存放着属性，方法的键值对
 * @param module_name 模块名字符串
 */
PyObject *module_get_module_dict_by_name(PyObject *module_name) {
	PyObject *sys_modules;
	PyObject *module_object = NULL;

	/* 获取sys.modules字典 */
	sys_modules = PyImport_GetModuleDict();
	if (NULL == sys_modules) {
		return NULL;
	}

	/* 从sys.modules字典中查找模块名 */
	module_object = PyDict_GetItem(sys_modules, module_name);
	if (NULL == module_object) {
		return NULL;
	}

	return PyModule_GetDict(module_object);
}

/**
 * @description: opcode IMPORT_NAME的实现(copy from ceval.c:import_name)
 * @param module_name 模块名字符串
 */
PyObject *module_import_name(PyThreadState *tstate, PyFrameObject *f,
            PyObject *name, PyObject *fromlist, PyObject *level)
{
    _Py_IDENTIFIER(__import__);
    PyObject *import_func, *res;
    PyObject* stack[5];

    import_func = _PyDict_GetItemIdWithError(f->f_builtins, &PyId___import__);
    if (import_func == NULL) {
        if (!_PyErr_Occurred(tstate)) {
            _PyErr_SetString(tstate, PyExc_ImportError, "__import__ not found");
        }
        return NULL;
    }

    /* Fast path for not overloaded __import__. */
    if (import_func == tstate->interp->import_func) {
        int ilevel = _PyLong_AsInt(level);
        if (ilevel == -1 && _PyErr_Occurred(tstate)) {
            return NULL;
        }
        res = PyImport_ImportModuleLevelObject(
                        name,
                        f->f_globals,
                        f->f_locals == NULL ? Py_None : f->f_locals,
                        fromlist,
                        ilevel);
        return res;
    }

    Py_INCREF(import_func);

    stack[0] = name;
    stack[1] = f->f_globals;
    stack[2] = f->f_locals == NULL ? Py_None : f->f_locals;
    stack[3] = fromlist;
    stack[4] = level;
    res = _PyObject_FastCall(import_func, stack, 5);
    Py_DECREF(import_func);
    return res;
}

/**
  * @description: 创建一个新的module对象到sys.modules字典
  * @param module_name 模块名字符串，可以是"xxx.xxx"
  * @return PyObject* 新创建的模块对象列表
  */
PyObject* module_create_module(PyObject *module_name) {
	PyObject *sys_modules, *new_module_obj_list;
	PyObject *module_name_list, *module_name_obj, *sep_obj;
	PyObject *top_module_obj, *sub_module_obj, *last_level_module_obj;
	int index;

	new_module_obj_list = PyList_New(0);

	/* 将模块名按"."切割 */
	sep_obj = PyUnicode_FromString(".");
	module_name_list = PyUnicode_Split(module_name, sep_obj, -1);

	if (PyList_Size(module_name_list) == 0) {
		return new_module_obj_list;
	}

	/* 判断顶层模块是否存在 */
	module_name_obj = PyList_GetItem(module_name_list, 0);

	/* 检查模块是否存在 */
	top_module_obj = PyImport_Import(module_name_obj);
	if (top_module_obj == NULL) {
		/* 创建模块 */
		top_module_obj = PyModule_NewObject(module_name_obj);

		/* 获取sys.modules字典 */
		sys_modules = PyImport_GetModuleDict();
		if (NULL == sys_modules) {
			return NULL;
		}

		/* 标记该模块是被创建的 */
		PyModule_AddObject(top_module_obj, CREATED_BY_DETECT_KEY, Py_True);

		/* 向sys.modules字典中添加模块对象 */
		PyDict_SetItem(sys_modules, module_name_obj, top_module_obj);

		PyList_Append(new_module_obj_list, top_module_obj);
	}

	/* 记录上一层模块 */
	last_level_module_obj = top_module_obj;

	/* 处理子模块 */
	for (index = 1; index < PyList_Size(module_name_list); index++) {
		/* 构建子模块名 */
		module_name_obj = PyUnicode_Join(sep_obj, PyList_GetSlice(module_name_list, 0, index+1));

		/* 检查子模块是否存在 */
		sub_module_obj = PyImport_Import(module_name_obj);
		if (sub_module_obj == NULL) {
			/* 创建子模块 */
			sub_module_obj = PyModule_NewObject(PyList_GetItem(module_name_list, index));

			/* 标记该模块是被创建的 */
			PyModule_AddObject(sub_module_obj, CREATED_BY_DETECT_KEY, Py_True);

			/* 将创建的子模块添加进上一层的模块字典中 */
			PyModule_AddObject(last_level_module_obj, 
					PyUnicode_AsUTF8(PyList_GetItem(module_name_list, index)), sub_module_obj);

			/* 同时将其添加进sys.modules，因为import时会优先从sys.modules中导入，否则会
			 * 调用__import__ python函数去导入，它会检查模块的__path__是否存在来判断是否真的
			 * 是一个包，而我们新建的模块并没有__path__，所以会导入出错。这里参考os.path模块
			 * 的做法，将其也加入sys.modules
			 */
			PyDict_SetItem(sys_modules, module_name_obj, sub_module_obj);

			PyList_Append(new_module_obj_list, sub_module_obj);
		}

		/* 记录上一层模块 */
		last_level_module_obj = sub_module_obj;

		Py_DECREF(module_name_obj);
		//Py_DECREF(sub_module_obj);
	}

	Py_DECREF(sep_obj);
	Py_DECREF(module_name_list);
	//Py_DECREF(top_module_obj);

	return new_module_obj_list;
}

/**
  * @description: 根据属性名从模块对象中获取属性值，属性不存在时不会设置异常
  * @param module_obj 模块对象
  * @param attr_name 属性名
  * @return PyObject* 属性值
  */
PyObject* module_get_attr_by_string(PyObject *module_obj, const char *attr_name) {
	PyObject *attr_value;

	attr_value = PyObject_GetAttrString(module_obj, attr_name);
	if (attr_value == NULL && PyErr_ExceptionMatches(PyExc_AttributeError)) {
		PyErr_Clear();
	}

	return attr_value;
}

/**
  * @description: 根据属性名从模块对象中获取属性值，属性不存在时不会设置异常
  * @param module_obj 模块对象
  * @param attr_name 属性名
  * @return PyObject* 属性值
  */
PyObject* module_get_attr(PyObject *module_obj, PyObject *attr_name) {
	PyObject *attr_value;

	attr_value = PyObject_GetAttr(module_obj, attr_name);
	if (attr_value == NULL && PyErr_ExceptionMatches(PyExc_AttributeError)) {
		PyErr_Clear();
	}

	return attr_value;
}

