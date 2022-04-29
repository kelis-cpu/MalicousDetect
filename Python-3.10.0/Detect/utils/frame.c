/*
 * @Description: 与frame对象相关的操作函数
 */

#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "frameobject.h"
#include "str.h"
 
/**
  * @description: 检查frame对象是否属于直接被执行的主文件
  * @param tstate 线程对象
  * @param frame  栈帧对象
  */
bool frame_is_belong_running_mainfile(PyThreadState *tstate, PyFrameObject *frame) {
	PyObject *filename = NULL;
	bool is_belong = false;

	if (tstate->interp->config.run_filename == NULL) {
		return false;
	}

	filename = PyUnicode_FromWideChar(tstate->interp->config.run_filename, -1);

	if (!PyUnicode_Compare(frame->f_code->co_filename, filename)) {
		is_belong = true;
	}

	Py_DECREF(filename);

	return is_belong;
}

/**
 * @description: 根据当前的frame对象判断当前执行的是否是frozen模块
 * @param frame 栈帧对象
 * @return bool				
 */
static bool frame_is_frozen_frame(PyFrameObject *frame) {
	const struct _frozen *p;
	PyCodeObject *code = PyFrame_GetCode(frame);
	PyObject *filename = code->co_filename;

	Py_DECREF(code);

	if (filename == NULL) {
		return false;
	}

	for (p = PyImport_FrozenModules; ; p++) {
		if (p->name == NULL) {
	 		continue;
		}
		if (_PyUnicode_EqualToASCIIString(filename, p->name)) {
			return true;
			break;
		}
	}
	
	return false;
}


 /**
  * @description: 根据当前的frame对象判断当前执行的是否是importlib._bootstrap
  * 			  中的代码，copy from _warnings.c:758
  * @param frame 栈帧对象
  * @return bool
  */
bool frame_is_internal_frame(PyFrameObject *frame) {
	PyCodeObject *code = PyFrame_GetCode(frame);
	PyObject *filename = code->co_filename;
	const char *pattern = "<frozen";

	Py_DECREF(code);

	/* 内部帧都以"<frozen"开头 */
	if (str_unicode_object_find_string(filename, pattern, 0, strlen(pattern)+1, 1) == 0) {
		return true;
	}

	return false;
#if 0
	static PyObject *importlib_string = NULL;
	static PyObject *bootstrap_string = NULL;
	int contains;

	if (importlib_string == NULL) {
		importlib_string = PyUnicode_FromString("importlib");
	 	if (importlib_string == NULL) {
			return 0;
	 	}

		bootstrap_string = PyUnicode_FromString("_bootstrap");
		if (bootstrap_string == NULL) {
			Py_DECREF(importlib_string);
			return 0;
	 	}
	 	Py_INCREF(importlib_string);
	 	Py_INCREF(bootstrap_string);
	}

	if (frame == NULL) {
		return 0;
	}

	PyCodeObject *code = PyFrame_GetCode(frame);
	PyObject *filename = code->co_filename;
	Py_DECREF(code);

	if (filename == NULL) {
		return 0;
	}

	if (!PyUnicode_Check(filename)) {
		return 0;
	}

	contains = PyUnicode_Contains(filename, importlib_string);
	if (contains < 0) {
		return 0;
	} else if (contains > 0) {
		contains = PyUnicode_Contains(filename, bootstrap_string);
		if (contains < 0) {
			return 0;
		} else if (contains > 0) {
			return 1;
		}
	}

	return 0;
#endif
}

/**
  * @description: 检查frame对象是否属于lib目录下的模块
  * @param tstate 线程对象
  * @param frame  栈帧对象
  */
bool frame_is_belong_lib(PyThreadState *tstate, PyFrameObject *frame) {
	PyObject *executable_name, *norm_executable_name, *norm_frame_filename;
	static PyObject *lib_path = NULL;
	PyObject *path_module, *normpath_method, *dirname_method, *join_method;
	bool is_belong = false;

	if (tstate->interp->config.executable == NULL) {
		return false;
	}
	
	/* 获取path模块和normpath方法 */
	path_module = PyImport_ImportModule("posixpath");
	normpath_method = PyObject_GetAttrString(path_module, "normpath");

	/* 正规化frame所属文件路径 */
	norm_frame_filename = PyObject_CallFunctionObjArgs(
        						normpath_method, frame->f_code->co_filename, NULL);

	/* 获取lib目录 */
	if (lib_path == NULL) {
		PyObject *tmp_path, *parent_path;
		PyObject *lib;

		/* 正规化python解释器路径 */
		executable_name = PyUnicode_FromWideChar(tstate->interp->config.executable, -1);
		norm_executable_name = PyObject_CallFunctionObjArgs(
        						normpath_method, executable_name, NULL);
		
		/* 获取解释器所在目录的父目录 */
		dirname_method = PyObject_GetAttrString(path_module, "dirname");
		tmp_path =  PyObject_CallFunctionObjArgs(
        						dirname_method, norm_executable_name, NULL);
		parent_path = PyObject_CallFunctionObjArgs(
        						dirname_method, tmp_path, NULL);

		/* 和lib拼接成lib目录 */
		lib = PyUnicode_FromString("lib");
		join_method = PyObject_GetAttrString(path_module, "join");
		lib_path = PyObject_CallFunctionObjArgs(
        						join_method, parent_path, lib, NULL);

		Py_DECREF(executable_name);
		Py_DECREF(norm_executable_name);
		//Py_DECREF(tmp_path);
		Py_DECREF(parent_path);
		Py_DECREF(lib);
	}

	/* 判断frame所属文件是否在lib目录下 */
	if (PyUnicode_Find(norm_frame_filename, lib_path, 0, PyUnicode_GET_LENGTH(lib_path)+1, 1) > -1) {
		is_belong = true;
	}

	Py_DECREF(norm_frame_filename);

	return is_belong;
}

