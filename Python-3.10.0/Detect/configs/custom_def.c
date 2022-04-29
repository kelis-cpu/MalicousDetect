/*
 * @Description: 自定义逻辑的类/方法/函数定义
 */

#include <stdio.h>
#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"
#include "Detect/configs/custom_def.h"
#include "Detect/object/object_common.h"
#include "Detect/utils/dict.h"

/**
 * @description: 跳过当前处理逻辑的通用处理函数
 * @param hook对象 hook对象
 * @param callable 原被hook的调用对象
 * @param args 位置参数元组
 * @param kwargs 关键字参数字典
 */
static PyObject* detect_config_custom_skip_common(PyObject *self,
												PyObject *callable, 
												PyObject *args,
	  								            PyObject *kwargs) {

	return detect_object_class_call(self, args, kwargs);
}

/* 自定义类定义 */
static DETECT_CUSTOM_DEF g_custom_class_def[] = {
	
};

/* 自定义方法定义 */
static DETECT_CUSTOM_DEF g_custom_method_def[] = {
	
};

/* 自定义函数定义 */
static DETECT_CUSTOM_DEF g_custom_func_def[] = {
	/* 跳过执行的函数 */
	{"os", NULL, NULL, "dup", detect_config_custom_skip_common},
	{"os", NULL, NULL, "dup2", detect_config_custom_skip_common},
	{"os", NULL, NULL, "exit", detect_config_custom_skip_common},
	{"os", NULL, NULL, "fork", detect_config_custom_skip_common},
	{"sys", NULL, NULL, "exit", detect_config_custom_skip_common},
	{"time", NULL, NULL, "sleep", detect_config_custom_skip_common},
	{"ctypes", NULL, NULL, "c_char_p", detect_config_custom_skip_common},
	{"ctypes", NULL, NULL, "c_void_p", detect_config_custom_skip_common},
	{"ctypes", NULL, NULL, "CFUNCTYPE", detect_config_custom_skip_common},
	{"ctypes", NULL, NULL, "memmove", detect_config_custom_skip_common},
	{"ctypes", NULL, NULL, "cast", detect_config_custom_skip_common},
	{"cgitb", NULL, NULL,  "enable", detect_config_custom_skip_common},
	{"importlib", NULL, NULL,  "reload", detect_config_custom_skip_common},
};

/* 下面这些字典全局变量供其他模块使用 */
PyObject *g_custom_class_dict;  // 自定义类字典
PyObject *g_custom_method_dict; // 自定义方法字典
PyObject *g_custom_func_dict;   // 自定义函数字典

PyObject *g_custom_all_dict;    // 包含上述四种自定义的集合字典

/**
 * @description: 自定义配置初始化，主要是构建各外部输入对象的字典
 */
void detect_config_custom_def_init() {
	unsigned int index;
	PyObject *dict_tmp;

	g_custom_class_dict  = PyDict_New();
	g_custom_method_dict = PyDict_New();
	g_custom_func_dict   = PyDict_New();
	g_custom_all_dict    = PyDict_New();

	/* 
	  初始化自定义类字典, key为"模块名-类名, 
	  value为dict{"module_name": xxx, "class_name": xxx, "taint_pos": list{0, ...}}
	 */
	for (index = 0; index < sizeof(g_custom_class_def)/sizeof(DETECT_CUSTOM_DEF); index++) {
		dict_tmp = PyDict_New();

		dict_setitem_string_string(dict_tmp, MODULE_NAME_STRING, 	 g_custom_class_def[index].module_name);
		dict_setitem_string_string(dict_tmp, CLASS_NAME_STRING,      g_custom_class_def[index].class_name);
		dict_setitem_string_object(dict_tmp, CONFIG_OBJ_TYPE_STRING, PyLong_FromLong(DETECT_CONFIG_OBJ_TYPE_CLASS));
		dict_setitem_string_object(dict_tmp, CUSTOM_FUNC_STRING,     PyLong_FromVoidPtr(g_custom_class_def[index].pfunc));

		PyDict_SetItem(g_custom_class_dict,
					   PyUnicode_FromFormat("%s-%s", g_custom_class_def[index].module_name,
						  				       g_custom_class_def[index].class_name),
					   dict_tmp);
	}

	/* 初始化自定义方法字典 */
	for (index = 0; index < sizeof(g_custom_method_def)/sizeof(DETECT_CUSTOM_DEF); index++) {
		dict_tmp = PyDict_New();

		dict_setitem_string_string(dict_tmp, MODULE_NAME_STRING, 	 g_custom_method_def[index].module_name);
		dict_setitem_string_string(dict_tmp, CLASS_NAME_STRING,      g_custom_method_def[index].class_name);
		dict_setitem_string_string(dict_tmp, METHOD_NAME_STRING,     g_custom_method_def[index].method_name);
		dict_setitem_string_object(dict_tmp, CONFIG_OBJ_TYPE_STRING, PyLong_FromLong(DETECT_CONFIG_OBJ_TYPE_METHOD));
		dict_setitem_string_object(dict_tmp, CUSTOM_FUNC_STRING,     PyLong_FromVoidPtr(g_custom_method_def[index].pfunc));

		PyDict_SetItem(g_custom_method_dict,
					   PyUnicode_FromFormat("%s-%s-%s", 
					   						g_custom_method_def[index].module_name,
						  				    g_custom_method_def[index].class_name,
						  				    g_custom_method_def[index].method_name),
					   dict_tmp);
	}

	/* 初始化自定义函数字典 */
	for (index = 0; index < sizeof(g_custom_func_def)/sizeof(DETECT_CUSTOM_DEF); index++) {
		dict_tmp = PyDict_New();

		dict_setitem_string_string(dict_tmp, MODULE_NAME_STRING, 	 g_custom_func_def[index].module_name);
		dict_setitem_string_string(dict_tmp, FUNC_NAME_STRING,       g_custom_func_def[index].func_name);
		dict_setitem_string_object(dict_tmp, CONFIG_OBJ_TYPE_STRING, PyLong_FromLong(DETECT_CONFIG_OBJ_TYPE_FUNC));
		dict_setitem_string_object(dict_tmp, CUSTOM_FUNC_STRING,     PyLong_FromVoidPtr(g_custom_func_def[index].pfunc));

		PyDict_SetItem(g_custom_func_dict,
					   PyUnicode_FromFormat("%s-%s", 
					   						g_custom_func_def[index].module_name,
						  				    g_custom_func_def[index].func_name),
					   dict_tmp);
	}

	/* 合并三个自定义字典到一个字典中 */
	PyDict_Merge(g_custom_all_dict, g_custom_class_dict, 1);
	PyDict_Merge(g_custom_all_dict, g_custom_method_dict, 1);
	PyDict_Merge(g_custom_all_dict, g_custom_func_dict, 1);

	return ;
}

