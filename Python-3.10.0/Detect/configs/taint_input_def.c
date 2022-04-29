/*
 * @Description: 外部输入定义
 */

#include <stdio.h>
#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"
#include "Detect/configs/taint_input_def.h"
#include "Detect/utils/dict.h"

/* 外部输入类定义 */
static DETECT_TAINT_INPUT g_taint_input_class_def[] = {
	{"socket",          "socket",        NULL, NULL, NULL, {0}},
	{"paramiko",        "SSHClient",     NULL, NULL, NULL, {0}},
	{"ctypes",          "CDLL",          NULL, NULL, NULL, {0}},
	{"cgi",             "FieldStorage",  NULL, NULL, NULL, {0}},
	{"argparse",        "ArgumentParser",NULL, NULL, NULL, {0}},
	{"urllib.request",  "Request",       NULL, NULL, NULL, {0}},
	{"tornado.netutil", "TCPServer",     NULL, NULL, NULL, {0}}
};

/* 外部输入方法定义 */
static DETECT_TAINT_INPUT g_taint_input_method_def[] = {
	{"socket", "socket", "accept", NULL, NULL, {0}},
};

/* 外部输入函数定义 */
static DETECT_TAINT_INPUT g_taint_input_func_def[] = {
	{"socket",         NULL, NULL, "create_server", NULL, {0}},
	{"builtins",       NULL, NULL, "input",         NULL, {0}},
	{"builtins",       NULL, NULL, "raw_input",     NULL, {0}},
	{"requests",       NULL, NULL, "post",          NULL, {0}},
	{"requests",       NULL, NULL, "get",           NULL, {0}},
	{"wget",           NULL, NULL, "download",      NULL, {0}},
	{"ssl",            NULL, NULL, "wrap_socket",   NULL, {0}},
	{"urllib",         NULL, NULL, "urlopen",       NULL, {0}},
	{"urllib.request", NULL, NULL, "urlopen",       NULL, {0}},
	{"urllib.request", NULL, NULL, "build_opener",  NULL, {0}},
};

/* 外部输入变量定义 */
static DETECT_TAINT_INPUT g_taint_input_var_def[] = {
	{"sys",    NULL, NULL, NULL, "argv",    {0}},
	{"sys",    NULL, NULL, NULL, "argc",    {0}},
	{"ctypes", NULL, NULL, NULL, "windll",  {0}},
	{"os",     NULL, NULL, NULL, "environ", {0}},
};

/* 下面这些字典全局变量供其他模块使用 */
PyObject *g_taint_input_class_dict;  // 外部输入类字典
PyObject *g_taint_input_method_dict; // 外部输入方法字典
PyObject *g_taint_input_func_dict;   // 外部输入函数字典
PyObject *g_taint_input_var_dict;    // 外部输入变量字典

PyObject *g_taint_input_all_dict;    // 包含上述四种外部输入的集合字典

/**
 * @description: 外部输入初始化，主要是构建各外部输入对象的字典
 */
void detect_config_taint_input_def_init() {
	unsigned int index;
	PyObject *dict_tmp;

	g_taint_input_class_dict  = PyDict_New();
	g_taint_input_method_dict = PyDict_New();
	g_taint_input_func_dict   = PyDict_New();
	g_taint_input_var_dict    = PyDict_New();
	g_taint_input_all_dict    = PyDict_New();

	/* 
	  初始化外部输入类字典, key为"模块名-类名, 
	  value为dict{"module_name": xxx, "class_name": xxx, "taint_type": 0, "taint_pos": list{0, ...}}
	 */
	for (index = 0; index < sizeof(g_taint_input_class_def)/sizeof(DETECT_TAINT_INPUT); index++) {
		dict_tmp = PyDict_New();

		dict_setitem_string_string(dict_tmp, MODULE_NAME_STRING, g_taint_input_class_def[index].module_name);
		dict_setitem_string_string(dict_tmp, CLASS_NAME_STRING, g_taint_input_class_def[index].class_name);
		dict_setitem_string_object(dict_tmp, CONFIG_OBJ_TYPE_STRING, PyLong_FromLong(DETECT_CONFIG_OBJ_TYPE_CLASS));
		dict_setitem_string_object(dict_tmp, TAINT_POS_STRING, 
			detect_config_create_pos_list(g_taint_input_class_def[index].taint_pos, MAX_POS));

		PyDict_SetItem(g_taint_input_class_dict,
					   PyUnicode_FromFormat("%s-%s", g_taint_input_class_def[index].module_name,
						  				       g_taint_input_class_def[index].class_name),
					   dict_tmp);
	}

	/* 
	  初始化外部输入方法字典, key为"模块名-类名-方法名"
	  value为dict{"module_name": xxx, "class_name": xxx, "method_name": xxx, "taint_type": 1, "taint_pos": list{0, ...}}
	 */
	for (index = 0; index < sizeof(g_taint_input_method_def)/sizeof(DETECT_TAINT_INPUT); index++) {
		dict_tmp = PyDict_New();

		dict_setitem_string_string(dict_tmp, MODULE_NAME_STRING, g_taint_input_method_def[index].module_name);
		dict_setitem_string_string(dict_tmp, CLASS_NAME_STRING, g_taint_input_method_def[index].class_name);
		dict_setitem_string_string(dict_tmp, METHOD_NAME_STRING, g_taint_input_method_def[index].method_name);
		dict_setitem_string_object(dict_tmp, CONFIG_OBJ_TYPE_STRING, PyLong_FromLong(DETECT_CONFIG_OBJ_TYPE_METHOD));
		dict_setitem_string_object(dict_tmp, TAINT_POS_STRING, 
			detect_config_create_pos_list(g_taint_input_method_def[index].taint_pos, MAX_POS));

		PyDict_SetItem(g_taint_input_method_dict,
					   PyUnicode_FromFormat("%s-%s-%s", 
					   						g_taint_input_method_def[index].module_name,
						  				    g_taint_input_method_def[index].class_name,
						  				    g_taint_input_method_def[index].method_name),
					   dict_tmp);
	}

	/* 
	  初始化外部输入函数字典，key为"模块名-函数名"
	  value为dict{"module_name": xxx, "func_name": xxx, "taint_type": 2, "taint_pos": list{0, ...}}
	 */
	for (index = 0; index < sizeof(g_taint_input_func_def)/sizeof(DETECT_TAINT_INPUT); index++) {
		dict_tmp = PyDict_New();

		dict_setitem_string_string(dict_tmp, MODULE_NAME_STRING, g_taint_input_func_def[index].module_name);
		dict_setitem_string_string(dict_tmp, FUNC_NAME_STRING, g_taint_input_func_def[index].func_name);
		dict_setitem_string_object(dict_tmp, CONFIG_OBJ_TYPE_STRING, PyLong_FromLong(DETECT_CONFIG_OBJ_TYPE_FUNC));
		dict_setitem_string_object(dict_tmp, TAINT_POS_STRING, 
			detect_config_create_pos_list(g_taint_input_func_def[index].taint_pos, MAX_POS));

		PyDict_SetItem(g_taint_input_func_dict,
					   PyUnicode_FromFormat("%s-%s", 
					   						g_taint_input_func_def[index].module_name,
						  				    g_taint_input_func_def[index].func_name),
					   dict_tmp);
	}

	/* 
	  初始化外部输入变量字典，key为"模块名-变量名"
	  value为dict{"module_name": xxx, "var_name": xxx, "taint_type": 3}
	 */
	for (index = 0; index < sizeof(g_taint_input_var_def)/sizeof(DETECT_TAINT_INPUT); index++) {
		dict_tmp = PyDict_New();

		dict_setitem_string_string(dict_tmp, MODULE_NAME_STRING, g_taint_input_var_def[index].module_name);
		dict_setitem_string_string(dict_tmp, VAR_NAME_STRING, g_taint_input_var_def[index].var_name);
		dict_setitem_string_object(dict_tmp, CONFIG_OBJ_TYPE_STRING, PyLong_FromLong(DETECT_CONFIG_OBJ_TYPE_VAR));

		PyDict_SetItem(g_taint_input_var_dict,
					   PyUnicode_FromFormat("%s-%s", 
					   						g_taint_input_var_def[index].module_name,
						  				    g_taint_input_var_def[index].var_name),
					   dict_tmp);
	}

	/* 合并四个外部输入字典到一个字典中 */
	PyDict_Merge(g_taint_input_all_dict, g_taint_input_class_dict, 1);
	PyDict_Merge(g_taint_input_all_dict, g_taint_input_method_dict, 1);
	PyDict_Merge(g_taint_input_all_dict, g_taint_input_func_dict, 1);
	PyDict_Merge(g_taint_input_all_dict, g_taint_input_var_dict, 1);

	return ;
}
