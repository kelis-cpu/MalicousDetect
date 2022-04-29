/*
 * @Description: 威胁定义
 */

#include <stdio.h>
#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"
#include "Detect/configs/threat_def.h"
#include "Detect/utils/dict.h"

/* 威胁类定义 */
static DETECT_THREAT_DEF g_threat_class_def[] = {
	{"subprocess",      "Popen",   NULL, NULL, {1}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"multiprocessing", "Process", NULL, NULL, {1}, DETECT_THREAT_TYPE_THREAD_EXEC, true},
};

/* 威胁方法定义 */
static DETECT_THREAT_DEF g_threat_method_def[] = {
	{"code", "InteractiveConsole", "push",    NULL, {1}, DETECT_THREAT_TYPE_CODE_EXEC},
	{"code", "InteractiveConsole", "runcode", NULL, {1}, DETECT_THREAT_TYPE_CODE_EXEC},
};

/* 威胁函数定义 */
static DETECT_THREAT_DEF g_threat_func_def[] = {
	{"subprocess", NULL, NULL, "call",            {1}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"subprocess", NULL, NULL, "check_output",    {1}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"subprocess", NULL, NULL, "getoutput",       {1}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"subprocess", NULL, NULL, "getstatusoutput", {1}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"subprocess", NULL, NULL, "check_call",      {1}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"subprocess", NULL, NULL, "run",             {1}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "system",          {1}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "popen",           {1}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "popen2",          {1}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "popen3",          {1}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "spawnvpe",        {2, 3}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "spawnvp",         {2, 3}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "spawnve",         {2, 3}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "spawnv",          {2, 3}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "spawnlpe",        {2}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "spawnlp",         {2}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "spawnle",         {2}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "spawnl",          {2}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "execvpe",         {1, 2}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "execvp",          {1, 2}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "execve",          {1, 2}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "execv",           {1, 2}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "execlpe",         {1, 2}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "execlp",          {1, 2}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "execle",          {1, 2}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"os",         NULL, NULL, "execl",           {1, 2}, DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"pty",        NULL, NULL, "spawn",           {1},    DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"popen2",     NULL, NULL, "popen2",          {1},    DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"popen2",     NULL, NULL, "popen3",          {1},    DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"popen2",     NULL, NULL, "popen4",          {1},    DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"scapy.all",  NULL, NULL, "sniff",          {1},    DETECT_THREAT_TYPE_COMMAND_EXEC},
	{"builtins",   NULL, NULL, "eval",            {1},  DETECT_THREAT_TYPE_CODE_EXEC, true}, // 执行原逻辑
	{"builtins",   NULL, NULL, "exec",            {-1}, DETECT_THREAT_TYPE_CODE_EXEC, true}, // 执行原逻辑
	//{"builtins",   NULL, NULL, "__import__",      {-1}, DETECT_THREAT_TYPE_CODE_EXEC, true}, // 该函数会将未定义模块置为威胁对象导致误报
	//{"webbrowser", NULL, NULL, "open_new_tab", {-1}},
	//{"webbrowser", NULL, NULL, "open_new",     {-1}},
	//{"webbrowser", NULL, NULL, "open",         {-1}},
	//{"winreg",     NULL, NULL, "DeleteValue",  {1, 2}},
	//{"winreg",     NULL, NULL, "SetValueEx",   {1, 2, 5}},
	//{"ctype",      NULL, NULL, "mprotect",     {1}}, 
	
};

/* 下面这些字典全局变量供其他模块使用 */
PyObject *g_threat_class_dict;  // 威胁类字典
PyObject *g_threat_method_dict; // 威胁方法字典
PyObject *g_threat_func_dict;   // 威胁函数字典

PyObject *g_threat_all_dict;    // 包含上述四种威胁的集合字典


/**
 * @description: 初始化一个威胁字典的公共域
 * @param dict 威胁字典
 * @param threat_def_item 单个威胁配置项
 * @return void
 */
static void detect_config_construct_threat_dict_common_fields(PyObject *dict, 
                                                              DETECT_THREAT_DEF *threat_def_item) {
	dict_setitem_string_string(dict, MODULE_NAME_STRING,  threat_def_item->module_name);
	dict_setitem_string_object(dict, THREAT_TYPE_STRING,  PyLong_FromLong(threat_def_item->threat_type));
	dict_setitem_string_object(dict, NEED_EXECUTE_STRING, PyBool_FromLong(threat_def_item->need_execute));
	dict_setitem_string_object(dict, TAINT_POS_STRING, 
				detect_config_create_pos_list(threat_def_item->param_pos, MAX_POS));
}

/**
 * @description: 威胁配置初始化，主要是构建各外部输入对象的字典
 */
void detect_config_threat_def_init() {
	unsigned int index;
	PyObject *dict_tmp;

	g_threat_class_dict  = PyDict_New();
	g_threat_method_dict = PyDict_New();
	g_threat_func_dict   = PyDict_New();
	g_threat_all_dict    = PyDict_New();

	/* 
	  初始化威胁类字典, key为"模块名-类名, 
	  value为dict{"module_name": xxx, "class_name": xxx, "taint_pos": list{0, ...}}
	 */
	for (index = 0; index < sizeof(g_threat_class_def)/sizeof(DETECT_THREAT_DEF); index++) {
		dict_tmp = PyDict_New();

		detect_config_construct_threat_dict_common_fields(dict_tmp, &g_threat_class_def[index]);
		dict_setitem_string_string(dict_tmp, CLASS_NAME_STRING,      g_threat_class_def[index].class_name);
		dict_setitem_string_object(dict_tmp, CONFIG_OBJ_TYPE_STRING, PyLong_FromLong(DETECT_CONFIG_OBJ_TYPE_CLASS));

		PyDict_SetItem(g_threat_class_dict,
					   PyUnicode_FromFormat("%s-%s", g_threat_class_def[index].module_name,
						  				       g_threat_class_def[index].class_name),
					   dict_tmp);
	}

	/* 初始化威胁方法字典 */
	for (index = 0; index < sizeof(g_threat_method_def)/sizeof(DETECT_THREAT_DEF); index++) {
		dict_tmp = PyDict_New();

		detect_config_construct_threat_dict_common_fields(dict_tmp, &g_threat_method_def[index]);
		dict_setitem_string_string(dict_tmp, CLASS_NAME_STRING, g_threat_method_def[index].class_name);
		dict_setitem_string_string(dict_tmp, METHOD_NAME_STRING, g_threat_method_def[index].method_name);
		dict_setitem_string_object(dict_tmp, CONFIG_OBJ_TYPE_STRING, PyLong_FromLong(DETECT_CONFIG_OBJ_TYPE_METHOD));

		PyDict_SetItem(g_threat_method_dict,
					   PyUnicode_FromFormat("%s-%s-%s", 
					   						g_threat_method_def[index].module_name,
						  				    g_threat_method_def[index].class_name,
						  				    g_threat_method_def[index].method_name),
					   dict_tmp);
	}

	/* 初始化威胁函数字典 */
	for (index = 0; index < sizeof(g_threat_func_def)/sizeof(DETECT_THREAT_DEF); index++) {
		dict_tmp = PyDict_New();

		detect_config_construct_threat_dict_common_fields(dict_tmp, &g_threat_func_def[index]);
		dict_setitem_string_string(dict_tmp, FUNC_NAME_STRING, g_threat_func_def[index].func_name);
		dict_setitem_string_object(dict_tmp, CONFIG_OBJ_TYPE_STRING, PyLong_FromLong(DETECT_CONFIG_OBJ_TYPE_FUNC));

		PyDict_SetItem(g_threat_func_dict,
					   PyUnicode_FromFormat("%s-%s", 
					   						g_threat_func_def[index].module_name,
						  				    g_threat_func_def[index].func_name),
					   dict_tmp);
	}

	/* 合并三个威胁字典到一个字典中 */
	PyDict_Merge(g_threat_all_dict, g_threat_class_dict, 1);
	PyDict_Merge(g_threat_all_dict, g_threat_method_dict, 1);
	PyDict_Merge(g_threat_all_dict, g_threat_func_dict, 1);

	return ;
}

