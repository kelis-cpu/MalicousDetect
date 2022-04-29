#ifndef DETECT_CONFIGS_TAINT_INPUT_DEF_H
#define DETECT_CONFIGS_TAINT_INPUT_DEF_H

#include "Python.h"
#include "Detect/configs/common.h"

/* 外部输入配置定义 */
typedef struct _detect_taint_input {
	const char *module_name;
	const char *class_name;
	const char *method_name;
	const char *func_name;
	const char *var_name;
	int taint_pos[MAX_POS]; // 返回的外部输入的位置: 0 --- 返回值，1 --- 第一个参数，...
} DETECT_TAINT_INPUT;

extern PyObject *g_taint_input_class_dict;  // 外部输入类字典
extern PyObject *g_taint_input_method_dict; // 外部输入方法字典
extern PyObject *g_taint_input_func_dict;   // 外部输入函数字典
extern PyObject *g_taint_input_var_dict;    // 外部输入变量字典
extern PyObject *g_taint_input_all_dict;    // 包含上述四种外部输入的集合字典

extern void detect_config_taint_input_def_init();

#endif

