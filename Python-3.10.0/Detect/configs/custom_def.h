#ifndef DETECT_CONFIGS_CUSTOM_DEF_H
#define DETECT_CONFIGS_CUSTOM_DEF_H

#include "stdbool.h"
#include "Python.h"
#include "Detect/configs/common.h"

/* 自定义处理函数原型 */
typedef PyObject*(*custom_func)(PyObject *self, PyObject *callable, PyObject *args, PyObject *kwargs);

// 自定义类、方法和函数定义
typedef struct _detect_custom_def {
	const char *module_name;
	const char *class_name;
	const char *method_name;
	const char *func_name;
	custom_func pfunc;
} DETECT_CUSTOM_DEF;

PyObject *g_custom_class_dict;  // 自定义类字典
PyObject *g_custom_method_dict; // 自定义方法字典
PyObject *g_custom_func_dict;   // 自定义函数字典

PyObject *g_custom_all_dict;    // 包含上述四种威胁的集合字典

extern void detect_config_custom_def_init();

#endif

