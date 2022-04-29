#ifndef DETECT_CONFIGS_THREAT_DEF_H
#define DETECT_CONFIGS_THREAT_DEF_H

#include "stdbool.h"
#include "Python.h"
#include "Detect/configs/common.h"

/* 威胁类型定义 */
typedef enum {
	DETECT_THREAT_TYPE_COMMAND_EXEC = 0, // 命令执行
	DETECT_THREAT_TYPE_CODE_EXEC,        // 代码执行
	DETECT_THREAT_TYPE_THREAD_EXEC,      // 线程执行
	DETECT_THREAT_TYPE_MAX
} DETECT_THREAT_TYPE_E;

/* 威胁类、方法和函数定义 */
typedef struct _detect_threat_def {
	const char *module_name;
	const char *class_name;
	const char *method_name;
	const char *func_name;
	int param_pos[MAX_POS];           // 外部输入生效的参数位置
	DETECT_THREAT_TYPE_E threat_type; // 威胁类型
	bool need_execute;                // 是否需要执行原处理逻辑，默认为false，即不执行
} DETECT_THREAT_DEF;

PyObject *g_threat_class_dict;  // 威胁类字典
PyObject *g_threat_method_dict; // 威胁方法字典
PyObject *g_threat_func_dict;   // 威胁函数字典

PyObject *g_threat_all_dict;    // 包含上述四种威胁的集合字典

extern void detect_config_threat_def_init();

#endif

