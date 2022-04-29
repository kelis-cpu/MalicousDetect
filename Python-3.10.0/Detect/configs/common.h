#ifndef DETECT_CONFIGS_COMMON_H
#define DETECT_CONFIGS_COMMON_H

#include "Python.h"

/* 参数的最大数量 */
#define MAX_POS 10

/* 配置中对象的类型 */
typedef enum {
	DETECT_CONFIG_OBJ_TYPE_CLASS = 0,
	DETECT_CONFIG_OBJ_TYPE_METHOD,
	DETECT_CONFIG_OBJ_TYPE_FUNC,
	DETECT_CONFIG_OBJ_TYPE_VAR,
	DETECT_CONFIG_OBJ_TYPE_MAX
} DETECT_CONFIG_OBJ_TYPE; 

/* 常用字典key字符串定义 */
#define MODULE_NAME_STRING         "module_name"     // 模块名
#define CLASS_NAME_STRING          "class_name"      // 类名
#define METHOD_NAME_STRING         "method_name"     // 方法名
#define FUNC_NAME_STRING           "func_name"       // 函数名
#define VAR_NAME_STRING            "var_name"        // 变量名
#define TAINT_POS_STRING           "taint_pos"       // 外部输入位置
#define PARAM_POS_STRING           "param_pos"       // 威胁参数位置
#define THREAT_TYPE_STRING         "threat_type"     // 威胁类型，值为DETECT_THREAT_TYPE_E
#define NEED_EXECUTE_STRING        "need_execute"    // 是否需要执行原处理逻辑
#define HOOK_OBJECT_STRING         "hook_object"     // 外部输入和威胁对象需要被hook的对象
#define CONFIG_DICT_STRING         "config_dict"     // 配置字典
#define CONFIG_OBJ_TYPE_STRING     "config_obj_type" // 配置中对象的类型，值为DETECT_CONFIG_OBJ_TYPE
#define HOOK_OBJ_TYPE_STRING       "hook_obj_type"   // hook对象的类型，值为DETECT_OBJECT_TYPE
#define CUSTOM_FUNC_STRING         "custom_func"     // 自定义逻辑处理函数
#define ORIGINAL_HOOKED_OBJ_STRING "original_hooked_object" // 原始被hook的对象

#define CALLABLE_TYPE_STRING	   "callable_type"   // 可调用对象的类型
#define CALLABLE_OPCODE_STRING	   "callable_opcode" // 可调用对象被调用时的opcode
#define LINE_NO_STRING             "line_no"         // 行号
#define PARAM_LIST_STRING          "param_list"      // 参数列表
#define SEARCH_KEY_STRING          "search_key"      // 用于在配置字典或其他字典中快速搜索

extern PyObject *detect_config_create_pos_list(int *taint_pos, int len);

#endif

