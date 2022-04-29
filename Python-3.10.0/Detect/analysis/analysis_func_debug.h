#ifndef DETECT_ANALYSIS_FUNC_DEBUG_H
#define DETECT_ANALYSIS_FUNC_DEBUG_H

/* 调试用调用信息字典的key */
#define DEBUG_MODULE_NAME_STRING     "module_name"
#define DEBUG_CLASS_NAME_STRING      "class_name"
#define DEBUG_METHOD_NAME_STRING     "method_name"
#define DEBUG_FUNC_NAME_STRING       "func_name"
#define DEBUG_HOOK_OBJ_TYPE_STRING   "hook_obj_type"
#define DEBUG_CONFIG_OBJ_TYPE_STRING "config_obj_type"
#define DEBUG_PARAM_LIST_STRING      "param_list"
#define DEBUG_OPCODE_STRING          "opcode"
#define DEBUG_OPARG_STRING           "oparg"
#define DEBUG_LINE_NO_STRING         "line_no"


extern PyObject* detect_analysis_func_debug_proc();

#endif

