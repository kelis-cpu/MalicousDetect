#ifndef DETECT_ANALYSIS_COMMON_H
#define DETECT_ANALYSIS_COMMON_H

#include "Python.h"
#include "pycore_interp.h"
#include "frameobject.h"

/* 分析函数原型 */
typedef PyObject*(*analysis_func)();

/* 检测结果字典的key */
#define FILENAME_STRING      "FileName"
#define MALICIOUS_STRING     "IsMalicious"
#define DESC_STRING          "Desc"
#define FUNCTION_NAME_STRING "FunctionName"
#define ARGUMENTS_STRING     "Arguments"
#define JUMP_BRANCH_STRING   "IsJumpBranch"

extern PyObject* detect_analysis_create_detect_malicious_result_dict(const char *desc);
extern PyObject* detect_analysis_create_detect_ok_result_dict(const char *desc);
extern PyObject* detect_record_create_params_list(PyObject **stack_pointer, int opcode, int oparg);
extern bool detect_analysis_check_list_taint(PyObject *list_obj);
extern bool detect_analysis_check_tuple_taint(PyObject *list_obj);
extern bool detect_analysis_check_dict_taint(PyObject *dict_obj);
extern PyObject*const* detect_analysis_get_call_original_params(PyObject **stack_pointer, 
														int opcode, 
														int oparg, 
														Py_ssize_t *nargs, 
														PyObject **kwnames,
														bool *need_free);
extern void detect_analysis_free_args_and_kwnames(PyObject *const *stack, Py_ssize_t nargs,
                         PyObject *kwnames);
extern PyObject* detect_analysis_re_search(const char *pattern, PyObject *string, int flags);

#endif


