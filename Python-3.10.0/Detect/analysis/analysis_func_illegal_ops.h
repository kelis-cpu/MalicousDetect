#ifndef DETECT_ANALYSIS_FUNC_ILLEGAL_OPS_H
#define DETECT_ANALYSIS_FUNC_ILLEGAL_OPS_H

/* 非法操作定义 */
typedef struct {
	const char *module_name;
	const char *callable_name;
} DETECT_ANALYSIS_ILLEGAL_OPS_T;

extern PyObject* detect_analysis_func_illegal_ops_proc();

#endif

