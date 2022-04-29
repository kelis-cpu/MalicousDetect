/*
 * @Description: 非法操作的分析策略
 */

#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"
#include "import.h"
#include "opcode.h"
#include "Detect/configs/config.h"
#include "Detect/record/record.h"
#include "Detect/object/object.h"
#include "Detect/analysis/analysis_common.h"
#include "Detect/analysis/analysis_func_illegal_ops.h"
#include "Detect/utils/list.h"
#include "Detect/utils/re.h"
#include "Detect/utils/str.h"


DETECT_ANALYSIS_ILLEGAL_OPS_T g_illegal_ops_def[] = {
	{"scapy.all", "sniff"},
	{"wget",      "download"},
};

 /**
   * @description: 非法操作分析函数，检测策略如下：
   *				 1、可调用对象的名字为非法操作列表中的名字;
   * @return PyObject*
   */
PyObject* detect_analysis_func_illegal_ops_proc() {
	DETECT_RECORD_INFO_T *detect_record_info;
	DETECT_RECORD_CALLABLE_INFO_T *callable_info;
	PyObject *callable_name = NULL;
	int index;
	bool is_malicious = false;

	detect_record_info = detect_record_get_record_info();
	if (!detect_record_info->cur_call_info.is_avaliable) {
		return NULL;
	}
 
	callable_info = &detect_record_info->cur_call_info.callable_info;
	if (callable_info->class_name != NULL) {
		callable_name = callable_info->class_name;
	} else if (callable_info->method_name != NULL) {
		callable_name = callable_info->method_name;
	} else if (callable_info->func_name != NULL) {
		callable_name = callable_info->func_name;
	}

	for (index = 0; index < sizeof(g_illegal_ops_def)/sizeof(DETECT_ANALYSIS_ILLEGAL_OPS_T); index++) {
		/* 比较模块名 */
		if (PyUnicode_CompareWithASCIIString(callable_info->module_name, g_illegal_ops_def[index].module_name) != 0) {
			continue;
		}

		/* 比较可调用对象名 */
		if (callable_name != NULL &&
			PyUnicode_CompareWithASCIIString(callable_name, g_illegal_ops_def[index].callable_name) == 0) {
			is_malicious = true;
			break;
		}
			
	}

	if (is_malicious) {
		return detect_analysis_create_detect_malicious_result_dict("Illegal Operations");
	}
	 
	return NULL;
 }

