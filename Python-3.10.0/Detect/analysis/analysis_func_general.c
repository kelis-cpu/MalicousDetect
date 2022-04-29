/*
 * @Description: 通用分析函数定义
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
#include "Detect/utils/list.h"

/**
  * @description: 通用分析函数，当威胁函数的参数为外部输入时即告警
  * @return PyObject*
  */
PyObject* detect_analysis_func_general_proc() {
	DETECT_RECORD_INFO_T *detect_record_info;
	PyObject *param_list;
	DETECT_OBJECT_TYPE hook_obj_type;
	PyObject **stack_pointer;
	int opcode, oparg;
	bool is_malicious = false;

	detect_record_info = detect_record_get_record_info();
	if (!detect_record_info->cur_call_info.is_avaliable) {
		return NULL;
	}
	
	opcode        = detect_record_info->cur_call_info.opcode;
	oparg         = detect_record_info->cur_call_info.oparg;
	stack_pointer = detect_record_info->cur_call_info.stack_pointer;

	/* 判断当前调用项是否为威胁对象调用 */
	hook_obj_type = detect_record_info->cur_call_info.callable_info.hook_object_type;
	if (hook_obj_type != DETECT_OBJECT_TYPE_THREAT) {
		return NULL;
	}

	/* 创建参数list，检查参数是否为外部输入，不同的opcode检查策略不同 */
	param_list = detect_record_create_params_list(stack_pointer, opcode, oparg);
	switch (opcode) {
	case CALL_FUNCTION:
	case CALL_METHOD:
		if (detect_analysis_check_list_taint(param_list)) {
			is_malicious = true;				
		}
		break;
	case CALL_FUNCTION_KW:
		if (detect_analysis_check_list_taint(param_list)) {
			is_malicious = true;
			break;
		}

		/* 检查list最后一项的关键字参数名称的元组是否包括tait对象 */
		if (detect_analysis_check_tuple_taint(list_top(param_list))) {
			is_malicious = true;
		}
		break;
	case CALL_FUNCTION_EX:
		/* 检查位置参数元组 */
		if (detect_analysis_check_tuple_taint(PyList_GetItem(param_list, 1))) {
			is_malicious = true;
			break;
		}

		/* 检查关键字参数字典 */
		if (PyList_Size(param_list) == 2 && 
			detect_analysis_check_dict_taint(PyList_GetItem(param_list, 2))) {
			is_malicious = true;
		}
		break;
	default:
		break;
	}

	/* 销毁参数list，恢复对参数对象的引用计数 */
	Py_DECREF(param_list);

	/* 填充检测结果字典 */
	if (is_malicious) {
		return detect_analysis_create_detect_malicious_result_dict("Taint data reach threat callables");
	}
	
	return NULL;
}

