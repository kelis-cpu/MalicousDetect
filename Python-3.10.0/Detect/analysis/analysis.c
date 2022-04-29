/*
 * @Description: 执行信息分析模块主文件
 */

#include <stdbool.h>
#include "Detect/configs/config.h"
#include "Detect/analysis/analysis_common.h"
#include "Detect/analysis/analysis_func_debug.h"
#include "Detect/analysis/analysis_func_general.h"
#include "Detect/analysis/analysis_func_reverse_shell.h"
#include "Detect/analysis/analysis_func_malicious_command.h"
#include "Detect/analysis/analysis_func_illegal_ops.h"

/* 分析函数列表 */
static PyObject *detect_analysis_func_list;

/**
  * @description: 分析模块处理函数，每个opcode执行前触发
  * @return void
  */
void detect_analysis_main_proc() {
	int index;
	DETECT_RUN_STATE last_run_state;
	PyObject *result_dict = NULL;

	last_run_state = detect_config_get_runtime_state();

	/* 更新运行状态 */
	detect_config_set_runtime_state(RUN_STATE_ANALYSING);

	for (index = 0; index < PyList_Size(detect_analysis_func_list); index++) {
		analysis_func f = PyLong_AsVoidPtr(PyList_GetItem(detect_analysis_func_list, index));
		result_dict = f();

		if (result_dict != NULL) {
			/* 该检测函数检测出恶意，停止后续检测 */
			break;
		}
	}

	/* 恢复运行状态 */
	detect_config_set_runtime_state(last_run_state);

	/* 检测出恶意 */
	if (result_dict != NULL) {
		/* 输出检测结果到标准输出 */
		PyObject_Print(result_dict, stdout, Py_PRINT_RAW);
		fprintf(stdout, "\n");
	    fflush(stdout);

		/* 退出后续检测 */
		exit(0);
	}

	return;
}

/**
  * @description: 分析模块初始化函数
  * @return void
  */
void detect_analysis_init() {
	static bool has_init = false;

	if (has_init) {
		return;
	}

	detect_analysis_func_list = PyList_New(0);

	/* 注册debug处理函数 */
	if (detect_config_get_runtime_is_debug()) {	
		PyList_Append(detect_analysis_func_list, PyLong_FromVoidPtr(detect_analysis_func_debug_proc));
	}

	/* 注册各分析函数 */
	PyList_Append(detect_analysis_func_list, PyLong_FromVoidPtr(detect_analysis_func_general_proc));
	PyList_Append(detect_analysis_func_list, PyLong_FromVoidPtr(detect_analysis_func_reverse_shell_proc));
	PyList_Append(detect_analysis_func_list, PyLong_FromVoidPtr(detect_analysis_func_malicious_command_proc));
	PyList_Append(detect_analysis_func_list, PyLong_FromVoidPtr(detect_analysis_func_illegal_ops_proc));

	has_init = true;
}

