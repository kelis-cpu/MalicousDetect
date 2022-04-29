/*
 * @Description: 恶意命令执行的分析策略
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
#include "Detect/utils/re.h"
#include "Detect/utils/str.h"

const char *g_malicious_commands_str[] = {
	"reg add", "reg delete", "pyinstaller"
};

PyObject *g_malicious_commands_list;

/**
  * @description: 恶意命令执行分析初始化
  * @return PyObject*
  */
void detect_analysis_func_malicious_command_init() {
	int index;

	if (g_malicious_commands_list != NULL) {
		return;
	}

	g_malicious_commands_list = PyList_New(0);
	for (index = 0; index < sizeof(g_malicious_commands_str)/sizeof(const char*); index++) {
		PyList_Append(g_malicious_commands_list, PyUnicode_FromString(g_malicious_commands_str[index]));
	}
}

/**
  * @description: 检查unicode对象中所包含的参数是否包含恶意命令
  * @return PyObject* 恶意命令
  */
static bool malicious_command_check_executed_command_by_unicode(PyObject *unicode_obj) {
	int index;
	PyObject *searches;

	for (index = 0; index < sizeof(g_malicious_commands_str)/sizeof(const char*); index++) {
		searches = detect_analysis_re_search((g_malicious_commands_str)[index], unicode_obj, 0);
		if (searches && searches != Py_None) {
			return true;
		}
	}
	
	return false;
}

/**
  * @description: 检查list中所包含的参数是否包含恶意命令
  * @return PyObject*
  */
static bool malicious_command_check_executed_command_by_list(PyObject *list_obj) {
	int index;
	PyObject *searches;
	PyObject *command_obj;

	/* 将列表中分割的命令拼接起来 */
	command_obj = PyUnicode_Join(PyUnicode_FromString(" "), list_obj);
	
	for (index = 0; index < sizeof(g_malicious_commands_str)/sizeof(const char*); index++) {
		searches = detect_analysis_re_search(g_malicious_commands_str[index], command_obj, 0);
		if (searches && searches != Py_None) {
			return true;
		}
	}
	
	return false;
}

/**
  * @description: 检查当前调用参数是否存在恶意命令
  * @return PyObject*
  */
static bool malicious_command_check_executed_command(DETECT_RECORD_CALL_INFO_T *call_info) {
	PyObject *const *args; Py_ssize_t nargs; PyObject *kwnames; bool need_free = false;
	int opcode, oparg;
	PyObject **statck_pointer;
	int param_count, index;
	bool has_malicious_command = false;

	opcode         = call_info->opcode;
	oparg          = call_info->oparg;
	statck_pointer = call_info->stack_pointer;

	args = detect_analysis_get_call_original_params(statck_pointer, opcode, oparg, &nargs, &kwnames, &need_free);

	/* 计算所有参数的数量 */
	param_count = nargs;
	if (kwnames) {
		param_count += PyTuple_Size(kwnames);
	}

	/* 遍历所有参数进行检查 */
	for (index = 0; index < param_count; index++) {
		if (PyUnicode_Check(args[index])) {
			has_malicious_command = malicious_command_check_executed_command_by_unicode(args[index]);
		} else if (PyList_Check(args[index])) {
			has_malicious_command = malicious_command_check_executed_command_by_list(args[index]);
		}
	}

	if (need_free) {
		detect_analysis_free_args_and_kwnames(args, nargs, kwnames);
	}

	return has_malicious_command;
}

/**
  * @description: 恶意命令执行分析函数，检测策略如下：
  *               	1、定位命令执行类的可调用对象；
  *                 2、判断参数是否为预定义的恶意命令
  * @return PyObject*
  */
PyObject* detect_analysis_func_malicious_command_proc() {
	DETECT_RECORD_INFO_T *detect_record_info;
	DETECT_OBJECT_TYPE hook_obj_type;
	DETECT_THREAT_TYPE_E threat_type;
	bool is_malicious = false;

	detect_record_info = detect_record_get_record_info();
	if (!detect_record_info->cur_call_info.is_avaliable) {
		return NULL;
	}

	/* 初始化 */
	detect_analysis_func_malicious_command_init();

	/* 判断当前调用项是否为威胁且命令执行对象调用 */
	hook_obj_type = detect_record_info->cur_call_info.callable_info.hook_object_type;
	threat_type   = detect_record_info->cur_call_info.callable_info.threat_type;
	if (hook_obj_type != DETECT_OBJECT_TYPE_THREAT || 
		threat_type != DETECT_THREAT_TYPE_COMMAND_EXEC) {
		return NULL;
	}

	/* 检查命令执行函数的参数是否符合反弹特征 */
	is_malicious = malicious_command_check_executed_command(&detect_record_info->cur_call_info);

	if (is_malicious) {
		return detect_analysis_create_detect_malicious_result_dict("Execute Malicious Command");
	}
	
	return NULL;
}


