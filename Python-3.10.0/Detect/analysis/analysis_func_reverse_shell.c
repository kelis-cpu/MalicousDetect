/*
 * @Description: 反弹恶意脚本分析函数定义
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

static bool g_dup_0           = false; // 是否复制了描述符0 
static bool g_dup_1           = false; // 是否复制了描述符1
static int  g_dup_taint_count = 0;     // fd2为外部输入时复制的次数

static bool g_command_contain_sh = false; // 执行的命令是否包含sh
static bool g_command_malicious  = false; // 命令本身是否就是恶意的
	
/**
  * @description: 检查os.dup2的参数是否符合反弹的特征
  * @return bool
  */
static void reverse_shell_check_os_dup2_params(DETECT_RECORD_CALL_INFO_T *call_info) {
	PyObject *const *args; Py_ssize_t nargs; PyObject *kwnames; bool need_free = false;
	int opcode, oparg;
	PyObject **statck_pointer;

	/* os.dup2参数校验相关参数 */
	static const char * const _keywords[] = {"fd", "fd2", "inheritable", NULL};
    static _PyArg_Parser _parser = {NULL, _keywords, "dup2", 0};
    PyObject *argsbuf[3];
	int fd2;

	opcode         = call_info->opcode;
	oparg          = call_info->oparg;
	statck_pointer = call_info->stack_pointer;

	args = detect_analysis_get_call_original_params(statck_pointer, opcode, oparg, &nargs, &kwnames, &need_free);
	if (args == NULL) {
		return;
	}

    args = _PyArg_UnpackKeywords(args, nargs, NULL, kwnames, &_parser, 2, 3, 0, argsbuf);
    if (args == NULL) {
		return;
	}

	/* fd不是外部输入 */
	if (!detect_object_object_is_taint(args[0])) {
		return;
	}

	/* fd2不是外部输入*/
	if (!detect_object_object_is_taint(args[1])) {
		/* fd2不是整数 */
		if (!PyLong_Check(args[1])) {
			return;
		}

		/* fd2 */
		fd2 = _PyLong_AsInt(args[1]);
		if (fd2 == 0) {
			g_dup_0 = true;
		} else if (fd2 == 1) {
			g_dup_1 = true;
		}
	} else {
		g_dup_taint_count++;
	}
	
	if (need_free) {
		detect_analysis_free_args_and_kwnames(args, nargs, kwnames);
	}

	return;
}

/**
  * @description: 检查unicode对象中所包含的参数是否符合反弹命令的特点
  * @return PyObject*
  */
static void reverse_shell_check_executed_command_by_unicode(PyObject *unicode_obj) {
	PyObject *searches;

	/* 匹配sh */
	searches = detect_analysis_re_search("sh", unicode_obj, 0);
	if (searches && searches != Py_None) {
		g_command_contain_sh = true;
		Py_DECREF(searches);
	}

	/* 匹配sh -i   /dev/tcp/xxx */
	searches = detect_analysis_re_search("sh.*/dev/tcp/.*", unicode_obj, 0);
	if (searches && searches != Py_None) {
		g_command_malicious = true;
		Py_DECREF(searches);
	}
}

/**
  * @description: 检查list中所包含的参数是否符合反弹命令的特点
  * @return PyObject*
  */
static void reverse_shell_check_executed_command_by_list(PyObject *list_obj) {
	int index;
	PyObject *searches, *item;
	bool contain_sh = false, contain_devtcp = false;

	for (index = 0; index < PyList_Size(list_obj); index++) {
		item = PyList_GetItem(list_obj, index);
		if (!PyUnicode_Check(item)) {
			continue;
		}

		/* 匹配sh */
		searches = detect_analysis_re_search("sh", item, 0);
		if (searches != NULL) {
			contain_sh = true;
			Py_DECREF(searches);
			break;
		}

		/* 匹配/dev/tcp/ */
		searches = detect_analysis_re_search("/dev/tcp/", item, 0);
		if (searches != NULL) {
			contain_devtcp = true;
			Py_DECREF(searches);
			return;
		}
	}

	if (contain_sh) {
		g_command_contain_sh = true;

		if (contain_devtcp) {
			g_command_malicious = true;
		}
	}

	return;
}

/**
  * @description: 检查当前调用是否符合反弹命令的特点
  * @return PyObject*
  */
static void reverse_shell_check_executed_command(DETECT_RECORD_CALL_INFO_T *call_info) {
	PyObject *const *args; Py_ssize_t nargs; PyObject *kwnames; bool need_free = false;
	int opcode, oparg;
	PyObject **statck_pointer;
	int param_count, index;

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
			reverse_shell_check_executed_command_by_unicode(args[index]);
		} else if (PyList_Check(args[index])) {
			reverse_shell_check_executed_command_by_list(args[index]);
		}
	}

	if (need_free) {
		detect_analysis_free_args_and_kwnames(args, nargs, kwnames);
	}

	return;
}

/**
  * @description: 反弹恶意脚本分析函数，检测策略如下：
  *               	1、定位命令执行类的可调用对象；
  *                 2、判断参数是否为bash -i；
  *                 3、第二步ok则遍历执行流是否有os.dup2(taint_obj, [0,1,2])；
  *                 4、上述三个条件都符合则可以输出告警；
  * @return PyObject*
  */
PyObject* detect_analysis_func_reverse_shell_proc() {
	DETECT_RECORD_INFO_T *detect_record_info;
	DETECT_OBJECT_TYPE hook_obj_type;
	DETECT_THREAT_TYPE_E threat_type;
	bool is_malicious = false;

	detect_record_info = detect_record_get_record_info();
	if (!detect_record_info->cur_call_info.is_avaliable) {
		return NULL;
	}

	/* 检查os.dup2的参数是否符合反弹特征 */
	/* 首先判断是否为os.dup2调用 */
	if (str_compare_unicode_object_with_string(detect_record_info->cur_call_info.callable_info.module_name, "os") &&
		str_compare_unicode_object_with_string(detect_record_info->cur_call_info.callable_info.func_name, "dup2")) {

		reverse_shell_check_os_dup2_params(&detect_record_info->cur_call_info);
		return NULL;
	}

	/* 判断当前调用项是否为威胁且命令执行对象调用 */
	hook_obj_type = detect_record_info->cur_call_info.callable_info.hook_object_type;
	threat_type   = detect_record_info->cur_call_info.callable_info.threat_type;
	if (hook_obj_type != DETECT_OBJECT_TYPE_THREAT || 
		threat_type != DETECT_THREAT_TYPE_COMMAND_EXEC) {
		return NULL;
	}

	/* 检查命令执行函数的参数是否符合反弹特征 */
	reverse_shell_check_executed_command(&detect_record_info->cur_call_info);

	/* 判断脚本是否为反弹shell */
	if (g_command_contain_sh) {
		if (g_dup_taint_count >= 2) {
			is_malicious = true;
		} else if (g_dup_taint_count == 1) {
			if (g_dup_0 || g_dup_1) {
				is_malicious = true;
			}
		} else if (g_dup_taint_count == 0) {
			if (g_dup_0 && g_dup_1) {
				is_malicious = true;
			}
		}
	}
	if (g_command_malicious) {
		is_malicious = true;
	}

	if (is_malicious) {
		return detect_analysis_create_detect_malicious_result_dict("Rverse shell");
	}
	
	return NULL;
}

