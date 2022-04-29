/*
 * @Description: 执行信息分析模块公共文件
 */

#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"
#include "pycore_tuple.h"
#include "import.h"
#include "opcode.h"
#include "Detect/configs/config.h"
#include "Detect/object/object.h"
#include "Detect/analysis/analysis_common.h"
#include "Detect/utils/dict.h"
#include "Detect/utils/re.h"

/**
  * @description: 向结果字典添加调试信息，用于debug模式下
  * @return PyObject*
  */
static void detect_analysis_result_dict_add_debug_info(PyObject *result_dict) {
	/* 添加当前检测是否跳过了所有分支 */
	if (detect_config_get_runtime_is_jump_branch()) {	
		dict_setitem_string_object(result_dict, JUMP_BRANCH_STRING, Py_True);
	} else {
		dict_setitem_string_object(result_dict, JUMP_BRANCH_STRING, Py_False);
	}

	return;
}

/**
  * @description: 生成一个检测为恶意的检测结果字典
  * @param desc 恶意描述
  * @return PyObject*
  */
PyObject* detect_analysis_create_detect_malicious_result_dict(const char *desc) {
	wchar_t  *run_filename;
	PyObject *run_filename_obj;
	PyObject *is_webshell_obj;
	PyObject *result_dict = PyDict_New();

	run_filename     = _Py_GetConfig()->run_filename;
	run_filename_obj = PyUnicode_FromWideChar(run_filename, wcslen(run_filename));

	is_webshell_obj = Py_True;

	dict_setitem_string_object(result_dict, FILENAME_STRING,  run_filename_obj);
	dict_setitem_string_object(result_dict, MALICIOUS_STRING, is_webshell_obj);
	dict_setitem_string_string(result_dict, DESC_STRING, desc);

	if (detect_config_get_runtime_is_debug()) {
		detect_analysis_result_dict_add_debug_info(result_dict);
	}

	return result_dict;
}


/**
  * @description: 生成一个检测无异常的检测结果字典
  * @return PyObject*
  */
PyObject* detect_analysis_create_detect_ok_result_dict(const char *desc) {
	wchar_t  *run_filename;
	PyObject *run_filename_obj;
	PyObject *is_webshell_obj;
	PyObject *result_dict = PyDict_New();

	run_filename     = _Py_GetConfig()->run_filename;
	run_filename_obj = PyUnicode_FromWideChar(run_filename, wcslen(run_filename));

	is_webshell_obj = Py_False;

	dict_setitem_string_object(result_dict, FILENAME_STRING,  run_filename_obj);
	dict_setitem_string_object(result_dict, MALICIOUS_STRING, is_webshell_obj);

	if (detect_config_get_runtime_is_debug()) {
		detect_analysis_result_dict_add_debug_info(result_dict);

		if (desc != NULL) {
			dict_setitem_string_string(result_dict, DESC_STRING, desc);
		}
	}
	
	return result_dict;
}

/**
  * @description: 获取可调用对象的参数列表,将参数信息都放在一个新list中
  * @param stack_pointer 栈顶指针
  * @param opcode
  * @param oparg
  * @return PyObject* 参数列表
  */
PyObject* detect_record_create_params_list(PyObject **stack_pointer, int opcode, int oparg) {
	PyObject *args_list;
	int i;

	args_list = PyList_New(0);
	if (opcode == CALL_FUNCTION_KW) {
		/* 位置参数 */
		for ( i = 0; i < oparg; i++) {
			PyList_Append(args_list, stack_pointer[i - oparg - 1]);
		}

		/* 栈顶为关键字参数名称的元组，也将其作为参数添加到参数列表 */
		PyList_Append(args_list, stack_pointer[-1]);
	} else if (opcode == CALL_METHOD || opcode == CALL_FUNCTION) {
		/* 这两个opcode只有位置参数 */
		for (i = 0; i < oparg; i++) {
			PyList_Append(args_list, stack_pointer[i - oparg]);
		}
	} else if (opcode == CALL_FUNCTION_EX) {
		PyObject *args_tuple, *kwargs_dict =NULL;

		if (oparg & 0x01) {
			args_tuple = stack_pointer[-2];
			kwargs_dict = stack_pointer[-1];
		} else {
			args_tuple = stack_pointer[-1];
		}

		/* 位置参数组成的元组 */
		if (PyTuple_CheckExact(args_tuple)) {
			PyList_Append(args_list, args_tuple);
		}

		/* 关键字参数组成的字典 */
		if (kwargs_dict && PyDict_CheckExact(kwargs_dict)) {
			PyObject *d = PyDict_New();
			_PyDict_MergeEx(d, kwargs_dict, 2);
			kwargs_dict = d;
			PyList_Append(args_list, kwargs_dict);
		}
	}

	return args_list;
}

/**
  * @description: 检查给定列表中是否包括taint的对象，不递归检查
  * @param list_obj 列表对象
  * @return bool
  */
bool detect_analysis_check_list_taint(PyObject *list_obj) {
	PyObject *item_obj;
	int index;

	for (index = 0; index < PyList_Size(list_obj); index++) {
		item_obj = PyList_GetItem(list_obj, index);
		if (detect_object_object_is_taint(item_obj)) {
			return true;
		}
	}

	return false;
}

/**
  * @description: 检查给定元组中是否包括taint的对象，不递归检查
  * @param tuple_obj 元组对象
  * @return bool
  */
bool detect_analysis_check_tuple_taint(PyObject *tuple_obj) {
	PyObject *item_obj;
	int index;

	for (index = 0; index < PyTuple_Size(tuple_obj); index++) {
		item_obj = PyTuple_GetItem(tuple_obj, index);
		if (detect_object_object_is_taint(item_obj)) {
			return true;
		}
	}

	return false;
}

/**
  * @description: 检查给定字典中是否包括taint的对象，不递归检查
  * @param dict_obj 字典对象
  * @return bool
  */
bool detect_analysis_check_dict_taint(PyObject *dict_obj) {
	Py_ssize_t i = 0;
	PyObject *key, *value;

	while (PyDict_Next(dict_obj, &i, &key, &value)) {
		if (detect_object_object_is_taint(key) ) {
			return true;
		}

		if (detect_object_object_is_taint(value) ) {
			return true;
		}
	}

	return false;
}

/**
  * @description: 用于在CALL_FUNCTION_EX opcode时根据栈上的位置参数元组和关键字
  *               参数字典创建新的args数组和kwnames元组，copy from call.c:_PyStack_UnpackDict
  * @param args 栈上参数的起始位置
  * @param nargs 位置参数数量
  * @param kwargs 关键字参数字典
  * @param *nargs 待获取的位置参数的数量
  * @param **kwnames 新创建的关键字参数名称元组
  * @return PyObject*const* 新创建的参数数组
  */
static PyObject*const* detect_analysis_create_args_and_kwnames(PyObject *const *args, Py_ssize_t nargs,
                    										PyObject *kwargs, PyObject **p_kwnames) {
    assert(nargs >= 0);
    assert(kwargs != NULL);
    assert(PyDict_Check(kwargs));

    Py_ssize_t nkwargs = PyDict_GET_SIZE(kwargs);
    /* Check for overflow in the PyMem_Malloc() call below. The subtraction
     * in this check cannot overflow: both maxnargs and nkwargs are
     * non-negative signed integers, so their difference fits in the type. */
    Py_ssize_t maxnargs = PY_SSIZE_T_MAX / sizeof(args[0]) - 1;
    if (nargs > maxnargs - nkwargs) {
        return NULL;
    }

    /* Add 1 to support PY_VECTORCALL_ARGUMENTS_OFFSET */
    PyObject **stack = PyMem_Malloc((1 + nargs + nkwargs) * sizeof(args[0]));
    if (stack == NULL) {
        return NULL;
    }

    PyObject *kwnames = PyTuple_New(nkwargs);
    if (kwnames == NULL) {
        PyMem_Free(stack);
        return NULL;
    }

    stack++;  /* For PY_VECTORCALL_ARGUMENTS_OFFSET */

    /* Copy positional arguments */
    for (Py_ssize_t i = 0; i < nargs; i++) {
        Py_INCREF(args[i]);
        stack[i] = args[i];
    }

    PyObject **kwstack = stack + nargs;
    /* This loop doesn't support lookup function mutating the dictionary
       to change its size. It's a deliberate choice for speed, this function is
       called in the performance critical hot code. */
    Py_ssize_t pos = 0, i = 0;
    PyObject *key, *value;
    unsigned long keys_are_strings = Py_TPFLAGS_UNICODE_SUBCLASS;
    while (PyDict_Next(kwargs, &pos, &key, &value)) {
        keys_are_strings &= Py_TYPE(key)->tp_flags;
        Py_INCREF(key);
        Py_INCREF(value);
        PyTuple_SET_ITEM(kwnames, i, key);
        kwstack[i] = value;
        i++;
    }

    /* keys_are_strings has the value Py_TPFLAGS_UNICODE_SUBCLASS if that
     * flag is set for all keys. Otherwise, keys_are_strings equals 0.
     * We do this check once at the end instead of inside the loop above
     * because it simplifies the deallocation in the failing case.
     * It happens to also make the loop above slightly more efficient. */
    if (!keys_are_strings) {
        return NULL;
    }

    *p_kwnames = kwnames;
    return stack;
}

/**
  * @description: 用于在CALL_FUNCTION_EX opcode释放新创建的args数组和kwnames元组，
  *               copy from call.c:_PyStack_UnpackDict_Free
  * @param stack 新创建的参数数组
  * @param nargs 位置参数数量
  * @param kwnames 新创建的关键字参数名称元组
  * @return void
  */
void detect_analysis_free_args_and_kwnames(PyObject *const *stack, Py_ssize_t nargs,
                         PyObject *kwnames)
{
    Py_ssize_t n = PyTuple_GET_SIZE(kwnames) + nargs;
    for (Py_ssize_t i = 0; i < n; i++) {
        Py_DECREF(stack[i]);
    }
    PyMem_Free((PyObject **)stack - 1);
    Py_DECREF(kwnames);
}


/**
  * @description: 获取可调用对象的原始参数形式，用来更准确地获取某个参数的值
  * @param stack_pointer 栈顶指针
  * @param opcode
  * @param oparg
  * @param *nargs 待获取的位置参数的数量
  * @param **kwnames 待获取的关键字参数名称的元组
  * @param *need_free 是否需要释放参数数组和关键字参数名称元组
  * @return PyObject*const* 参数在stack上的起始位置
  */
PyObject*const* detect_analysis_get_call_original_params(PyObject **stack_pointer, 
														int opcode, 
														int oparg, 
														Py_ssize_t *nargs, 
														PyObject **kwnames,
														bool *need_free) {
	PyObject *const *args = NULL;

	/* 获取参数 */
	switch(opcode) {
	case CALL_FUNCTION:
		*nargs = oparg;
		args  = stack_pointer - *nargs;
		*kwnames = NULL;
		break;
	case CALL_METHOD:
	{
		PyObject *meth;
        meth = stack_pointer[-(oparg + 2)];
		if (meth == NULL) {
			*nargs = oparg;
		} else {
			*nargs = oparg + 1;
		}
		args  = stack_pointer - *nargs;
		*kwnames = NULL;
		break;
	}
	case CALL_FUNCTION_KW:
		*kwnames = stack_pointer[-1];
		*nargs = oparg - PyTuple_GET_SIZE(*kwnames);
		args = stack_pointer - *nargs - PyTuple_GET_SIZE(*kwnames);
		break;
	case CALL_FUNCTION_EX:
	{
		PyObject *args_tuple, *kwargs_dict =NULL;

		if (oparg & 0x01) {
			args_tuple = stack_pointer[-2];
			kwargs_dict = stack_pointer[-1];
		} else {
			args_tuple = stack_pointer[-1];
		}

		*nargs = PyTuple_GET_SIZE(args_tuple);
		if (kwargs_dict == NULL || PyDict_GET_SIZE(kwargs_dict) == 0) {
			args = _PyTuple_ITEMS(args_tuple);
			*kwnames = NULL;
		} else {
			/* 申请内存存放所有参数和关键字参数名称元组 */
    		args = detect_analysis_create_args_and_kwnames(_PyTuple_ITEMS(args_tuple), *nargs, kwargs_dict, kwnames);
			*need_free = true;
		}
		break;
	}
	}

	return args;
}

/**
  * @description: 正则表达式search实现
  * @param pattern 模式字符串
  * @param string 主串对象
  * @param flags
  * @return PyObject*
  */
PyObject* detect_analysis_re_search(const char *pattern, PyObject *string, int flags) {
	PyObject *searches;

	/* re search使用了re库，为python层代码，为了不影响其执行，暂时关闭detect模块 */
	detect_config_set_runtime_is_enable(false);

	searches = re_search(pattern, string, flags);

	detect_config_set_runtime_is_enable(true);

	return searches;
}

