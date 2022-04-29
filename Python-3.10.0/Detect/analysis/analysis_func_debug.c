/*
 * @Description: 调试用分析函数定义，用于在detect模块的debug模式下输出执行信息
 */

#include "Detect/configs/config.h"
#include "Detect/record/record.h"
#include "Detect/object/object.h"
#include "Detect/analysis/analysis_common.h"
#include "Detect/analysis/analysis_func_debug.h"
#include "Detect/utils/dict.h"

/**
  * @description: 调试用对象输出函数，简化了PyObject_Print，针对没实现__repr__
  *               的对象的输出做了修改
  * @return PyObject*
  */
static void detect_analysis_object_print(PyObject *op, FILE *fp, int flags) {

    clearerr(fp); /* Clear any previous error condition */
    if (op == NULL) {
        Py_BEGIN_ALLOW_THREADS
        fprintf(fp, "<nil>");
        Py_END_ALLOW_THREADS
    }  else {
        PyObject *s;

		/* op是object模块中的对象 */
		if (detect_object_get_object_type(op) < DETECT_OBJECT_TYPE_MAX) {
			s = PyUnicode_FromFormat("<%s object at %p>", Py_TYPE(op)->tp_name, op);
		} else {
			if (flags & Py_PRINT_RAW)
	            s = PyObject_Str(op);
	        else
	            s = PyObject_Repr(op);

			if (PyErr_Occurred()) {
				s = PyUnicode_FromFormat("class %s not implement repr or str", Py_TYPE(op)->tp_name);
			}
		}

        if (s == NULL) {
            ;
        } else if (PyBytes_Check(s)) {
            fwrite(PyBytes_AS_STRING(s), 1, PyBytes_GET_SIZE(s), fp);
        } else if (PyUnicode_Check(s)) {
            PyObject *t;
            t = PyUnicode_AsEncodedString(s, "utf-8", "backslashreplace");
            if (t != NULL) {
                fwrite(PyBytes_AS_STRING(t), 1,
                       PyBytes_GET_SIZE(t), fp);
                Py_DECREF(t);
            }
        } else {
            PyErr_Format(PyExc_TypeError,
                         "str() or repr() returned '%.100s'",
                         Py_TYPE(s)->tp_name);
            
        }

		Py_XDECREF(s);
    }

    return;
}


/**
  * @description: 调试用分析函数定义，用于在detect模块的debug模式下输出执行信息
  * @param PyObject*
  * @return PyObject*
  */
PyObject* detect_analysis_func_debug_proc() {
	DETECT_RECORD_INFO_T *detect_record_info;
	PyObject *param_list;
	DETECT_OBJECT_TYPE hook_obj_type;
	DETECT_CONFIG_OBJ_TYPE config_obj_type;
	PyObject **stack_pointer;
	int opcode, oparg, line_no;
	PyObject *call_info_dict; // 调用信息字典，用于调试输出

	detect_record_info = detect_record_get_record_info();
	if (!detect_record_info->cur_call_info.is_avaliable) {
		return NULL;
	}
	
	opcode          = detect_record_info->cur_call_info.opcode;
	oparg           = detect_record_info->cur_call_info.oparg;
	line_no         = detect_record_info->cur_call_info.line_no;
	stack_pointer   = detect_record_info->cur_call_info.stack_pointer;
	hook_obj_type   = detect_record_info->cur_call_info.callable_info.hook_object_type;
	config_obj_type = detect_record_info->cur_call_info.callable_info.config_object_type;
	param_list      = detect_record_create_params_list(stack_pointer, opcode, oparg);

	/* 填充调试用调用信息字典 */
	call_info_dict = PyDict_New();
	if (detect_record_info->cur_call_info.callable_info.module_name) {
		dict_setitem_string_object(call_info_dict, DEBUG_MODULE_NAME_STRING, 
					detect_record_info->cur_call_info.callable_info.module_name);
	}
	if (detect_record_info->cur_call_info.callable_info.class_name) {
		dict_setitem_string_object(call_info_dict, DEBUG_CLASS_NAME_STRING, 
					detect_record_info->cur_call_info.callable_info.class_name);
	}
	if (detect_record_info->cur_call_info.callable_info.method_name) {
		dict_setitem_string_object(call_info_dict, DEBUG_METHOD_NAME_STRING, 
					detect_record_info->cur_call_info.callable_info.method_name);
	}
	if (detect_record_info->cur_call_info.callable_info.func_name) {
		dict_setitem_string_object(call_info_dict, DEBUG_FUNC_NAME_STRING, 
					detect_record_info->cur_call_info.callable_info.func_name);
	}

	dict_setitem_string_long(call_info_dict,   DEBUG_HOOK_OBJ_TYPE_STRING,   hook_obj_type);
	dict_setitem_string_long(call_info_dict,   DEBUG_CONFIG_OBJ_TYPE_STRING, config_obj_type);
	dict_setitem_string_long(call_info_dict,   DEBUG_OPCODE_STRING,          opcode);
	dict_setitem_string_long(call_info_dict,   DEBUG_OPARG_STRING,           oparg);
	dict_setitem_string_long(call_info_dict,   DEBUG_LINE_NO_STRING,         line_no);
	dict_setitem_string_object(call_info_dict, DEBUG_PARAM_LIST_STRING,      param_list);

	/* 输出调用字典项 */
	PyObject_Print(call_info_dict, stdout, Py_PRINT_RAW);
	fprintf(stdout, "\n");

	/* 某些对象没有实现__repr__会导致异常，因此此处清掉异常 */
	PyErr_Clear();

	fflush(stdout);

	/* 销毁对象 */
	Py_DECREF(param_list);
	Py_DECREF(call_info_dict);

	return NULL;
}

