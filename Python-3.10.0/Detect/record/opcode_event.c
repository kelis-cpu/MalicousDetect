/*
 * @Description: opcode事件处理
 */

#include "opcode.h"
#include "Python.h"
#include "frameobject.h"
#include "methodobject.h"
#include "Detect/utils/callable.h"
#include "Detect/configs/config.h"
#include "Detect/object/object.h"
#include "Detect/record/opcode_event.h"
#include "Detect/utils/str.h"


static DETECT_RECORD_INFO_T detect_record_info;

/**
  * @description: 获取可调用对象
  * @param stack_pointer 栈顶指针
  * @param opcode
  * @param oparg
  * @return PyObject* 可调用对象
  */
static PyObject* detect_record_get_callable(PyObject **stack_pointer, int opcode, int oparg) {
	PyObject *callable = NULL;

	if (opcode == CALL_FUNCTION) {
		callable = *(stack_pointer - oparg - 1);
	} else if (opcode == CALL_FUNCTION_KW) {
		/* 栈顶是关键字参数名称元组 */
		callable = *(stack_pointer - oparg - 1 - 1);
	} else if (opcode == CALL_FUNCTION_EX) {
		if (oparg & 0x01) {
			/* 存在额外关键字参数 */
			callable = *(stack_pointer -3);
		} else {
			callable = *(stack_pointer -2);
		}
	} else if (opcode == CALL_METHOD) {
		PyObject *meth;

    	meth = *(stack_pointer - oparg - 2);
    	if (meth == NULL) {
        	/* 绑定方法 */
			callable = *(stack_pointer - oparg - 1);
    	} else {
        	/* 未绑定方法 */
			callable = *(stack_pointer - oparg - 2);
    	}
	}

	return callable;
}

/**
  * @description: 填充可调用对象的基本信息
  * @param callable_info 可调用对象信息结构
  * @param callable 可调用对象
  * @param callable_type 可调用对象的类型
  * @return int 成功或失败
  */
static int detect_record_fill_callable_info(DETECT_RECORD_CALLABLE_INFO_T *callable_info,
												  PyObject *callable,
												  CALLABLE_TYPE_E callable_type) {
	DETECT_OBJECT_TYPE     hook_object_type   = DETECT_OBJECT_TYPE_MAX;     // 对象的hook类型
	DETECT_CONFIG_OBJ_TYPE config_object_type = DETECT_CONFIG_OBJ_TYPE_MAX; // 对象的配置类型
	DETECT_THREAT_TYPE_E threat_type          = DETECT_THREAT_TYPE_MAX;
	PyObject *module_name = NULL, *class_name = NULL, *method_name = NULL, *func_name = NULL, *threat_type_obj = NULL;
	bool need_copy = false; // 是否需要复制各个信息对象

	switch (callable_type) {
	case CALLABLE_CFUNCTION_TYPE:
	case CALLABLE_CMETHOD_TYPE:
		module_name = callable_cfunc_get_module_name(callable);
		func_name = PyUnicode_FromString(((PyCFunctionObject *)callable)->m_ml->ml_name);
		need_copy = false;
		break;
	case CALLABLE_FUNCTION_TYPE:
		module_name = PyFunction_GET_MODULE(callable);
		func_name   = ((PyFunctionObject *)callable)->func_name;
		need_copy   = true;
		break;
	case CALLABLE_METHOD_TYPE: // 绑定实例的方法
	{
		PyFunctionObject *meth; // 方法对象
		meth        = (PyFunctionObject *)(((PyMethodObject *)callable)->im_func);
		module_name = PyFunction_GET_MODULE(meth);
		method_name = meth->func_name;
		need_copy   = true;
		break;
	}
	case CALLABLE_INSTANCEMETHOD_TYPE:
	{
		PyFunctionObject *meth;
		meth = (PyFunctionObject*)(((PyInstanceMethodObject *)callable)->func);
		module_name = PyFunction_GET_MODULE(meth);
		method_name = meth->func_name;
		need_copy   = true;
		break;
	}
	case CALLABLE_CLASS_TYPE:
	{
		/* 类实例化 */
		PyTypeObject *cls = (PyTypeObject *)callable;

		/* 记录可调用对象的配置类型为class */
		config_object_type = DETECT_CONFIG_OBJ_TYPE_CLASS;

		/* 记录可调用对象的hook类型 */
		hook_object_type = detect_object_get_object_type((PyObject*)cls);

		if (hook_object_type < DETECT_OBJECT_TYPE_MAX) {
			/* 该类是object模块中的类或其子类 */
			/* 获取配置字典 */
			PyObject *config_dict = PyObject_GetAttrString((PyObject*)cls, CONFIG_DICT_STRING);
			if (config_dict == NULL) {
				break;
			}

			module_name = PyDict_GetItemString(config_dict, MODULE_NAME_STRING);
			class_name  = PyDict_GetItemString(config_dict, CLASS_NAME_STRING);

			threat_type_obj = PyDict_GetItemString(config_dict, THREAT_TYPE_STRING);
			if (threat_type_obj != NULL) {
				threat_type = PyLong_AsLong(threat_type_obj);
			}

			need_copy   = true;
		} else {
			/* 未被hook的类实例化 */
			class_name = PyUnicode_FromString(cls->tp_name);
			if (cls->tp_dict) {
		 		module_name = PyDict_GetItemString(cls->tp_dict, "__module__");
		 		if (module_name == NULL) {
			 		module_name = PyUnicode_FromString("unkown_class_module");
		 		} else {
					module_name = _PyUnicode_Copy(module_name);
				}
			} else {
		 		module_name = PyUnicode_FromString("unkown_class_module");
			}
			need_copy   = false;
		}

		break;
	}
	case CALLABLE_INSTANCE_TYPE:
	{
		/* hook对象中除了class，method和func都是object模块中的类实例对象调用 */
		if (detect_object_get_object_type(callable) < DETECT_OBJECT_TYPE_UNDEF) {
			/* 从配置字典中获取可调用对象信息 */
			PyHookObject *hook_obj = (PyHookObject *)callable;

			module_name  = PyDict_GetItemString(hook_obj->config_dict, MODULE_NAME_STRING);
			class_name   = PyDict_GetItemString(hook_obj->config_dict, CLASS_NAME_STRING);
			method_name  = PyDict_GetItemString(hook_obj->config_dict, METHOD_NAME_STRING);
			func_name    = PyDict_GetItemString(hook_obj->config_dict, FUNC_NAME_STRING);

			hook_object_type   = detect_object_get_object_type(callable);
			config_object_type = PyLong_AsLong(PyDict_GetItemString(hook_obj->config_dict, CONFIG_OBJ_TYPE_STRING));

			threat_type_obj = PyDict_GetItemString(hook_obj->config_dict, THREAT_TYPE_STRING);
			if (threat_type_obj != NULL) {
				threat_type = PyLong_AsLong(threat_type_obj);
			}

			need_copy   = true;
		}
	
		break;
	}
	default:
		break;
	}

	/* 模块名不能为NULL */
	if (module_name == NULL) {
		return -1;
	}

	/* 填充可调用对象信息 */
	callable_info->module_name = need_copy ? str_copy_from_unicode_object(module_name) : module_name;
	callable_info->class_name  = need_copy ? str_copy_from_unicode_object(class_name)  : class_name;
	callable_info->method_name = need_copy ? str_copy_from_unicode_object(method_name) : method_name;
	callable_info->func_name   = need_copy ? str_copy_from_unicode_object(func_name)   : func_name;

	callable_info->hook_object_type   = hook_object_type;
	callable_info->config_object_type = config_object_type;
	callable_info->threat_type        = threat_type;
	
	return 0;
}

/**
  * @description: 填充调用信息
  * @param call_info 调用信息结构
  * @param frame 当前栈帧
  * @param opcode
  * @param oparg
  * @return int
  */
static int detect_record_fill_cur_call_info(DETECT_RECORD_CALL_INFO_T *call_info,
										PyFrameObject *frame,
                                        int opcode,
                                        int oparg) {
	PyObject **stack_pointer;      // 栈顶指针
	PyObject *callable;            // 可调用对象
	CALLABLE_TYPE_E callable_type; // 可调用对象的类型
	int res = 0;
	
	stack_pointer = frame->f_valuestack + frame->f_stackdepth;

	/* 获取可调用对象和它的类型 */
	callable = detect_record_get_callable(stack_pointer, opcode, oparg);
	callable_type = callable_get_callable_type(callable);

	/* 记录可调用对象的信息 */
	res = detect_record_fill_callable_info(&call_info->callable_info, callable, callable_type);
	if (res) {
		return 0;
	}

	/* 记录其他调用信息 */
	detect_record_info.cur_call_info.stack_pointer      = stack_pointer;
	detect_record_info.cur_call_info.opcode             = opcode;
	detect_record_info.cur_call_info.oparg              = oparg;
	detect_record_info.cur_call_info.line_no            = frame->f_lineno;

	/* 标记当前调用信息是有效的 */
	detect_record_info.cur_call_info.is_avaliable = true;

	return 0;
}

/**
  * @description: 释放调用信息
  * @return
  */
static void detect_record_free_cur_call_info() {
	/* 释放各信息对象 */
	Py_CLEAR(detect_record_info.cur_call_info.callable_info.module_name);
	Py_CLEAR(detect_record_info.cur_call_info.callable_info.class_name);
	Py_CLEAR(detect_record_info.cur_call_info.callable_info.method_name);
	Py_CLEAR(detect_record_info.cur_call_info.callable_info.func_name);

	/* 标记调用信息无效 */
	detect_record_info.cur_call_info.is_avaliable = false;
}

/**
  * @description: opcode事件处理函数
  * @param frame 当前栈帧
  * @param what 事件类型 opcode事件为PyTrace_OPCODE
  * @param arg 事件参数，opcode事件时为None
  * @return int
  */
int detect_record_opcode_event_proc(PyFrameObject *frame, int what, PyObject *arg) {
	int opcode;                // 当前待执行的opcdoe
    int oparg;                 // opcode的参数
	_Py_CODEUNIT *first_instr; // 指向字节码对象的第一条指令
	_Py_CODEUNIT *next_instr;  // 指向字节码对象中当前待执行的指令

	/* 释放上一次记录的调用信息并标记其无效 */
	if (detect_record_info.cur_call_info.is_avaliable) {
		detect_record_free_cur_call_info();
	}

	/* 获取opcode和oparg */
	first_instr = (_Py_CODEUNIT *)PyBytes_AsString(frame->f_code->co_code);
	next_instr = first_instr + frame->f_lasti;
	opcode = _Py_OPCODE(*next_instr);
 	oparg = _Py_OPARG(*next_instr);

	/* 目前只关注函数调用 */
	if (opcode != CALL_METHOD && opcode != CALL_FUNCTION &&
	 	opcode != CALL_FUNCTION_KW && opcode != CALL_FUNCTION_EX) {

		return 0;
	}

	/* 填充当前调用信息 */
	detect_record_fill_cur_call_info(&detect_record_info.cur_call_info, frame, opcode, oparg);

	return 0;
}

/**
  * @description: 获取执行信息记录结构
  * @return DETECT_RECORD_INFO_T*
  */
DETECT_RECORD_INFO_T* detect_record_get_record_info() {
	return &detect_record_info;
}

