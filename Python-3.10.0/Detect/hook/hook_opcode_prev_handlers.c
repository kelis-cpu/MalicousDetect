/*
 * @Description: opcode处理前函数定义
 */

#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"
#include "import.h"
#include "opcode.h"
#include "code.h"
#include "frameobject.h"
#include "Detect/object/object.h"
#include "Detect/hook/hook_opcode_macro.h"
#include "Detect/hook/hook_indirect_taint.h"
#include "Detect/analysis/analysis.h"
#include "Detect/utils/module.h"
#include "Detect/utils/frame.h"
#include "Detect/utils/exception.h"

/**
  * @description: 当函数参数包含object模块的对象时，返回该对象作为函数的返回值
  * @param pp_stack 栈顶指针
  * @param oparg 当前opcode的参数
  * @return PyObject* object模块对象，为NULL时代表返回正常返回值
  */
static PyObject* detect_hook_get_func_param_need_return(PyObject **p_stack, Py_ssize_t oparg) {
	PyObject **stack = p_stack - oparg;
	PyObject *res = NULL;

	while (stack < p_stack) {
		if (detect_object_get_object_type(*stack) < detect_object_get_object_type(res)) {
			res = *stack;
		}
	
		stack++;
	}

	if (res != NULL) {
		Py_INCREF(res);		
	}

	return res;
}

/**
  * @description: 函数调用的处理逻辑
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return PyObject* 函数返回值
  */
static PyObject* detect_hook_call_function(PyThreadState *tstate,
              						 PyObject ***pp_stack,
              						 Py_ssize_t oparg,
              						 PyObject *kwnames) {
	PyObject **pfunc = (*pp_stack) - oparg - 1; // 获取可调用对象
    PyObject *func = *pfunc;
    PyObject *x, *w;
    Py_ssize_t nkwargs = (kwnames == NULL) ? 0 : PyTuple_GET_SIZE(kwnames); // 获取关键字参数的数量
    Py_ssize_t nargs = oparg - nkwargs;               // 获取位置参数的数量
    PyObject **stack = (*pp_stack) - nargs - nkwargs; // 获取栈底位置 

	/* 这里不再考虑call、c_call事件的触发，目前所有执行信息都通过opcode事件来获取 */
    x = PyObject_Vectorcall(func, stack, nargs | PY_VECTORCALL_ARGUMENTS_OFFSET, kwnames);

    // assert((x != NULL) ^ (_PyErr_Occurred(tstate) != NULL));

    /* 函数执行完将可调用对象及其参数全部出栈 */
    while ((*pp_stack) > pfunc) {
        w = EXT_POP(*pp_stack);
        Py_DECREF(w);
    }

    return x;
}

 /**
   * @description: 二元操作符处理执行函数
   * @param left 左操作数
   * @param right 右操作数
   * @param opcode opcode
   * @return PyObject* 函数返回值
   */
static PyObject* detect_hook_binary_execute(PyObject *left, PyObject *right, int opcode, int oparg) {
	PyObject *res;

	switch (opcode) {
	case BINARY_POWER:
		res = PyNumber_Power(left, right, Py_None);
		break;
	case BINARY_MULTIPLY:
		res = PyNumber_Multiply(left, right);
		break;
	case BINARY_MATRIX_MULTIPLY:
		res = PyNumber_MatrixMultiply(left, right);
		break;
	case BINARY_TRUE_DIVIDE:
		res = PyNumber_TrueDivide(left, right);
		break;
	case BINARY_FLOOR_DIVIDE:
		res = PyNumber_FloorDivide(left, right);
		break;
	case BINARY_MODULO:
		res = PyNumber_Remainder(left, right);
		break;
	case BINARY_ADD:
		res = PyNumber_Add(left, right);
		break;
	case BINARY_SUBTRACT:
		res = PyNumber_Subtract(left, right);
		break;
	case BINARY_SUBSCR:
		res = PyObject_GetItem(left, right);
		break;
	case BINARY_LSHIFT:
		res = PyNumber_Lshift(left, right);
		break;
	case BINARY_RSHIFT:
		res = PyNumber_Rshift(left, right);
		break;
	case BINARY_AND:
		res = PyNumber_And(left, right);
		break;
	case BINARY_XOR:
		res = PyNumber_Xor(left, right);
		break;
	case BINARY_OR:
		res = PyNumber_Or(left, right);
		break;

	case INPLACE_POWER:
		res = PyNumber_InPlacePower(left, right, Py_None);
		break;
	case INPLACE_MULTIPLY:
		res = PyNumber_InPlaceMultiply(left, right);
		break;
	case INPLACE_MATRIX_MULTIPLY:
		res = PyNumber_InPlaceMatrixMultiply(left, right);
		break;
	case INPLACE_TRUE_DIVIDE:
		res = PyNumber_InPlaceTrueDivide(left, right);
		break;
	case INPLACE_FLOOR_DIVIDE:
		res = PyNumber_InPlaceFloorDivide(left, right);
		break;
	case INPLACE_MODULO:
		res = PyNumber_InPlaceRemainder(left, right);
		break;
	case INPLACE_ADD:
		res = PyNumber_InPlaceAdd(left, right);
		break;
	case INPLACE_SUBTRACT:
		res = PyNumber_InPlaceSubtract(left, right);
		break;
	case INPLACE_LSHIFT:
		res = PyNumber_InPlaceLshift(left, right);
		break;
	case INPLACE_RSHIFT:
		res = PyNumber_InPlaceRshift(left, right);
		break;
	case INPLACE_AND:
		res = PyNumber_InPlaceAnd(left, right);
		break;
	case INPLACE_XOR:
		res = PyNumber_InPlaceXor(left, right);
		break;
	case INPLACE_OR:
		res = PyNumber_InPlaceOr(left, right);
		break;

	case COMPARE_OP:
		res = PyObject_RichCompare(left, right, oparg);

		/* 当op为==或!=时，res会为false且不抛出异常，这里强制置空后让外层将返回值置为object模块对象 */
		if (oparg == Py_EQ || oparg == Py_NE) {
			res = NULL;
		}
		break;
	default:
		assert(false);
		break;
	}

	return res;
}


/**
  * @description: 一元操作符的opcode处理前函数定义
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_unary_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int opcode, int oparg) {
	int skip_count = 0;
	PyObject *tos = TOP();

	if (detect_object_get_object_type(tos) != DETECT_OBJECT_TYPE_MAX) {
		/* 保留原栈顶对象，跳过当前opcode的执行 */
		skip_count = 1;
	}

	return skip_count;
}

/**
  * @description: 二元操作符的opcode处理前函数定义
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_binary_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int opcode, int oparg) {
	int skip_count = 0;

	PyObject *right = TOP();
    PyObject *left = SECOND();
    PyObject *res;
	DETECT_OBJECT_TYPE right_type, left_type;

	right_type = detect_object_get_object_type(right);
	left_type  = detect_object_get_object_type(left);
	if (right_type != DETECT_OBJECT_TYPE_MAX || left_type  != DETECT_OBJECT_TYPE_MAX) {

		/* 操作数其中之一为object模块的类实例对象时，完全hook */
		skip_count = 1;
		PyObject *right = POP();
    	PyObject *left  = TOP();

		/* 之所以尝试执行是因为不能错过left定义了相关魔术方法的情况 */
		res = detect_hook_binary_execute(left, right, opcode, oparg);
		
		/* 过程中发生了异常 */
		if (res == NULL) {
			res = right_type > left_type ? left : right;
		}

		Py_INCREF(res);
		SET_TOP(res);

		Py_DECREF(left);
   	    Py_DECREF(right);
		PyErr_Clear();
	}

	return skip_count;
}

/**
  * @description: opcode IMPORT_NAME处理前函数定义
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_import_name_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {
	int skip_count = 0;
	PyFrameObject *frame = tstate->frame;
	PyObject *names = frame->f_code->co_names;
	PyObject *name = GETITEM(names, oparg);
    PyObject *fromlist = POP();
    PyObject *level = TOP();
    PyObject *res;

	/* 导入指定模块 */
	res = module_import_name(tstate, frame, name, fromlist, level);

	/* 因为模块未找到而导入失败 */
    if (res == NULL && exception_get_curexectype() == PyExc_ModuleNotFoundError) {
		/* 创建一个未定义对象来代替模块对象 */
		PyObject *undef_object = detect_object_undef_object_create();
		SET_TOP(undef_object);

		/* 跳过当前opcode的执行 */
		skip_count = 1;

		Py_DECREF(level);
    	Py_DECREF(fromlist);
	} else if (res == NULL && PyErr_Occurred()) {
		
		/* 其他类型的导入失败，继续执行当前opcode去处理错误 */
		/* 恢复frame栈 */
		PUSH(fromlist);
	} else {
		
		/* 导入成功，无需再执行当前opcode */
		SET_TOP(res);
		skip_count = 1;
		Py_DECREF(level);
    	Py_DECREF(fromlist);
	}

	/* 如果有异常发生的话则清理异常 */
	PyErr_Clear();
	
	return skip_count;
}

/**
  * @description: opcode IMPORT_FROM处理前函数定义
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_import_from_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {
	int skip_count = 0;
	PyObject *names, *name, *from, *attr_value;

	/* 获取模块对象 */
    from = TOP();

	/* 只处理我们创建的模块 */
	if (module_get_attr_by_string(from, CREATED_BY_DETECT_KEY)) {

		/* 在模块对象中查找指定名称的属性，没找到则返回一个未定义对象 */
		names = tstate->frame->f_code->co_names;
		name = GETITEM(names, oparg);
		attr_value = module_get_attr(from, name);
		if (attr_value == NULL) {
			PUSH(detect_object_undef_object_create());

			/* 跳过当前opcode */
			skip_count = 1;
		}		
	}

	return skip_count;
}


/**
  * @description: opcode IMPORT_STAR处理前函数定义
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_import_star_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {
	int skip_count = 0;	
	PyObject *tos = TOP();

	if (detect_object_get_object_type(tos) != DETECT_OBJECT_TYPE_MAX) {
		/* 弹出栈顶对象，跳过当前opcode的执行 */
		POP();
		skip_count = 1;
	}

	return skip_count;
}

/**
  * @description: opcode CALL_FUNCTION处理前函数定义, 只有位置参数的函数调用
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_call_function_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {
	int skip_count = 1;	// 将函数调用完全hook，不再执行原处理逻辑
	PyObject *res;      // 函数返回值
	PyObject *res_tmp;

	/* 检测函数参数是否包含object模块中类实例对象 */
	res_tmp = detect_hook_get_func_param_need_return(*stack_pointer_addr, oparg);
	
    res = detect_hook_call_function(tstate, stack_pointer_addr, oparg, NULL);

	/* 如果函数调用时发生了异常，那么清除异常 */
	if (res == NULL) {
		if (res_tmp != NULL) {
			/* 发生异常后，调用PyErr_Clear()会将res_tmp的引用计数-2，导致后续出现问题 */
			Py_INCREF(res_tmp);

			res = res_tmp;
		} else {
			res = Py_None;
		}
	} else {
		if (res_tmp != NULL) {
			Py_DECREF(res_tmp);
		}
	}
	PyErr_Clear();

	/* 入栈返回值 */
	PUSH(res);
	
	return skip_count;
}

/**
  * @description: opcode CALL_FUNCTION_KW处理前函数定义, 包含关键字参数的函数调用
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_call_function_kw_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {
	int skip_count  = 1;	 // 将函数调用完全hook，不再执行原处理逻辑
	PyObject *names = POP(); // 关键字参数名的元组
	PyObject *res;           // 函数返回值
	PyObject *res_tmp;

	/* 检测函数参数是否包含object模块中类实例对象 */
	res_tmp = detect_hook_get_func_param_need_return(*stack_pointer_addr, oparg);

    res = detect_hook_call_function(tstate, stack_pointer_addr, oparg, names);

	/* 如果函数调用时发生了异常，那么清除异常 */
	if (res == NULL) {
		if (res_tmp != NULL) {
			res = res_tmp;
		} else {
			res = Py_None;
		}
	} else {
		if (res_tmp != NULL) {
			Py_DECREF(res_tmp);
		}
	}
	PyErr_Clear();

	/* 入栈返回值 */
	PUSH(res);
	Py_DECREF(names);
	
	return skip_count;
}

/**
  * @description: opcode CALL_FUNCTION_EX处理前函数定义, 包含额外位置参数或额外关键字参数的函数调用
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_call_function_ex_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {
	int skip_count  = 1;	 // 将函数调用完全hook，不再执行原处理逻辑
	PyObject *func;          // 可调用对象
	PyObject *callargs;      // 位置参数元组
	PyObject *kwargs = NULL; // 关键字参数字典
	PyObject *res;           // 返回值
	PyObject *res_tmp;

	/* 获取额外关键字参数 */
	if (oparg & 0x01) {
        kwargs = POP();
        if (!PyDict_CheckExact(kwargs)) {
            PyObject *d = PyDict_New();
            if (d == NULL)
                goto error;
            if (_PyDict_MergeEx(d, kwargs, 2) < 0) {
                Py_DECREF(d);
                Py_DECREF(kwargs);
                goto error;
            }
            Py_DECREF(kwargs);
            kwargs = d;
        }
        assert(PyDict_CheckExact(kwargs));
    }

	/* 获取位置参数元组，如果没有位置参数，那么该元组元素个数为0 */
	callargs = POP();
    func = TOP();
    if (!PyTuple_CheckExact(callargs)) {
        if (Py_TYPE(callargs)->tp_iter == NULL && !PySequence_Check(callargs)) {
            Py_DECREF(callargs);
            goto error;
        }
        Py_SETREF(callargs, PySequence_Tuple(callargs));
        if (callargs == NULL) {
            goto error;
        }
    }

	/* 获取参数中的object模块中类实例对象 */
	res_tmp = detect_object_get_highest_priority_item_by_args_and_kwargs(callargs, kwargs);

    res = PyObject_Call(func, callargs, kwargs);

	/* 如果函数调用时发生了异常，那么清除异常 */
	if (res == NULL) {
		if (res_tmp != NULL) {
			res = res_tmp;
		} else {
			res = Py_None;
		}
	} else {
		if (res_tmp != NULL) {
			Py_DECREF(res_tmp);
		}
	}
	PyErr_Clear();

	Py_DECREF(func);
    Py_DECREF(callargs);
    Py_XDECREF(kwargs);

    SET_TOP(res);

error:
	
	return skip_count;
}

/**
  * @description: opcode CALL_METHOD处理前函数定义, 只包含位置参数的方法调用
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_call_method_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {
	int skip_count  = 1;	 // 将函数调用完全hook，不再执行原处理逻辑
	PyObject *res, *meth, *res_tmp;

    meth = PEEK(oparg + 2);
    if (meth == NULL) {
        /* 绑定方法 */
		res_tmp = detect_hook_get_func_param_need_return(*stack_pointer_addr, oparg);
        res = detect_hook_call_function(tstate, stack_pointer_addr, oparg, NULL);
        (void)POP(); /* POP the NULL. */
    }
    else {
        /* 未绑定方法 */
		res_tmp = detect_hook_get_func_param_need_return(*stack_pointer_addr, oparg+1);
        res = detect_hook_call_function(tstate, stack_pointer_addr, oparg + 1, NULL);
    }

    /* 如果函数调用时发生了异常，那么清除异常 */
	if (res == NULL) {
		if (res_tmp != NULL) {
			/* 发生异常后，调用PyErr_Clear()会将res_tmp的引用计数-2，导致后续出现问题 */
			Py_INCREF(res_tmp);
			
			res = res_tmp;
		} else {
			res = Py_None;
		}
	} else {
		if (res_tmp != NULL) {
			Py_DECREF(res_tmp);
		}
	}
	PyErr_Clear();

	/* 入栈返回值 */
	PUSH(res);

	return skip_count;
}

/**
  * @description: opcode RETURN_VALUE处理前函数定义
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_return_value_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {
	int skip_count  = 0;
	Py_ssize_t code_size;

	/* 判断该opcode是否需要跳过，如果该return不是字节码对象的最后一个opcode，
	 * 代表其可能为代码底部一个循环的break，二次执行时我们跳过它即可 */
	if (detect_config_get_runtime_is_jump_branch()) {
		code_size = PyBytes_Size(tstate->frame->f_code->co_code) / 2;
		if (tstate->frame->f_lasti +1 < code_size) {
			/* 代表不是最后一个opcode，选择跳过 */
			skip_count = 1;

			/* 出栈返回值 */
			POP();
		}		
	}
	
	return skip_count;
}

/**
  * @description: opcode UNPACK_SEQUENCE处理前函数定义, 将序列对象解包成单个对象
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_unpack_sequence_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {
	int skip_count = 0;
	PyObject *seq = TOP();

	/* object模块定义的对象 */
	if (detect_object_get_object_type(seq) != DETECT_OBJECT_TYPE_MAX) {
		while (oparg--) {
			Py_INCREF(seq);
			PUSH(seq);
		}

		/* 跳过当前opcdoe的处理 */
		skip_count = 1;
		POP();
	}

	return skip_count;
}

/**
  * @description: opcode JUMP_FORWARD处理前函数定义
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_jump_forward_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {
	int skip_count = 0;

	/* 判断是否需要分支展平 */
	if (detect_config_get_runtime_is_jump_branch()) {
		/* 判断其上一个opcode是否为POP_BLOCK,是的话代表为try块中最后一个opcode，
		 * 目前先跳过except部分代码，后续再研究异常*/
		const _Py_CODEUNIT *first_instr, *last_instr;
		int opcode;

		first_instr = (_Py_CODEUNIT *) PyBytes_AS_STRING(tstate->frame->f_code->co_code);
		last_instr = first_instr + tstate->frame->f_lasti - 1;

		/* 判断上一个opcode，是try块和except块时不跳过 */
		opcode = _Py_OPCODE(*last_instr);
		if (opcode != POP_BLOCK && opcode != POP_EXCEPT) {
			skip_count = 1;
		}
	}

	return skip_count;
}

/**
  * @description: opcode POP_JUMP_IF_FALSE处理前函数定义, if、while语句
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_pop_jump_if_false_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {
	int skip_count = 0;
	PyObject *cond = TOP();

	/* 判断条件是否为taint类型,划定间接污染污染区 */
	if (detect_object_get_object_type(cond) == DETECT_OBJECT_TYPE_TAINT) {
		detect_hook_indirect_taint_set_area(tstate->frame, POP_JUMP_IF_FALSE, oparg);
	}

	/* 判断是否需要分支展平 */
	if (detect_config_get_runtime_is_jump_branch()) {
		POP();
		skip_count = 1;
	}

	return skip_count;
}

/**
  * @description: opcode POP_JUMP_IF_TRUE处理前函数定义, while语句
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_pop_jump_if_true_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {
	int skip_count = 0;

	/* 判断是否需要分支展平 */
	if (detect_config_get_runtime_is_jump_branch()) {
		POP();
		skip_count = 1;
	}

	return skip_count;
}

/**
  * @description: opcode JUMP_ABSOLUTE处理前函数定义, while语句
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_jump_absolute_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {	
	Py_ssize_t code_size;
	int skip_count = 0;

	/* 判断是否需要分支展平 */
	if (detect_config_get_runtime_is_jump_branch()) {
		/* 如果跳转到的位置为for循环，那么不跳过 */
		const _Py_CODEUNIT *first_instr, *jump_instr;
		int opcode;

		first_instr = (_Py_CODEUNIT *) PyBytes_AS_STRING(tstate->frame->f_code->co_code);
		jump_instr = first_instr + oparg;

		/* 判断后面第一个opcode */
		opcode = _Py_OPCODE(*jump_instr);
		if (opcode == FOR_ITER) {
			skip_count = 0;
		} else {
			skip_count = 1;			
		}
	} else {
		/* 当while条件为写死的True或非0数字时，JUMP_ABSOLUTE为字节码对象的最后一个opcode，
		 * 以此判断是否为死循环，注意这只是死循环的一种方式。即使跳过最后一个opcode后没有了
		 * return的opcode来主动退出当前frame，虚拟机依然有兜底方式来正常退出当前frame
		 */
		code_size = PyBytes_Size(tstate->frame->f_code->co_code) / 2;
		if (tstate->frame->f_lasti +1 == code_size) {
			/* 是最后一个opcode，跳过死循环 */
			skip_count = 1;
		}		
	}

	return skip_count;
}

/**
  * @description: opcode CONTAINS_OP处理前函数定义,执行in比较, 如果oparg为1，则为not in
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_contains_op_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {
	int skip_count = 0;
	PyObject *right = TOP();
    PyObject *left = SECOND();
    PyObject *res;
	DETECT_OBJECT_TYPE right_type, left_type;

	right_type = detect_object_get_object_type(right);
	left_type  = detect_object_get_object_type(left);
	if (right_type != DETECT_OBJECT_TYPE_MAX || left_type  != DETECT_OBJECT_TYPE_MAX) {
		/* 操作数其中之一为object模块的类实例对象时，完全hook */
		skip_count = 1;
		PyObject *right = POP();
    	PyObject *left  = TOP();

		/* 此处不能去尝试执行，一是没有意义，而是会导致coredump */
		res = right_type > left_type ? left : right;

		Py_INCREF(res);
		SET_TOP(res);

		Py_DECREF(left);
   	    Py_DECREF(right);
	}

	return skip_count;
}

/**
  * @description: opcode POP_TOP处理前函数定义
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_pop_top_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {
	int skip_count = 0;
	PyObject *top = TOP();

	if (detect_config_get_runtime_is_jump_branch()) {
		const _Py_CODEUNIT *first_instr, *next_instr;
		int opcode, oparg;

		first_instr = (_Py_CODEUNIT *) PyBytes_AS_STRING(tstate->frame->f_code->co_code);
		next_instr = first_instr + tstate->frame->f_lasti + 1;

		/* 首先判断是否为for循环中的break上的pop_top,此时需要跳过，否则此pop_top会将顶层
		 * 的可迭代对象出栈，导致后续走到for_iter时找不到可迭代对象
		 */
		do {
			/* 判断后面第一个opcode */
			opcode = _Py_OPCODE(*next_instr);
			if (opcode != JUMP_ABSOLUTE) {
				break;
			}

			/* 判断后面第二个opcode */
			next_instr++;
			opcode = _Py_OPCODE(*next_instr);
			if (opcode != JUMP_ABSOLUTE) {
				break;
			}

			/* 判断最后一个opcode跳转的位置是否为for_iter */
			oparg = _Py_OPARG(*next_instr);
			next_instr = first_instr + oparg;
			opcode = _Py_OPCODE(*next_instr);
			if (opcode == FOR_ITER) {
				/* 跳过当前的pop_top和下一个jump_absolute */
				skip_count = 2;
			}
			
		} while(0);

		/* 然后判断此opcode是否属于异常处理，特征为后两个opcode依然是POP_TOP。
		 * 分支展平时如果没有发生异常，需要要跳过异常处理中的三个POP_TOP，否则
		 * 会pop出无效指针去释放，导致coredump
		 */
		next_instr = first_instr + tstate->frame->f_lasti + 1;
		do {
			/* 只有没有异常时才需要跳过 */
			if (PyErr_Occurred()) {
				break;
			}

			/* 判断后面第一个opcode */
			opcode = _Py_OPCODE(*next_instr);
			if (opcode != POP_TOP) {
				break;
			}

			/* 判断后面第二个opcode */
			next_instr++;
			opcode = _Py_OPCODE(*next_instr);
			if (opcode != POP_TOP) {
				break;
			}

			/* 跳过这连续的三个POP_TOP */
			skip_count = 3;
		} while(0);
	}

	return skip_count;
}

/**
  * @description: opcode SET_FINALLY处理前函数定义,
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_setup_finally_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {
	int skip_count = 0;

	/* 分支展平时先跳过，异常比较复杂，后续再深入解决 */
	if (detect_config_get_runtime_is_jump_branch()) {
		skip_count = 1;
	}

	return skip_count;
}

/**
  * @description: opcode POP_EXCEPT处理前函数定义,
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_pop_except_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {
	int skip_count = 0;

	/* 分支展平时先跳过，异常比较复杂，后续再深入解决 */
	if (detect_config_get_runtime_is_jump_branch()) {

		/* 没有异常发生，那么直接跳过 */
		if (!PyErr_Occurred()) {
			skip_count = 1;			
		}
	}

	return skip_count;
}

/**
  * @description: opcode POP_BLOCK处理前函数定义,
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_pop_block_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {
	int skip_count = 0;

	if (detect_config_get_runtime_is_jump_branch()) {
		/* 当try中有其他分支时，每个分支可能都产生了一个pop_block，分支展平可能会
		 * 导致其执行两遍而出错，所以在此处加上安全判断 */
		if (tstate->frame->f_iblock <= 0) {
			/* block小于等于0会报错，所以此处跳过 */
			skip_count = 1;
		}
	}

	return skip_count;
}

/**
  * @description: opcode RERAISE处理前函数定义
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_reraise_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {
	int skip_count = 0;

	if (detect_config_get_runtime_is_jump_branch()) {
		/* 因为JUMP_FORWARD被跳过了，所以finally块可能被执行两遍，
		 * RERAISE是第二个finally的最后一个opcode，第二遍执行它时
		 * 会报错
		 */
		if (tstate->frame->f_iblock <= 0) {
			skip_count = 1;
		}
	}

	return skip_count;
}

/**
  * @description: opcode DUP_TOP处理前函数定义
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_dup_top_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg) {
	int skip_count = 0;

	if (detect_config_get_runtime_is_jump_branch()) {
		/* 判断是否为无异常情况下的cathc xxx as xxx,是的话需要跳过这个catch语句
		 */
		if (PyErr_Occurred()) {
			return skip_count;
		}

		const _Py_CODEUNIT *first_instr, *next_instr;
		int opcode, oparg;

		first_instr = (_Py_CODEUNIT *) PyBytes_AS_STRING(tstate->frame->f_code->co_code);
		next_instr = first_instr + tstate->frame->f_lasti + 1;

		/* 判断后面第一个opcode */
		opcode = _Py_OPCODE(*next_instr);
		if (opcode != LOAD_GLOBAL) { // LOAD_GLOBAL用来导入catch语句中的异常类
			return skip_count;
		}

		/* 判断后面第二个opcode */
		next_instr++;
		opcode = _Py_OPCODE(*next_instr);
		if (opcode != JUMP_IF_NOT_EXC_MATCH) {
			return skip_count;
		}

		oparg = _Py_OPARG(*next_instr);
		skip_count = oparg - tstate->frame->f_lasti;
	}

	return skip_count;
}

