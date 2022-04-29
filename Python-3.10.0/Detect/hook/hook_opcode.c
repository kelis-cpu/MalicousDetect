/*
 * @Description: opcode hook主文件
 */

#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"
#include "import.h"
#include "opcode.h"
#include "Detect/configs/config.h"
#include "Detect/hook/hook_opcode_prev_handlers.h"
#include "Detect/hook/hook_indirect_taint.h"
#include "Detect/record/record.h"
#include "Detect/analysis/analysis.h"
#include "Detect/utils/frame.h"

/**
  * @description: opcode处理前函数
  * @param tstate 当前线程对象
  * @param stack_pointer_addr 栈顶指针的地址
  * @param opcode 当前执行的opcode
  * @param oparg 当前opcode的参数
  * @return int 跳过的opcode数量：0 --- 不跳过，1 --- 跳过当前opcode执行，n --- 跳过n个包括后续的opcode(包括当前opcode)
  */
int detect_hook_opcode_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int opcode, int oparg) {
	int skip_count = 0;

	/* 检查是否需要进行opcode处理 */
	if (!detect_record_need_record(tstate, tstate->frame)) {
		return skip_count;
	}

	/* 进行实时检测分析 */
	detect_analysis_main_proc();

	/* opcode自定义处理逻辑 */
	switch (opcode) {
	/* frame栈操作opcode，无需hook */
	case ROT_TWO:
	case ROT_THREE:
	case ROT_FOUR:
	case ROT_N:
	case DUP_TOP_TWO:
		break;
		
	/* 一元操作符opcode，从栈中弹出TOS，执行逻辑操作，并将结果推回堆栈 */
	case GET_LEN:
	case UNARY_POSITIVE:
	case UNARY_NEGATIVE:
	case UNARY_NOT:
	case UNARY_INVERT:
		skip_count = detect_hook_opcode_unary_prev_handler(tstate, stack_pointer_addr, oparg);
		break;
	case GET_ITER:
	case GET_YIELD_FROM_ITER:
		break;

	/* 二元操作符opcode，从栈中弹出TOS和TOS1，执行逻辑操作，并将结果推回堆栈 */
	case BINARY_POWER:
	case BINARY_MULTIPLY:
	case BINARY_MATRIX_MULTIPLY:
	case BINARY_FLOOR_DIVIDE:
	case BINARY_TRUE_DIVIDE:
	case BINARY_MODULO:
	case BINARY_ADD:
	case BINARY_SUBTRACT:
	case BINARY_SUBSCR:
	case BINARY_LSHIFT:
	case BINARY_RSHIFT:
	case BINARY_AND:
	case BINARY_XOR:
	case BINARY_OR:
		skip_count = detect_hook_opcode_binary_prev_handler(tstate, stack_pointer_addr, opcode, oparg);
		break;

	/* inplace二元操作符opcode，从栈中弹出TOS和TOS1，执行逻辑操作，并将结果推回堆栈 */
	case INPLACE_POWER:
	case INPLACE_MULTIPLY:
	case INPLACE_MATRIX_MULTIPLY:
	case INPLACE_FLOOR_DIVIDE:
	case INPLACE_TRUE_DIVIDE:
	case INPLACE_MODULO:
	case INPLACE_ADD:
	case INPLACE_SUBTRACT:
	case INPLACE_LSHIFT:
	case INPLACE_RSHIFT:
	case INPLACE_AND:
	case INPLACE_XOR:
	case INPLACE_OR:
		skip_count = detect_hook_opcode_binary_prev_handler(tstate, stack_pointer_addr, opcode, oparg);
		break;

	/* 逻辑比较运算符opcode */
	case COMPARE_OP:
		skip_count = detect_hook_opcode_binary_prev_handler(tstate, stack_pointer_addr, opcode, oparg);
		break;

	/* a[xxx] = xxx操作的opcode */
	case STORE_SUBSCR:

	
	case DELETE_SUBSCR:
		break;

	/* 协程操作符opcode */
	case GET_AWAITABLE:
	case GET_AITER:
	case GET_ANEXT:
	case END_ASYNC_FOR:
	case BEFORE_ASYNC_WITH:
	case SETUP_ASYNC_WITH:
		break;

	/* import相关操作符opcode，IMPORT_FROM和IMPORT_STAR的上一个opcode必然是IMPORT_NAME */
	case IMPORT_NAME:
		skip_count = detect_hook_opcode_import_name_prev_handler(tstate, stack_pointer_addr, oparg);
		break;
	case IMPORT_FROM:
		/**
		  * 如果IMPORT_NAME返回的是undef对象，IMPORT_FROM的处理逻辑是先对IMPORT_NAME返回的对象
		  * 调用_PyObject_LookupAttr来查找模块属性，而taint和undef类都实现了__get__方法来返回自身，所以
		  * 该opcode无需hook。
		  */
		skip_count = detect_hook_opcode_import_from_prev_handler(tstate, stack_pointer_addr, oparg);
		break;
	case IMPORT_STAR:
		skip_count = detect_hook_opcode_import_star_prev_handler(tstate, stack_pointer_addr, oparg);
		break;

	/* 函数与方法调用相关操作符opcode */
	case CALL_FUNCTION:
		skip_count = detect_hook_opcode_call_function_prev_handler(tstate, stack_pointer_addr, oparg);
		break;
	case CALL_FUNCTION_KW:
		skip_count = detect_hook_opcode_call_function_kw_prev_handler(tstate, stack_pointer_addr, oparg);
		break;
	case CALL_FUNCTION_EX:
		skip_count = detect_hook_opcode_call_function_ex_prev_handler(tstate, stack_pointer_addr, oparg);
		break;
	case CALL_METHOD:
		skip_count = detect_hook_opcode_call_method_prev_handler(tstate, stack_pointer_addr, oparg);
		break;
	case RETURN_VALUE:
		skip_count = detect_hook_opcode_return_value_prev_handler(tstate, stack_pointer_addr, oparg);
		break;

	/* 分支类操作符opcode */
	case JUMP_ABSOLUTE:
		skip_count = detect_hook_opcode_jump_absolute_prev_handler(tstate, stack_pointer_addr, oparg);
		break;
	case JUMP_FORWARD:
		skip_count = detect_hook_opcode_jump_forward_prev_handler(tstate, stack_pointer_addr, oparg);
		break;
	case POP_JUMP_IF_TRUE:
		skip_count = detect_hook_opcode_pop_jump_if_true_prev_handler(tstate, stack_pointer_addr, oparg);
		break;
	case POP_JUMP_IF_FALSE:
		skip_count = detect_hook_opcode_pop_jump_if_false_prev_handler(tstate, stack_pointer_addr, oparg);
		break;
	case JUMP_IF_NOT_EXC_MATCH:
	case JUMP_IF_TRUE_OR_POP:
	case JUMP_IF_FALSE_OR_POP:
		break;

	case LOAD_NAME:
		break;

	/* 序列解包操作opcode */
	case UNPACK_SEQUENCE:
		skip_count = detect_hook_opcode_unpack_sequence_prev_handler(tstate, stack_pointer_addr, oparg);
		break;

	/* 执行in比较, 如果oparg为1，则为not in */
	case CONTAINS_OP:
		skip_count = detect_hook_opcode_contains_op_prev_handler(tstate, stack_pointer_addr, oparg);
		break;

	/* 异常处理或其他用途 */
	case POP_TOP:
		skip_count = detect_hook_opcode_pop_top_prev_handler(tstate, stack_pointer_addr, oparg);
		break;
	case SETUP_FINALLY:
		//skip_count = detect_hook_opcode_setup_finally_prev_handler(tstate, stack_pointer_addr, oparg);
		break;
	case POP_EXCEPT:
		skip_count = detect_hook_opcode_pop_except_prev_handler(tstate, stack_pointer_addr, oparg);
		break;
	case POP_BLOCK:
		skip_count = detect_hook_opcode_pop_block_prev_handler(tstate, stack_pointer_addr, oparg);
		break;
	case RERAISE:
		skip_count = detect_hook_opcode_reraise_prev_handler(tstate, stack_pointer_addr, oparg);
		break;
	case DUP_TOP:
		skip_count = detect_hook_opcode_dup_top_prev_handler(tstate, stack_pointer_addr, oparg);
		break;
	
	/* 无需hook的其它操作符opcode */
	case PRINT_EXPR:
	case SETUP_ANNOTATIONS:
	case HAVE_ARGUMENT:
		break;
		
	default:
		break;
	}

	/* 检查当前frame，判断是否需要出栈间接污染区 */
	detect_hook_indirect_taint_pop_area(tstate->frame, opcode, skip_count);

	return skip_count;
}

 /**
   * @description: opcode处理后函数
   * @param frame 当前frame栈帧对象
   * @param stack_pointer_addr 栈顶指针的地址
   * @param opcode 当前执行的opcode
   * @param oparg 当前opcode的参数
   * @return int 跳过的opcode数量：0 --- 不跳过，n --- 跳过n个包括后续的opcode(不包括当前opcode)
   */
 int detect_hook_opcode_after_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int opcode, int oparg) {
	 int skip_count = 0;
 
	 /* opcode自定义处理逻辑 */
	 switch (opcode) {
	 default:
		 break;
	 }
  
	 return skip_count;
  }


