/*
 * @Description: 间接污染模块
 */

#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"
#include "import.h"
#include "opcode.h"
#include "frameobject.h"
#include "Detect/hook/hook_indirect_taint.h"
#include "Detect/utils/list.h"

/* 污染区栈 */
static PyObject *taint_area_stack;

/**
  * @description: 释放污染区
  * @param PyObject* 污染区对象
  * @return void
  */
static void detect_hook_indirect_taint_free_taint_area(PyObject *taint_area_obj) {
	DETECT_INDIRECT_TAINT_AREA_T *taint_area = PyLong_AsVoidPtr(taint_area_obj);

	/* 释放内存 */
	PyMem_RawFree(taint_area);
	_Py_Dealloc(taint_area_obj);
}

/**
  * @description: 检查当前是否正处于污染区中，只判断当前frame与污染区栈最顶层的记录区域
  * @param frame 所属栈帧
  * @param opcode 当前正执行的opcode
  * @return void
  */
static bool detect_hook_indirect_taint_check_in_taint_area(PyFrameObject *frame) {
	PyObject *top_taint_area_obj;
	DETECT_INDIRECT_TAINT_AREA_T *top_taint_area;
	int current_opcode_index;

	if (PyList_Size(taint_area_stack) == 0) {
		return false;
	}

	top_taint_area_obj = PyList_GetItem(taint_area_stack, PyList_Size(taint_area_stack)-1);
	top_taint_area = PyLong_AsVoidPtr(top_taint_area_obj);

	/* 不是同一个frame */
	if (frame != top_taint_area->frame) {
		return false;
	}

	/* 判断当前正在执行的opcode是否在污染区 */
	current_opcode_index = frame->f_lasti;
	if (current_opcode_index < top_taint_area->opcode_index_begin || 
		current_opcode_index > top_taint_area->opcode_index_end) {
		return false;
	}

	return true;
}

/**
  * @description: 根据当前执行的opcode设置间接污染的污染区
  * @param frame 所属栈帧
  * @param opcode 当前正执行的opcode
  * @return void
  */
void detect_hook_indirect_taint_set_area(PyFrameObject *frame, int opcode, int oparg) {
	const _Py_CODEUNIT *first_instr;
	DETECT_INDIRECT_TAINT_AREA_T *new_taint_area;

	/* 检查当前是否已经处于污染区 */
	if (detect_hook_indirect_taint_check_in_taint_area(frame)) {
		return;
	}

	new_taint_area = PyMem_RawMalloc(sizeof(DETECT_INDIRECT_TAINT_AREA_T));
	new_taint_area->frame = frame;
	new_taint_area->opcode_index_begin = frame->f_lasti;

	first_instr = (_Py_CODEUNIT *) PyBytes_AS_STRING(frame->f_code->co_code);
	if (opcode == POP_JUMP_IF_FALSE) {

		if (_Py_OPCODE(*(first_instr+oparg-1)) != JUMP_FORWARD) {
			/* POP_JUMP_IF_FALSE跳转到的opcode的上一个opcode不是JUMP_FORWARD，代表为if或者while */
			new_taint_area->opcode_index_end = oparg;
		} else {
			/* 代表为if-else、if-elif-else，JUMP_FORWARD的oparg为相对跳转 */
			new_taint_area->opcode_index_end = frame->f_lasti + _Py_OPARG(*(first_instr+oparg-1));
		}
	}

	PyList_Append(taint_area_stack, PyLong_FromVoidPtr(new_taint_area));

	return;
}

/**
  * @description: 出栈污染区
  * @param frame 所属栈帧
  * @param opcode 当前正执行的opcode
  * @return void
  */
void detect_hook_indirect_taint_pop_area(PyFrameObject *frame, int opcode, int skip_count) {
	PyObject *taint_area_obj;
	DETECT_INDIRECT_TAINT_AREA_T *taint_area;
	bool need_pop_top = false;

	if (taint_area_stack == NULL || PyList_Size(taint_area_stack) == 0) {
		return;
	}

	/* 获取顶层污染区 */
	taint_area_obj = list_top(taint_area_stack);
	taint_area = PyLong_AsVoidPtr(taint_area_obj);

	if (frame == taint_area->frame) {

		/* 当前frame与顶层污染区为同一个frame，代表在同一个函数中 */
		if (frame->f_lasti < taint_area->opcode_index_begin || 
			frame->f_lasti > taint_area->opcode_index_end) {

			/* 当前frame已执行到污染区的外侧，出栈顶层污染区 */
			need_pop_top = true;
		} else if (opcode == RETURN_VALUE && skip_count == 0) {
			/* 代表当前frame要退出了，可能是while中的break或return，出栈顶层污染区 */
			need_pop_top = true;
		}
	} else {
		int index;
		PyFrameObject *tmp = frame->f_back;
	
		/* 首先判断当前frame是否只是顶层污染区内部的一个函数调用 */
		while (tmp != NULL) {
			if (tmp == taint_area->frame) {
				/* 如果只是一个函数调用，那么直接返回即可 */
				return;
			}

			tmp = tmp->f_back;
		}

		/* 其实判断是否因为污染区内部的return导致当前frame是污染区frame的上层栈帧 */
		for (index = PyList_Size(taint_area_stack)-1; index >= 0; index--) {
			taint_area_obj = list_top(taint_area_stack);
			taint_area = PyLong_AsVoidPtr(taint_area_obj);

			/* 代表当前frame与污染区的frame在一个函数中，由后续opcode的调用来触发出栈即可 */
			if (taint_area->frame == frame) {
				break;
			}

			tmp = taint_area->frame->f_back;
			while (tmp != NULL) {
				/* 代表当前frame是该污染区return后的上层函数，把当前污染区出栈 */
				if (tmp == frame) {
					need_pop_top = true;
				}

				tmp = tmp->f_back;
			}
		}
	}

	/* 出栈顶层污染区 */
	if (need_pop_top) {
		list_pop(taint_area_stack);
		detect_hook_indirect_taint_free_taint_area(taint_area_obj);
	}

	return;
}

/**
  * @description: 初始化间接污染模块
  * @return void
  */
void detect_hook_indirect_taint_init() {
	taint_area_stack = PyList_New(0);

	return;
}

