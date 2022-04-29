/*
 * @Description: 追踪函数定义以及追踪的核心逻辑
 */

#include "Python.h"
#include "frameobject.h"
#include "methodobject.h"
#include "Detect/record/opcode_event.h"

/**
* @description: line事件追踪函数
*/
static int py_trace_line_proc(PyFrameObject *frame, int what, PyObject *arg) {
	return 0;
}

/**
* @description: opcode事件追踪函数，目前所有的执行信息记录都通过opcode事件来完成
*/
static int py_trace_opcode_proc(PyFrameObject *frame, int what, PyObject *arg) {
	
	return detect_record_opcode_event_proc(frame, what, arg);
}

/**
* @description: call事件追踪函数
*/
static int py_trace_call_proc(PyFrameObject *frame, int what, PyObject *arg) {
	return 0;
}

/**
* @description: return事件追踪函数
*/
static int py_trace_return_proc(PyFrameObject *frame, int what, PyObject *arg) {
	return 0;
}

/**
* @description: c call事件追踪函数
*/
static int py_trace_c_call_proc(PyFrameObject *frame, int what, PyObject *arg) {
	return 0;
}

/**
* @description: c return事件追踪函数
*/
static int py_trace_c_return_proc(PyFrameObject *frame, int what, PyObject *arg) {
	return 0;
}

/**
* @description: trace追踪函数，负责追踪line、opcode事件
* @param self python层设置的trace方法，这里一直为NULL
* @param frame 当前栈帧对象
* @param what 事件类型
* @param arg 事件参数
* @return 追踪函数是否执行成功，0 -- 成功，非0 -- 失败
*/
int detect_record_trace(PyObject *self, PyFrameObject *frame,
                 int what, PyObject *arg) {
    int ret = 0;
	
    switch (what) {
	case PyTrace_LINE:
		ret = py_trace_line_proc(frame, what, arg);
		break;
	case PyTrace_OPCODE:
		ret = py_trace_opcode_proc(frame, what, arg);
		break;
	default:
		break;
	}
	
	return ret;
}

/**
* @description: profile追踪函数，负责追踪call、return、c_call、c_return事件
* @param self python层设置的profile方法，这里一直为NULL
* @param frame 当前栈帧对象
* @param what 事件类型
* @param arg 事件参数
* @return 追踪函数是否执行成功，0 -- 成功，非0 -- 失败
*/
int detect_record_profile(PyObject *self, PyFrameObject *frame,
			 int what, PyObject *arg) {
	int ret = 0;

	switch (what) {
	case PyTrace_CALL:
		ret = py_trace_call_proc(frame, what, arg);
		break;
	case PyTrace_RETURN:
		ret = py_trace_return_proc(frame, what, arg);
		break;
	case PyTrace_C_CALL:
		ret = py_trace_c_call_proc(frame, what, arg);
		break;
	case PyTrace_C_RETURN:
		ret = py_trace_c_return_proc(frame, what, arg);
		break;
	default:
		break;
	}

	return ret;
}

