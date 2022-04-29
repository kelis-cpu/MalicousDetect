/*
 * @Description: 与异常相关的操作函数
 */

#include "Python.h"
#include "pycore_interp.h"
#include "frameobject.h"

 /**
  * @description: 获取当前的异常类型
  * @return PyObject* 异常类型对象
  */
PyObject* exception_get_curexectype() {
	PyThreadState *tstate = PyThreadState_GET();

	return tstate->curexc_type;
}

 /**
  * @description: 获取当前的异常值
  * @return PyObject* 异常值对象
  */
PyObject* exception_get_curexecvalue() {
	PyThreadState *tstate = PyThreadState_GET();

	return tstate->curexc_value;
}

