/*
 * @Description: 通用配置处理函数
 */

#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"

 /**
  * @description: 根据参数position数组构建对应的list
  * @param taint_pos 参数position数组
  * @param len 数组长度
  * return PyObject* 列表对象
  */
 PyObject *detect_config_create_pos_list(int *taint_pos, int len) {
	 PyObject *list_tmp = PyList_New(0);
	 int index;
 
	 for (index = 0; index < len; index++) {
		 if (taint_pos[index] == 0) {
			 break;
		 }
		 PyList_Append(list_tmp, PyLong_FromLong(taint_pos[index]));
	 }
 
	 return list_tmp;
 }

