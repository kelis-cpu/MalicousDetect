/*
 * @Description: undefined类对象的实例化
 */

#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"
#include "import.h"
#include "object.h"
#include "Detect/utils/dict.h"
#include "Detect/object/undef/object_undef_class.h"

/**
  * @description: 创建一个undefined对象.
  * @return int
  */
PyObject* detect_object_undef_object_create() {
	return PyUndef_Type.tp_new(&PyUndef_Type, NULL, NULL);;
}

