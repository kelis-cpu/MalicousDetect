/*
 * @Description: undefined未定义的类实现和初始化，其实例化对象用于hook脚本中未定义的对象(模块、类、函数等等)
 */

#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"
#include "import.h"
#include "object.h"
#include "Detect/object/object_common.h"
#include "Detect/object/undef/object_undef_class.h"
#include "Detect/configs/config.h"
#include "Detect/utils/dict.h"
#include "Detect/utils/exception.h"

/**
 * @description: undefined类的__new__方法实现，所有undefined对象的生成会调用该函数
 * @param type 类型对象
 * @param args 位置参数
 * @param kwargs 关键字参数
 * @return PyObject* 生成的对象
 */
static PyObject *detect_object_undef_class_method_new(PyTypeObject *type, PyObject *args, PyObject *kwargs) {
	PyUndefObject *taint_obj;

    taint_obj = (PyUndefObject *)type->tp_alloc(type, 0);

	return (PyObject *)taint_obj;
}


/**
  * undefined类实现，undefined类为静态类，因此不能在外部添加
  * 和修改类属性，所有属性需在此处静态定义.
  */
PyTypeObject PyUndef_Type = {
	PyVarObject_HEAD_INIT(&PyType_Type, 0)
	.tp_name		= UNDEF_CLASS_PREFIX,
	.tp_basicsize	= sizeof(PyUndefObject),
	.tp_itemsize	= 0,
	.tp_getattro    = detect_object_class_getattro,
    .tp_setattro    = detect_object_class_setattro,
    .tp_iter        = detect_object_class_iter,
    .tp_iternext    = detect_object_class_iternext,
    .tp_new         = detect_object_undef_class_method_new,
    .tp_free        = PyObject_Free,
    .tp_dealloc     = detect_object_class_dealloc,
    .tp_call        = detect_object_class_call,
	.tp_alloc		= PyType_GenericAlloc, // 该申请函数会先将对象memset 0后再做初始化
	.tp_init		= NULL, 			   // 不设置__init__
	.tp_dictoffset  = 0,				   // 实例对象中不设置__dict__属性
	.tp_flags		= Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, // 允许undefined类被继承
	.tp_repr       = detect_object_class_repr,
	.tp_str        = detect_object_class_str,
};

/**
 * @description: undefined类初始化
 * @return void
 */
int detect_object_undef_class_init() {
	int ret = 0;

	/* 初始化undefined类 */
	ret = PyType_Ready(&PyUndef_Type);

	return ret;
}

