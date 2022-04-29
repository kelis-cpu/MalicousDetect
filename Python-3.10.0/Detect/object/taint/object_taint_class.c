/*
 * @Description: taint类和子类实现和初始化，taint子类作为外部输入类配置的hook对象
 */
#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"
#include "import.h"
#include "object.h"
#include "Detect/object/object_common.h"
#include "Detect/object/taint/object_taint_class.h"
#include "Detect/configs/config.h"
#include "Detect/utils/dict.h"
#include "Detect/utils/exception.h"

/**
 * @description: taint类的__new__方法实现，所有taint对象的生成会调用该函数
 * @param type 类型对象
 * @param args 位置参数
 * @param kwargs 关键字参数
 * @return PyObject* 生成的对象
 */
static PyObject *detect_object_taint_class_method_new(PyTypeObject *type, PyObject *args, PyObject *kwargs) {
	PyTaintObject *taint_obj;

    taint_obj = (PyTaintObject *)type->tp_alloc(type, 0);

	if (PyType_IsSubtype(type, &PyTaint_Type) && type != &PyTaint_Type) { // type为taint类的子类, 此时为taint子类的实例化操作
		taint_obj->config_dict = PyObject_GetAttrString((PyObject *)type, CONFIG_DICT_STRING);
	} else { // type为taint类
		/* taint类的实例对象在外面自行初始化 */
	}

	return (PyObject *)taint_obj;
}


/* 
 * taint类实现，该类作为所有taint子类的父类. taint类为静态类，因此不能在外部添加
 * 和修改类属性，所有属性需在此处静态定义.
 */
PyTypeObject PyTaint_Type = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    .tp_name       = TAINT_CLASS_PREFIX,
    .tp_basicsize  = sizeof(PyTaintObject),
    .tp_itemsize   = 0,
    .tp_getattro   = detect_object_class_getattro,
    .tp_setattro   = detect_object_class_setattro,
    .tp_call       = detect_object_class_call,
    .tp_iter       = detect_object_class_iter,
    .tp_iternext   = detect_object_class_iternext,
    .tp_dealloc    = detect_object_class_dealloc,
	.tp_free       = PyObject_Free,
    .tp_alloc      = PyType_GenericAlloc, // 该申请函数会先将对象memset 0后再做初始化
    .tp_new        = detect_object_taint_class_method_new,
    .tp_init       = NULL,                // 不设置__init__
	.tp_dictoffset = 0,                   // 实例对象中不设置__dict__属性
    .tp_flags      = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, // 允许taint类被继承
    .tp_repr       = detect_object_class_repr,
	.tp_str        = detect_object_class_str,
};

/**
 * @description: taint类初始化
 * @return void
 */
int detect_object_taint_class_init() {
	int ret = 0;

	/* 初始化taint类 */
	ret = PyType_Ready(&PyTaint_Type);

	/* 根据外部输入类的配置表创建对应的taint子类 */
	ret = detect_object_create_subclass(&PyTaint_Type, g_taint_input_class_dict, TAINT_CLASS_PREFIX);

	return ret;
}

