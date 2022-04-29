/*
 * @Description: 与c function对象相关的操作函数
 */

#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "frameobject.h"
#include "callable.h"

/**
 * @description: 从c函数或c方法中获取所属模块名
 * @param callable 可调用对象
 * @return PyObject* 模块名
 */
PyObject* callable_cfunc_get_module_name(PyObject *callable) {
    PyCFunctionObject *fn;

    /* Replace built-in function objects with a descriptive string
       because of built-in methods -- keeping a reference to
       __self__ is probably not a good idea. */
    fn = (PyCFunctionObject *)callable;

    if (fn->m_self == NULL) {
        /* built-in function: look up the module name */
        PyObject *mod = fn->m_module;
        PyObject *modname = NULL;
        if (mod != NULL) {
            if (PyUnicode_Check(mod)) {
                modname = mod;
                Py_INCREF(modname);
            }
            else if (PyModule_Check(mod)) {
                modname = PyModule_GetNameObject(mod);
                if (modname == NULL)
                    PyErr_Clear();
            }
        }
        if (modname != NULL) {
            if (!_PyUnicode_EqualToASCIIString(modname, "builtins")) {
                PyObject *result;
                result = PyUnicode_FromFormat("%U", modname);
                Py_DECREF(modname);
                return result;
            }
            Py_DECREF(modname);
        }
        return PyUnicode_FromFormat("%s", fn->m_ml->ml_name);
    }
    else {
        /* built-in method: try to return
            repr(getattr(type(__self__), __name__))
        */
        PyObject *self = fn->m_self;
        PyObject *name = PyUnicode_FromString(fn->m_ml->ml_name);
        PyObject *modname = fn->m_module;

        if (name != NULL) {
            PyObject *mo = _PyType_Lookup(Py_TYPE(self), name);
            Py_XINCREF(mo);
            Py_DECREF(name);
            if (mo != NULL) {
                PyObject *res = PyObject_Repr(mo);
                Py_DECREF(mo);
                if (res != NULL)
                    return res;
            }
        }
        /* Otherwise, use __module__ */
        PyErr_Clear();
        if (modname != NULL && PyUnicode_Check(modname))
            return PyUnicode_FromFormat("%S", modname);
        else
            return PyUnicode_FromFormat("%s", fn->m_ml->ml_name);
    }
}

/**
 * @description: 获取可调用对象的类型
 * @param callable 可调用对象
 */
CALLABLE_TYPE_E callable_get_callable_type(PyObject *callable) {
	CALLABLE_TYPE_E callable_type;

	if (!PyCallable_Check(callable)) {
		return CALLABLE_UNKNOWN_TYPE;
	}
	
	if (PyFunction_Check(callable)) {
		callable_type = CALLABLE_FUNCTION_TYPE;
	} else if (PyCFunction_CheckExact(callable)) {
		callable_type = CALLABLE_CFUNCTION_TYPE;
	} else if (PyCMethod_CheckExact(callable)) {
		callable_type = CALLABLE_CMETHOD_TYPE;
	} else if (PyInstanceMethod_Check(callable)) {
		callable_type = CALLABLE_INSTANCEMETHOD_TYPE;
	} else if (PyMethod_Check(callable)) {
		callable_type = CALLABLE_METHOD_TYPE;
	} else if (PyType_IsSubtype(Py_TYPE(callable), &PyType_Type)) {
		callable_type = CALLABLE_CLASS_TYPE;
	} else if (PyGen_CheckExact(callable)) {
		callable_type = CALLABLE_GENFUNTION_TYPE;
	} else if (PyCoro_CheckExact(callable)) {
		callable_type = CALLABLE_CORFUNCTION_TYPE;
	} else if (PyAsyncGen_CheckExact(callable)) {
		callable_type = CALLABLE_ASYGEN_TYPE;
	} else {
		callable_type = CALLABLE_INSTANCE_TYPE;
	}
	
	return callable_type;
}

