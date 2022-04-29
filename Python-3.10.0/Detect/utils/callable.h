#ifndef DETECT_UTILS_CFUNC_H
#define DETECT_UTILS_CFUNC_H

/* 可调用对象类型 */
typedef enum {
	CALLABLE_FUNCTION_TYPE = 0,   // 普通python函数或者未绑定实例的python实例方法
	CALLABLE_METHOD_TYPE,         // 绑定实例的python实例方法
	CALLABLE_CMETHOD_TYPE,        // c实现的类实例方法
	CALLABLE_CFUNCTION_TYPE,      // c实现的普通函数
	CALLABLE_CLASS_TYPE,          // 类型对象
	CALLABLE_INSTANCE_TYPE,       // 类实例对象
	CALLABLE_INSTANCEMETHOD_TYPE,
	CALLABLE_METHOD_DESCR_TYPE,   // 方法描述符对象
	CALLABLE_GENFUNTION_TYPE,
	CALLABLE_CORFUNCTION_TYPE,
	CALLABLE_ASYGEN_TYPE,
	CALLABLE_UNKNOWN_TYPE,
}CALLABLE_TYPE_E;

extern PyObject* callable_cfunc_get_module_name(PyObject *callable);
extern CALLABLE_TYPE_E callable_get_callable_type(PyObject *callable);

#endif
