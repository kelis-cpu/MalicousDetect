/*
 * @Description: object模块用于提供各种类型的对象，比如taint对象、函数对象、方法对象等等
 */
#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"
#include "import.h"
#include "object.h"
#include "Detect/object/object.h"


/**
 * @description: object模块初始化
 * @return void
 */
int detect_object_init() {
	int ret = 0;

	/* 初始化taint类 */
	ret = detect_object_taint_class_init();

	/* 初始化taint类实例化对象 */	
	ret = detect_object_taint_object_init();

	/* 初始化threat类 */
	ret = detect_object_threat_class_init();

	/* 初始化threat类实例化对象 */	
	ret = detect_object_threat_object_init();

	/* 初始化custom类 */
	ret = detect_object_custom_class_init();

	/* 初始化custom类实例化对象 */
	ret = detect_object_custom_object_init();

	/* 初始化undefined类 */
	ret = detect_object_undef_class_init();

	return ret;
}
