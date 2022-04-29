/*
 * @Description: python恶意脚本检测主文件
 */

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"
#include "pycore_pyerrors.h"
#include "import.h"
#include "Detect/configs/config.h"
#include "Detect/object/object.h"
#include "Detect/hook/hook.h"
#include "Detect/analysis/analysis.h"

/**
  * @description: 检查是否需要使能detect恶意脚本检测模块。当编译python时，
  *               会执行源码目录下的"python -E ./setup.py build"命令来编译
  *               扩展so库，而detect模块会import外部输入和威胁模块，而此时
  *               这些模块还未编译出so库，会导致执行setup.py脚本失败，所以
  *               在编译阶段不开启detect模块。
  * @return void
  */
static bool detect_check_if_enable_detect_module() {
	/* 现在我们通过命令行开关来控制是否使能detect模块 */
	return detect_config_get_runtime_is_enable();

#if 0
	bool enable_if = true;
	
	/* 尝试导入_posixsubprocess模块，该模块为动态so模块，如果导入失败则认为在编译阶段 */
	if (!PyImport_ImportModule("_posixsubprocess")) {
		/* 模块未找到，不开启detect模块 */
		enable_if = false;

		/* 如果发生了异常则清除异常 */
		PyErr_Clear();
	}

	return enable_if;
#endif
}

 /**
  * @description: detect初始化函数
  * @return void
  */
 int detect_init() {
	int ret = 0;
	static bool has_init = false; // 该变量保证只初始化一次
 
	if (has_init || !detect_check_if_enable_detect_module()) {
		return ret;
	}

	 
	/* 配置初始化 */
	detect_config_init();
 
	/* object模块初始化 */
	ret = detect_object_init();
 
	/* hook模块初始化 */
	ret = detect_hook_init();

	/* analysis模块初始化 */
	detect_analysis_init();


	has_init = true;
 
	return ret;
 }

