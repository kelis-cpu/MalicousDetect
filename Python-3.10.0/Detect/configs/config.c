/*
 * @Description: 配置定义
 */

#include <stdlib.h>
#include "Detect/configs/config.h"
#include "Detect/utils/str.h"

/* 运行时检测配置 */
static DETECT_RUNTIME_CONFIG g_detect_runtime_config = {
	.is_enable = true,
	.is_jump_branch = false,
	.detect_timeout = 10,
	.memory_limit = 500,
	.run_mode = RUN_MODE_DEBUG,
	.run_state = RUN_STATE_INITIALIZING
};

/**
 * @description: 获取detect模块开关状态
 * @return bool true --- 开启，false --- 关闭
 */
bool detect_config_get_runtime_is_enable() {
	return g_detect_runtime_config.is_enable;
}

/**
 * @description: 设置detect模块开关状态
 * @return void
 */
void detect_config_set_runtime_is_enable(bool is_enable) {
	g_detect_runtime_config.is_enable = is_enable;
}

/**
 * @description: 获取detect模块是否跳过分支
 * @return bool
 */
bool detect_config_get_runtime_is_jump_branch() {
	return g_detect_runtime_config.is_jump_branch;
}

/**
 * @description: 获取detect模块是否运行在debug模式
 * @return bool
 */
bool detect_config_get_runtime_is_debug() {
	return g_detect_runtime_config.run_mode == RUN_MODE_DEBUG;
}

/**
 * @description: 设置detect模块的运行状态
 * @return void
 */
void detect_config_set_runtime_state(DETECT_RUN_STATE run_state) {
	g_detect_runtime_config.run_state = run_state;
}

/**
 * @description: 获取detect模块的运行状态
 * @return DETECT_RUN_STATE
 */
DETECT_RUN_STATE detect_config_get_runtime_state() {
	return g_detect_runtime_config.run_state;
}

/**
 * @description: 获取detect模块的超时时间
 * @return int
 */
int detect_config_get_runtime_timeout() {
	return g_detect_runtime_config.detect_timeout;
}

/**
 * @description: 解析命令行选项-D传入的参数中的key-value
 * @param args -D选项的参数
 */
static void detect_config_parse_cli_args_key_value(const char *key, const char *value) {
	if (!strcmp(key, "enable")) {
		g_detect_runtime_config.is_enable = !strcmp(value, "true") ? true : false;
	} else if (!strcmp(key, "jump_branch")) {
		g_detect_runtime_config.is_jump_branch = !strcmp(value, "true") ? true : false;
	} else if (!strcmp(key, "run_mode")) {
		g_detect_runtime_config.run_mode = !strcmp(value, "debug") ? RUN_MODE_DEBUG : RUN_MODE_RELEASE;
	} else if (!strcmp(key, "detect_timeout")) {
		g_detect_runtime_config.detect_timeout = atoi(value);
	} else if (!strcmp(key, "memory_limit")) {
		g_detect_runtime_config.memory_limit = atoi(value);
	} else {
		/* 未知参数 */
	}
}

/**
 * @description: 解析命令行选项-D传入的参数，参数格式为"enable=false,jump_branch=false,xxx=xxx".
 *               该函数中不能使用python对象，因为在配置初始化阶段还没有对象.
 * @param args -D选项的参数
 */
void detect_config_parse_cli_args(const wchar_t *args) {
	char *str_args = str_convert_wchar_to_string(args);
	char *key, *value, *iter;

	key = str_args;
	iter = str_args;
	while(true) {		
		iter++;
		
		if (*iter == '=') {
			value = (iter+1);
			*iter = '\0';
			continue;
		}

		/* 触发键值对的匹配 */
		if (*iter == ',') {
			*iter = '\0';

			detect_config_parse_cli_args_key_value(key, value);

			key = iter+1;
			continue;
		}

		/* 最后一个键值对 */
		if (*iter == '\0') {
			detect_config_parse_cli_args_key_value(key, value);

			break;
		}
	}
	

	PyMem_RawFree(str_args);
	
	return;
}

/**
 * @description: 配置初始化
 */
void detect_config_init() {
	/* 初始化外部输入配置 */
	detect_config_taint_input_def_init();

	/* 初始化威胁配置 */
	detect_config_threat_def_init();

	/* 初始化自定义配置 */
	detect_config_custom_def_init();

	return;
}
