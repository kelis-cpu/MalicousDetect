#ifndef DETECT_CONFIGS_CONFIG_H
#define DETECT_CONFIGS_CONFIG_H

#include <stdbool.h>
#include "Detect/configs/common.h"
#include "Detect/configs/custom_def.h"
#include "Detect/configs/taint_input_def.h"
#include "Detect/configs/threat_def.h"

/* 检测模式 --- release or debug */
typedef enum {
	RUN_MODE_RELEASE = 0,
	RUN_MODE_DEBUG
} DETECT_RUN_MODE;

/* 运行状态 */
typedef enum {
	RUN_STATE_INITIALIZING, // 初始化状态
	RUN_STATE_RECORDING,    // 执行信息记录状态
	RUN_STATE_ANALYSING,    // 分析状态
} DETECT_RUN_STATE;

/* 运行时配置 */
typedef struct {
	bool is_enable;      // 是否开启detect检测模块
	bool is_jump_branch; // 是否将分支展平
	int detect_timeout;  // 检测超时
	int memory_limit;    // 检测内存限制
	DETECT_RUN_MODE run_mode;   // 运行模式 --- release or debug
	DETECT_RUN_STATE run_state; // 运行状态
} DETECT_RUNTIME_CONFIG;

extern void detect_config_set_runtime_is_enable(bool is_enable);
extern bool detect_config_get_runtime_is_enable();
extern bool detect_config_get_runtime_is_jump_branch();
extern bool detect_config_get_runtime_is_debug();
extern DETECT_RUN_STATE detect_config_get_runtime_state();
extern void detect_config_set_runtime_state(DETECT_RUN_STATE run_state);
extern int detect_config_get_runtime_timeout();
extern void detect_config_parse_cli_args(const wchar_t *args);
extern void detect_config_init();

#endif

