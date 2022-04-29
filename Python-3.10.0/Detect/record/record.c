/*
 * @Description: 执行信息记录主文件
 */

#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "frameobject.h"
#include "Detect/record/record.h"
#include "Detect/utils/frame.h"

/**
 * @description: 根据当前栈帧所在的py文件来过滤是否执行后续的信息记录
 */
bool detect_record_need_record(PyThreadState *tstate, PyFrameObject *f) {
	static PyFrameObject *last_check_frame = NULL;
	static bool last_check_frame_need_proc = false;

	/* detect模块开关未打开 */
	if (!detect_config_get_runtime_is_enable()) {
		return false;
	}
	
	if (detect_config_get_runtime_state() != RUN_STATE_RECORDING) {
		/* 当前frame属于被执行检测的脚本, 设置运行状态, 代表开始执行主脚本的代码 */
		if (frame_is_belong_running_mainfile(tstate, f)) {
			detect_config_set_runtime_state(RUN_STATE_RECORDING);
		}

		/* 当前状态不是记录状态，则不进行opcode处理 */
		if (detect_config_get_runtime_state() != RUN_STATE_RECORDING) {
			return false;
		}
	}

	/* frame已经被检查过,快速判断 */
	if (last_check_frame == f) {
		return last_check_frame_need_proc;
	}

	/* 记录frame */
	last_check_frame = f;

	/* 判断当前frame是否为lib或者内部模块 */
	{
		/* 暂时关闭detect模块，因为frame_is_belong_lib函数会使用python层模块 */
		detect_config_set_runtime_is_enable(false);

		/* 当前frame为lib中的或内部模块，不进行opcode处理 */
		if (frame_is_belong_lib(tstate, f) || frame_is_internal_frame(f)) {
			/* 恢复detect模块 */
			detect_config_set_runtime_is_enable(true);

			last_check_frame_need_proc = false;
			return false;
		}

		/* 恢复detect模块 */
		detect_config_set_runtime_is_enable(true);
	}

	last_check_frame_need_proc = true;

	return true;
}

/**
 * @description: 使能事件追踪
 * @param tstate 线程对象
 * @param tstate 当前栈帧对象
 * @return void
 */
static void detect_record_enable(PyThreadState *tstate, PyFrameObject *f) {
	/* 设置trace和profile函数 */
    tstate->c_tracefunc = detect_record_trace;
	tstate->c_profilefunc = detect_record_profile;

    /* 打开trace和profile开关 */
    tstate->cframe->use_tracing = true;

	/* 打开opcode追踪开关 */
	f->f_trace_opcodes = true;
}

/**
 * @description: 关闭事件追踪
 * @param tstate 线程对象
 * @param tstate 当前栈帧对象
 * @return void
 */
static void detect_record_disable(PyThreadState *tstate, PyFrameObject *f) {
	/* 设置trace和profile函数 */
    tstate->c_tracefunc = NULL;
	tstate->c_profilefunc = NULL;

    /* 关闭trace和profile开关 */
    tstate->cframe->use_tracing = false;

	/* 关闭opcode追踪开关 */
	f->f_trace_opcodes = false;
}


/**
 * @description: 初始化函数，根据执行上下文判断是否开启事件追踪
 * @param tstate 线程对象
 * @param tstate 当前栈帧对象
 * @return void
 */
void detect_record_init(PyThreadState *tstate, PyFrameObject *f) {
	/* 过滤不必要的py文件，关闭事件追踪 */
	if (!detect_record_need_record(tstate, f)) {

		/* 关闭事件追踪 */
		detect_record_disable(tstate, f);
		return;
	}

	/* 开启事件追踪 */
	detect_record_enable(tstate, f);
}

/**
 * @description: 当内层虚拟机不需要追踪事件时，会把c_tracefunc和c_profilefunc
 *               也置为NULL，而这两个函数是线程唯一的，所以会导致回到外层虚拟机
 *               执行时这两个函数也是NULL，无法进行事件追踪，所以在内层返回时进行
 *               正规化操作。
 * @param tstate 线程对象
 * @param tstate 当前栈帧对象
 * @return void
 */
void detect_record_normalize(PyThreadState *tstate, PyFrameObject *f) {
	if (tstate->cframe->use_tracing) {
		/* 设置trace和profile函数 */
    	tstate->c_tracefunc = detect_record_trace;
		tstate->c_profilefunc = detect_record_profile;
	}

	return;
}

