#ifndef DETECT_RECORD_RECORD_H
#define DETECT_RECORD_RECORD_H

#include "Python.h"
#include "pycore_interp.h"
#include "frameobject.h"
#include "Detect/record/trace.h"
#include "Detect/record/opcode_event.h"

extern bool detect_record_need_record(PyThreadState *tstate, PyFrameObject *f);
extern void detect_record_normalize(PyThreadState *tstate, PyFrameObject *f);
extern void detect_record_init(PyThreadState *tstate, PyFrameObject *f);

#endif
