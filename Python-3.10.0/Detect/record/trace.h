#ifndef DETECT_RECORD_TRACE_H
#define DETECT_RECORD_TRACE_H

extern int detect_record_trace(PyObject *self, PyFrameObject *frame,
                 int what, PyObject *arg);
extern int detect_record_profile(PyObject *self, PyFrameObject *frame,
			 int what, PyObject *arg);

#endif
