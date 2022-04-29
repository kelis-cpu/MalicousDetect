#ifndef DETECT_UTILS_FRAME_H
#define DETECT_UTILS_FRAME_H

extern PyObject* frame_is_belong_running_mainfile();
extern bool frame_is_internal_frame(PyFrameObject *frame);
extern bool frame_is_belong_lib(PyThreadState *tstate, PyFrameObject *frame);

#endif



