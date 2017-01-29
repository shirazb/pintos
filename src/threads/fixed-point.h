

#include <sys/types.h>

#ifndef PINTOS_36_FIXED_POINT_H
#define PINTOS_36_FIXED_POINT_H

const int F = 1 << 14;

typedef int32_t fixed_point_t;

extern inline fixed_point_t CAST_INT_TO_FP(int n);
extern inline int CAST_FP_TO_INT_ROUND_ZERO(fixed_point_t n);
extern inline int CAST_FP_TO_INT_ROUND_NEAREST(fixed_point_t n);

extern inline fixed_point_t ADD_FP_FP(fixed_point_t n1, fixed_point_t n2);
extern inline fixed_point_t ADD_FP_INT(fixed_point_t n1, int n2);

extern inline fixed_point_t SUB_FP_FP(fixed_point_t n1, fixed_point_t n2);
extern inline fixed_point_t SUB_FP_INT(fixed_point_t n1, int n2);

extern inline fixed_point_t MUL_FP_FP(fixed_point_t n1, fixed_point_t n2);
extern inline fixed_point_t MUL_FP_INT(fixed_point_t n1, int n2);

extern inline fixed_point_t DIV_FP_FP(fixed_point_t n1, fixed_point_t n2);
extern inline fixed_point_t DIV_FP_INT(fixed_point_t n1, int n2);

#endif //PINTOS_36_FIXED_POINT_H
