#ifndef PINTOS_36_FIXED_POINT_H
#define PINTOS_36_FIXED_POINT_H

#include <lib/stdint.h>

const int F = 1 << 14;

typedef int32_t fixed_point_t;

inline fixed_point_t CAST_INT_TO_FP(int n);
inline int CAST_FP_TO_INT_ROUND_ZERO(fixed_point_t n);
inline int CAST_FP_TO_INT_ROUND_NEAREST(fixed_point_t n);

inline fixed_point_t ADD_FP_FP(fixed_point_t n1, fixed_point_t n2);
inline fixed_point_t ADD_FP_INT(fixed_point_t n1, int n2);

inline fixed_point_t SUB_FP_FP(fixed_point_t n1, fixed_point_t n2);
inline fixed_point_t SUB_FP_INT(fixed_point_t n1, int n2);

inline fixed_point_t MUL_FP_FP(fixed_point_t n1, fixed_point_t n2);
inline fixed_point_t MUL_FP_INT(fixed_point_t n1, int n2);

inline fixed_point_t DIV_FP_FP(fixed_point_t n1, fixed_point_t n2);
inline fixed_point_t DIV_FP_INT(fixed_point_t n1, int n2);

#endif //PINTOS_36_FIXED_POINT_H
