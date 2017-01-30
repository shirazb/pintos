

#include "threads/fixed-point.h"

const int F = 1 << 14;

inline fixed_point_t CAST_INT_TO_FP(int n) {
    return n * F;
}
inline int CAST_FP_TO_INT_ROUND_ZERO(fixed_point_t n) {
    return n / F;
}

inline int CAST_FP_TO_INT_ROUND_NEAREST(fixed_point_t n) {
    if (n >= 0) {
        return (n + F/2) / F;
    } else {
        return (n - F/2) / F;
    }
}

inline fixed_point_t ADD_FP_FP(fixed_point_t n1, fixed_point_t n2) {
    return n1 + n2;
}

inline fixed_point_t ADD_FP_INT(fixed_point_t n1, int n2) {
    return n1 + (n2 * F);
}

inline fixed_point_t SUB_FP_FP(fixed_point_t n1, fixed_point_t n2) {
    return n1 - n2;
}

inline fixed_point_t SUB_FP_INT(fixed_point_t n1, int n2) {
    return n1 - (n2 * F);
}

inline fixed_point_t MUL_FP_FP(fixed_point_t n1, fixed_point_t n2) {
    return (((int64_t) n1) * n2) / F;
}

inline fixed_point_t MUL_FP_INT(fixed_point_t n1, int n2) {
    return n1 * n2;
}

inline fixed_point_t DIV_FP_FP(fixed_point_t n1, fixed_point_t n2) {
    return (((int64_t) n1) * F )/ n2;
}

inline fixed_point_t DIV_FP_INT(fixed_point_t n1, int n2) {
    return n1 / n2;
}