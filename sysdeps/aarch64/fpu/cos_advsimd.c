/* Double-precision vector (Advanced SIMD) cos function.

   Copyright (C) 2023-2025 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include "v_math.h"

static const struct data
{
  float64x2_t poly[7];
  float64x2_t range_val, inv_pi, pi_1, pi_2, pi_3;
} data = {
  /* Worst-case error is 3.3 ulp in [-pi/2, pi/2].  */
  .poly = { V2 (-0x1.555555555547bp-3), V2 (0x1.1111111108a4dp-7),
	    V2 (-0x1.a01a019936f27p-13), V2 (0x1.71de37a97d93ep-19),
	    V2 (-0x1.ae633919987c6p-26), V2 (0x1.60e277ae07cecp-33),
	    V2 (-0x1.9e9540300a1p-41) },
  .inv_pi = V2 (0x1.45f306dc9c883p-2),
  .pi_1 = V2 (0x1.921fb54442d18p+1),
  .pi_2 = V2 (0x1.1a62633145c06p-53),
  .pi_3 = V2 (0x1.c1cd129024e09p-106),
  .range_val = V2 (0x1p23)
};

#define C(i) d->poly[i]

static float64x2_t VPCS_ATTR NOINLINE
special_case (float64x2_t x, float64x2_t y, uint64x2_t odd, uint64x2_t cmp)
{
  y = vreinterpretq_f64_u64 (veorq_u64 (vreinterpretq_u64_f64 (y), odd));
  return v_call_f64 (cos, x, y, cmp);
}

float64x2_t VPCS_ATTR V_NAME_D1 (cos) (float64x2_t x)
{
  const struct data *d = ptr_barrier (&data);
  float64x2_t n, r, r2, r3, r4, t1, t2, t3, y;
  uint64x2_t odd, cmp;

#if WANT_SIMD_EXCEPT
  r = vabsq_f64 (x);
  cmp = vcgeq_u64 (vreinterpretq_u64_f64 (r),
		   vreinterpretq_u64_f64 (d->range_val));
  if (__glibc_unlikely (v_any_u64 (cmp)))
    /* If fenv exceptions are to be triggered correctly, set any special lanes
       to 1 (which is neutral w.r.t. fenv). These lanes will be fixed by
       special-case handler later.  */
    r = vbslq_f64 (cmp, v_f64 (1.0), r);
#else
  cmp = vcageq_f64 (x, d->range_val);
  r = x;
#endif

  /* n = rint((|x|+pi/2)/pi) - 0.5.  */
  n = vrndaq_f64 (vfmaq_f64 (v_f64 (0.5), r, d->inv_pi));
  odd = vshlq_n_u64 (vreinterpretq_u64_s64 (vcvtq_s64_f64 (n)), 63);
  n = vsubq_f64 (n, v_f64 (0.5f));

  /* r = |x| - n*pi  (range reduction into -pi/2 .. pi/2).  */
  r = vfmsq_f64 (r, d->pi_1, n);
  r = vfmsq_f64 (r, d->pi_2, n);
  r = vfmsq_f64 (r, d->pi_3, n);

  /* sin(r) poly approx.  */
  r2 = vmulq_f64 (r, r);
  r3 = vmulq_f64 (r2, r);
  r4 = vmulq_f64 (r2, r2);

  t1 = vfmaq_f64 (C (4), C (5), r2);
  t2 = vfmaq_f64 (C (2), C (3), r2);
  t3 = vfmaq_f64 (C (0), C (1), r2);

  y = vfmaq_f64 (t1, C (6), r4);
  y = vfmaq_f64 (t2, y, r4);
  y = vfmaq_f64 (t3, y, r4);
  y = vfmaq_f64 (r, y, r3);

  if (__glibc_unlikely (v_any_u64 (cmp)))
    return special_case (x, y, odd, cmp);
  return vreinterpretq_f64_u64 (veorq_u64 (vreinterpretq_u64_f64 (y), odd));
}
