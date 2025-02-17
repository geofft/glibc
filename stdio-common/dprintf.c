/* Copyright (C) 1991-2025 Free Software Foundation, Inc.
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

#include <stdarg.h>
#include <libioP.h>

/* Write formatted output to D, according to the format string FORMAT.  */
/* VARARGS2 */
int
__dprintf (int d, const char *format, ...)
{
  va_list arg;
  int done;

  va_start (arg, format);
  done = __vdprintf_internal (d, format, arg, 0);
  va_end (arg);

  return done;
}
libc_hidden_def (__dprintf)
ldbl_hidden_def (__dprintf, dprintf)
ldbl_weak_alias (__dprintf, dprintf)
