/*
 * test_math_compat.c
 *
 * Verify that an old and new versioned math symbol behave identically in
 * _POSIX_ mode (_LIB_VERSION = _POSIX_, which is the default for any
 * program compiled with standard feature-test macros).
 *
 * Strategy:
 *   - Use dlvsym() to load both symbol versions from libm at runtime.
 *   - Set _LIB_VERSION = _POSIX_ explicitly (it already defaults to this,
 *     but we set it to be sure).
 *   - Call both versions with the same inputs; compare return values
 *     (bit-exact, with NaN == NaN) and errno.
 *
 * Build:
 *   gcc -O0 -o test_math_compat test_math_compat.c -lm -ldl
 *   (Use -O0 to prevent the compiler from constant-folding the calls away.)
 *
 * Usage:
 *   ./test_math_compat <func> <old_ver> <new_ver> <type> [verbose]
 *
 *   <type> is one of:
 *     d    double f(double)              — exp, log, exp2, log2, exp10, sqrt …
 *     dd   double f(double,double)       — pow, hypot, fmod, atan2 …
 *     f    float  f(float)               — expf, logf, exp2f …
 *     ff   float  f(float,float)         — powf, hypotf, fmodf …
 *
 * Examples (x86_64):
 *   ./test_math_compat exp  GLIBC_2.2.5 GLIBC_2.29 d
 *   ./test_math_compat log  GLIBC_2.2.5 GLIBC_2.29 d
 *   ./test_math_compat pow  GLIBC_2.2.5 GLIBC_2.29 dd
 *   ./test_math_compat expf GLIBC_2.2.5 GLIBC_2.27 f
 *
 * The version strings for a given library can be discovered with:
 *   python3 analyze_math_symbols.py /lib/x86_64-linux-gnu/libm.so.6
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <float.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * _LIB_VERSION_TYPE and _LIB_VERSION are no longer exposed in public glibc
 * headers (removed from <math.h> when SVID compat was fully deprecated).
 * Definitions copied from glibc math/math-svid-compat.h.
 * The symbol itself is still present in libm as a GLIBC_2.0 versioned global.
 */
typedef enum {
    _IEEE_ = -1,
    _SVID_,
    _XOPEN_,
    _POSIX_,
    _ISOC_,
} _LIB_VERSION_TYPE;

/* Loaded at runtime via dlvsym — it lives in libm@GLIBC_2.0. */
static _LIB_VERSION_TYPE *lib_version_ptr = NULL;

static int failures  = 0;
static int tests_run = 0;
static int verbose   = 0;

/* ------------------------------------------------------------------ */
/* Bit-exact comparison: treats NaN==NaN, but +0.0 != -0.0            */
/* ------------------------------------------------------------------ */
static int deq(double a, double b)
{
    uint64_t ai, bi;
    if (isnan(a) && isnan(b)) return 1;
    memcpy(&ai, &a, 8);
    memcpy(&bi, &b, 8);
    return ai == bi;
}

static int feq(float a, float b)
{
    uint32_t ai, bi;
    if (isnan(a) && isnan(b)) return 1;
    memcpy(&ai, &a, 4);
    memcpy(&bi, &b, 4);
    return ai == bi;
}

/* ------------------------------------------------------------------ */
/* Function pointer types                                              */
/* ------------------------------------------------------------------ */
typedef double (*d_fn)(double);
typedef double (*dd_fn)(double, double);
typedef float  (*f_fn)(float);
typedef float  (*ff_fn)(float, float);

/* ------------------------------------------------------------------ */
/* Per-call comparison helpers                                         */
/* ------------------------------------------------------------------ */
static void cmp_d(const char *name, d_fn oldf, d_fn newf, double x)
{
    double r1, r2; int e1, e2;
    errno = 0; r1 = oldf(x); e1 = errno;
    errno = 0; r2 = newf(x); e2 = errno;
    ++tests_run;
    if (!deq(r1, r2) || e1 != e2) {
        printf("FAIL  %s(%a):\n"
               "      old → (%a, errno=%d)\n"
               "      new → (%a, errno=%d)\n",
               name, x, r1, e1, r2, e2);
        ++failures;
    } else if (verbose) {
        printf("ok    %s(%a) = %a  errno=%d\n", name, x, r1, e1);
    }
}

static void cmp_dd(const char *name, dd_fn oldf, dd_fn newf,
                   double x, double y)
{
    double r1, r2; int e1, e2;
    errno = 0; r1 = oldf(x, y); e1 = errno;
    errno = 0; r2 = newf(x, y); e2 = errno;
    ++tests_run;
    if (!deq(r1, r2) || e1 != e2) {
        printf("FAIL  %s(%a, %a):\n"
               "      old → (%a, errno=%d)\n"
               "      new → (%a, errno=%d)\n",
               name, x, y, r1, e1, r2, e2);
        ++failures;
    } else if (verbose) {
        printf("ok    %s(%a, %a) = %a  errno=%d\n", name, x, y, r1, e1);
    }
}

static void cmp_f(const char *name, f_fn oldf, f_fn newf, float x)
{
    float r1, r2; int e1, e2;
    errno = 0; r1 = oldf(x); e1 = errno;
    errno = 0; r2 = newf(x); e2 = errno;
    ++tests_run;
    if (!feq(r1, r2) || e1 != e2) {
        printf("FAIL  %s(%a):\n"
               "      old → (%a, errno=%d)\n"
               "      new → (%a, errno=%d)\n",
               name, (double)x, (double)r1, e1, (double)r2, e2);
        ++failures;
    } else if (verbose) {
        printf("ok    %s(%a) = %a  errno=%d\n", name, (double)x, (double)r1, e1);
    }
}

static void cmp_ff(const char *name, ff_fn oldf, ff_fn newf,
                   float x, float y)
{
    float r1, r2; int e1, e2;
    errno = 0; r1 = oldf(x, y); e1 = errno;
    errno = 0; r2 = newf(x, y); e2 = errno;
    ++tests_run;
    if (!feq(r1, r2) || e1 != e2) {
        printf("FAIL  %s(%a, %a):\n"
               "      old → (%a, errno=%d)\n"
               "      new → (%a, errno=%d)\n",
               name, (double)x, (double)y, (double)r1, e1, (double)r2, e2);
        ++failures;
    } else if (verbose) {
        printf("ok    %s(%a, %a) = %a  errno=%d\n",
               name, (double)x, (double)y, (double)r1, e1);
    }
}

/* ------------------------------------------------------------------ */
/* Test-vector tables                                                  */
/*                                                                     */
/* These are intentionally broad: normal values, overflow triggers,   */
/* underflow triggers, domain-error triggers, and IEEE special values. */
/* Functions that don't overflow (e.g. fmod) will just see no ERANGE  */
/* for those inputs — both old and new will agree.                    */
/* ------------------------------------------------------------------ */

static const double d_inputs[] = {
    /* Normal */
    0.0, -0.0, 1.0, -1.0, 0.5, -0.5, 2.0, -2.0,
    M_PI, -M_PI, M_E, -M_E,
    1e-10, -1e-10, 1e-100, -1e-100,
    1e10,  -1e10,  1e100,  -1e100,
    /* exp/exp2 overflow — crosses into ERANGE */
    709.0,  710.0,  800.0,  1e300,
    /* exp/exp2 underflow */
    -745.0, -746.0, -800.0, -1e300,
    /* exp2 overflow / underflow */
    1023.0, 1024.0, -1074.0, -1100.0,
    /* log domain / singularity */
    0.0, -0.0, -1.0, -1e-300,
    /* Subnormal */
    DBL_MIN, DBL_MIN / 2.0, DBL_TRUE_MIN,
    DBL_MAX, DBL_MAX / 2.0,
    /* IEEE specials */
    __builtin_inf(), -__builtin_inf(), __builtin_nan(""),
};
#define ND_INPUTS  (sizeof d_inputs  / sizeof d_inputs[0])

static const struct { double x, y; } dd_inputs[] = {
    /* pow: normal */
    {2.0, 10.0}, {2.0, -10.0}, {0.5, 0.5}, {10.0, 0.3},
    {-1.0, 3.0}, {-1.0, 2.0}, {-2.0, -3.0},
    /* pow: overflow */
    {2.0, 1024.0}, {DBL_MAX, 2.0}, {10.0, 400.0},
    /* pow: underflow */
    {2.0, -1100.0}, {DBL_MIN, 2.0},
    /* pow: domain (negative base, non-integer exponent) */
    {-1.0, 0.5}, {-2.0, 1.5},
    /* pow: special */
    {0.0, 0.0}, {0.0, -1.0}, {1.0, __builtin_inf()},
    {__builtin_inf(), 2.0}, {-__builtin_inf(), 2.0},
    {__builtin_nan(""), 1.0}, {1.0, __builtin_nan("")},
    /* hypot: overflow */
    {DBL_MAX, DBL_MAX}, {1e308, 1e308},
    /* hypot: normal */
    {3.0, 4.0}, {1.0, 1.0}, {0.0, 5.0},
    /* fmod: domain (y=0) */
    {1.0, 0.0}, {__builtin_inf(), 1.0},
    /* fmod: normal */
    {5.0, 3.0}, {-5.0, 3.0}, {5.0, -3.0},
    /* atan2 */
    {0.0, 0.0}, {1.0, 0.0}, {0.0, 1.0},
};
#define NDD_INPUTS (sizeof dd_inputs / sizeof dd_inputs[0])

static const float f_inputs[] = {
    /* Normal */
    0.0f, -0.0f, 1.0f, -1.0f, 0.5f, -0.5f, 2.0f, -2.0f,
    1e-10f, -1e-10f, 1e10f, -1e10f,
    /* expf overflow/underflow */
    88.0f,  89.0f,  200.0f,
    -103.0f, -104.0f, -200.0f,
    /* exp2f overflow/underflow */
    127.0f, 128.0f, -150.0f, -200.0f,
    /* logf domain / singularity */
    0.0f, -0.0f, -1.0f, -1e-20f,
    /* Subnormal */
    FLT_MIN, FLT_TRUE_MIN,
    FLT_MAX, FLT_MAX / 2.0f,
    /* IEEE specials */
    __builtin_inff(), -__builtin_inff(), __builtin_nanf(""),
};
#define NF_INPUTS  (sizeof f_inputs  / sizeof f_inputs[0])

static const struct { float x, y; } ff_inputs[] = {
    {2.0f, 10.0f}, {2.0f, -10.0f}, {0.5f, 0.5f},
    {-1.0f, 3.0f}, {-1.0f, 2.0f},
    {2.0f, 128.0f}, {FLT_MAX, 2.0f},   /* overflow */
    {2.0f, -200.0f}, {FLT_MIN, 2.0f},  /* underflow */
    {-1.0f, 0.5f},                      /* domain */
    {0.0f, 0.0f}, {0.0f, -1.0f},
    {3.0f, 4.0f}, {FLT_MAX, FLT_MAX},  /* hypot overflow */
    {1.0f, 0.0f},                       /* fmod domain */
    {5.0f, 3.0f}, {-5.0f, 3.0f},
    {__builtin_inff(), 1.0f}, {__builtin_nanf(""), 1.0f},
};
#define NFF_INPUTS (sizeof ff_inputs / sizeof ff_inputs[0])

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char *argv[])
{
    if (argc < 5) {
        fprintf(stderr,
            "Usage: %s <func> <old_ver> <new_ver> <type> [verbose]\n\n"
            "  type:  d   = double f(double)\n"
            "         dd  = double f(double, double)\n"
            "         f   = float  f(float)\n"
            "         ff  = float  f(float, float)\n\n"
            "Example: %s exp GLIBC_2.2.5 GLIBC_2.29 d\n",
            argv[0], argv[0]);
        return 2;
    }

    const char *func    = argv[1];
    const char *old_ver = argv[2];
    const char *new_ver = argv[3];
    const char *type    = argv[4];
    verbose = (argc > 5 && strcmp(argv[5], "verbose") == 0);

    void *handle = dlopen("libm.so.6", RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 1;
    }

    /*
     * _LIB_VERSION is a non-default (@) versioned symbol in libm, so plain
     * dlsym won't find it.  The version string is the arch's initial glibc
     * ABI version (differs per arch), so try common ones in order.
     *
     * We assert it's already _POSIX_ rather than forcing it, because any
     * program that hasn't explicitly changed it runs in POSIX mode by default.
     * If it isn't _POSIX_, our assumption that old == new is wrong and the
     * test should not proceed.
     */
    {
        static const char *vers[] = {
            "GLIBC_2.2.5",  /* x86_64 */
            "GLIBC_2.0",    /* i386, most 32-bit */
            "GLIBC_2.17",   /* aarch64 */
            "GLIBC_2.4",    /* arm (32-bit) */
            "GLIBC_2.6",    /* mips */
            NULL
        };
        for (int i = 0; vers[i]; i++) {
            lib_version_ptr = (_LIB_VERSION_TYPE *)
                dlvsym(handle, "_LIB_VERSION", vers[i]);
            if (lib_version_ptr) break;
        }
    }
    if (!lib_version_ptr) {
        fprintf(stderr, "ERROR: cannot find _LIB_VERSION in libm "
                "(tried all known arch version strings)\n");
        dlclose(handle);
        return 1;
    }
    if (*lib_version_ptr != _POSIX_) {
        fprintf(stderr, "ERROR: _LIB_VERSION is %d, expected _POSIX_ (%d).\n"
                "       The test assumes default POSIX mode; something has\n"
                "       changed it before this process started.\n",
                (int)*lib_version_ptr, (int)_POSIX_);
        dlclose(handle);
        return 1;
    }

    void *old_sym = dlvsym(handle, func, old_ver);
    void *new_sym = dlvsym(handle, func, new_ver);

    if (!old_sym) {
        fprintf(stderr, "dlvsym: cannot find %s@%s: %s\n",
                func, old_ver, dlerror());
        dlclose(handle);
        return 1;
    }
    if (!new_sym) {
        fprintf(stderr, "dlvsym: cannot find %s@@%s: %s\n",
                func, new_ver, dlerror());
        dlclose(handle);
        return 1;
    }

    printf("Testing %s  (@%s  vs  @@%s)  in _POSIX_ mode\n\n",
           func, old_ver, new_ver);

    if (strcmp(type, "d") == 0) {
        d_fn oldf = (d_fn)old_sym, newf = (d_fn)new_sym;
        for (size_t i = 0; i < ND_INPUTS; i++)
            cmp_d(func, oldf, newf, d_inputs[i]);

    } else if (strcmp(type, "dd") == 0) {
        dd_fn oldf = (dd_fn)old_sym, newf = (dd_fn)new_sym;
        for (size_t i = 0; i < NDD_INPUTS; i++)
            cmp_dd(func, oldf, newf, dd_inputs[i].x, dd_inputs[i].y);

    } else if (strcmp(type, "f") == 0) {
        f_fn oldf = (f_fn)old_sym, newf = (f_fn)new_sym;
        for (size_t i = 0; i < NF_INPUTS; i++)
            cmp_f(func, oldf, newf, f_inputs[i]);

    } else if (strcmp(type, "ff") == 0) {
        ff_fn oldf = (ff_fn)old_sym, newf = (ff_fn)new_sym;
        for (size_t i = 0; i < NFF_INPUTS; i++)
            cmp_ff(func, oldf, newf, ff_inputs[i].x, ff_inputs[i].y);

    } else {
        fprintf(stderr, "Unknown type '%s'\n", type);
        dlclose(handle);
        return 2;
    }

    printf("\n%d tests run: %s\n",
           tests_run,
           failures ? "*** FAILURES ***" : "all passed.");

    dlclose(handle);
    return failures ? 1 : 0;
}
