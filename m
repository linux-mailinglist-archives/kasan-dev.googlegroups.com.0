Return-Path: <kasan-dev+bncBDQ27FVWWUFRBIEEQDYQKGQEGKDKIVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id E503A13D44A
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 07:26:41 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id z3sf11083001oto.22
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 22:26:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579156000; cv=pass;
        d=google.com; s=arc-20160816;
        b=j9kq0xn9wX9bm3JOqr5Vh8jd7PnLI0RuU7/ZRXKsObm3p6QZdQwxFNX8CvME4ZpP9i
         v3QKKCRA6KoZcbubMjRCeg1FJLARLIaj1oDACklQpPGXjHPoGHg6jPQm+Ep9Egj/kcI/
         95uBDg6a9+xrr6nXMomle38KeCpcCrjDHMLDiRYTp+DFeCM0alC7UUW/04dWftiglKjT
         vV1FvC/0vviqVhbasDmOXMAtncg6yvtBa3pFe5XLCshZRbyFOx9vahJ/4daUBHWJjCVM
         GJdDXxbop6fu8Rnfq0MJm/kGJMeFnGvxXMPbrhuO4djhq0uhJO9ZxMWgqwuAgO7YMJIj
         EHBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DYhgyqaru4GUlrsrs8yDG2qLOnjpelngpjzqvDml8Vk=;
        b=gVxMoQVXyPPuP/B2nXT7uEne86AkUgClMgHsl43nnoiX9epMZe6TleRb0H98TV14rP
         QvwbhVd6/sHGh16PICeen3pF7vdA+fIsdyqFkbSN0InWFQHe5jAUurK0NkbKw5ueptof
         XayxeGlFg2UneLgeQF3fqix1FC1VhgqOuSDwQTpwoCEzxodDhdjzcqAiW5JiDV9RPTC4
         KIZHKFPp4qSZ4KWMByLq0aGTf85WeFMVwVjtd3vMp0y3WS0AoiAb/chJ9AS6CfdMV/DX
         xbrQb8IDnfFYz9pvDqv8Y1upJQ4dP+XHRgULsw21UICMPa9IK/cTn+9FD1r7UWUPefKc
         SEIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Uhihq+6r;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DYhgyqaru4GUlrsrs8yDG2qLOnjpelngpjzqvDml8Vk=;
        b=oZqRafJSw81hNCpaFlJqVXY3GG0RZWwIaEbwAex9SlEzPzJgqNUNLq9tktFfWIDzh/
         edLiApDkLLkcA9p97fNackiUkrfnqNczZmkTCq0oHtMqVqLj5cOuT5gOFxvy6DUEfPOV
         skC2A7Z+0LrUjoSS1h075VuF8SzhQVolaJeHcfmAQeJKsrX77Jh//ZJGjnEwxkqpTSkh
         ilxzB2o+w5KdCVoNjAgS5nmLX1vDgeY7fnkIBxk33MCNFqWpax539zfcaVKV2sxWSM8m
         a06k/aYf00yNlM+W7NInVBWqERG/ykpuUf3GV62R6GyQDttV31gHkLPSwFy6v5gtu0Uo
         eJWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DYhgyqaru4GUlrsrs8yDG2qLOnjpelngpjzqvDml8Vk=;
        b=Xz4Cp5iDmFO7OCicbnpuG0qRt/00sp5EPuunYQ5bk0p+TrmqZn7yelKxYhXlLgLk3I
         VDbuZeoFWzckiA8fY2mHZbQgVYgrK+WZWUVNZrJpkQ3SQO4UjzwTnomn0OdxCivdu7Ms
         +jxaxL5yy0Q/QYkIYW4tOwOx/fpo8A8OcBzTGcl6WHIN3sVsI9NaoidZeOSXOyaM6nx9
         8YV7LDreSaaz0JmQvVI/vUsdtCVV0By00aiNe1SvulEOXfSO7XkG4SkHH0va51ZgjtDv
         9clikSb19SqYhyyBgumT31ilrIABRxberBMjm5XAfsQJrr/VdY6WQtn+wP1kfgbBjQWF
         8pFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUGQyT+DYonTw8LyjY8lW3Nie9lUkXzltgEazgzB0OVd0eeJJ5e
	yKFm6zAIPE+RcTKqJyA3RUY=
X-Google-Smtp-Source: APXvYqz/NN0ZnJ55/lNvLEVq/kYlXRNDMf6W244xI1A1k2HAzTXRr6UyL+NgyEB+ax5r8YvuJY199g==
X-Received: by 2002:a05:6830:1198:: with SMTP id u24mr792301otq.215.1579156000557;
        Wed, 15 Jan 2020 22:26:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7059:: with SMTP id x25ls3826401otj.16.gmail; Wed, 15
 Jan 2020 22:26:40 -0800 (PST)
X-Received: by 2002:a9d:6c52:: with SMTP id g18mr833308otq.356.1579156000178;
        Wed, 15 Jan 2020 22:26:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579156000; cv=none;
        d=google.com; s=arc-20160816;
        b=1JGYj4DOWMO6LRCQkOs22/zz+Hx+VUYlHwBLmHdceA0bGZOgPrjmCzXPAwiyp/veg2
         2TD3x60LpqzFM2Q6CpkI+0tFevWJoHxE9wEmawNNDk1piDVSoRDgXX2ZU3V7OQG3pMtt
         XpD4ChXMSBHtZ7Us/FdcV2T0m4vmRoJNcYhnqjOnLDbm1IuTW4t702dBzXnZIfM0NHN9
         xqQe2mKcsD1eJJgudR8xpudYCwEFphLmub9QJX2W0rvXHWNJctthMgVfRTJM3psBzjhN
         5gcPZbE4dHeT7b0Zt/3RjTRtAkFWK8SqZnppC3uklLcPumBvmEIYXQNPcI+rhrBj9dVa
         FShQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ecViW2B6K6MgjtfxW3TT7mCoLEuRKAGSK4ebp685lGI=;
        b=TsoSf6Yn240WKzKZIKyH/yglmG9HIVC9/AnIOhS0xj/9iFFH/hqJqeXlmkpR12+srI
         acCUxm6ba7t+LnuYPm3J5Z78yIQF4RRT3g0RAA40yu4pbL/dWOQE1VVz8J/LA1I3VfGt
         WkVgtjogtERHHq1xJ3ORq8gdSewLONnArM7C50u22rREIkVWsABZmR21GDNEViaGk+y0
         yZSkFSy4C/Lh0VzYyJsx+9ntubcsXPyA3rhlSwhSDx6yArufouQ3C+DIkFhR8FhPwe4K
         R9nNbUd1U6Rr9padqe606CG2HYdSN8JdXnza3fJvjAdS8bmsQA/xERmiv0SYGlFnrwD7
         WymQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Uhihq+6r;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id d16si944424oij.1.2020.01.15.22.26.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 22:26:40 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id s94so2761905pjc.1
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 22:26:40 -0800 (PST)
X-Received: by 2002:a17:90a:a608:: with SMTP id c8mr4785355pjq.36.1579155999384;
        Wed, 15 Jan 2020 22:26:39 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-097c-7eed-afd4-cd15.static.ipv6.internode.on.net. [2001:44b8:1113:6700:97c:7eed:afd4:cd15])
        by smtp.gmail.com with ESMTPSA id o16sm22735174pgl.58.2020.01.15.22.26.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Jan 2020 22:26:38 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Cc: linuxppc-dev@lists.ozlabs.org,
	linux-arm-kernel@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-xtensa@linux-xtensa.org,
	x86@kernel.org,
	dvyukov@google.com,
	christophe.leroy@c-s.fr,
	Daniel Axtens <dja@axtens.net>,
	Daniel Micay <danielmicay@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>
Subject: [PATCH v2 2/3] string.h: fix incompatibility between FORTIFY_SOURCE and KASAN
Date: Thu, 16 Jan 2020 17:26:24 +1100
Message-Id: <20200116062625.32692-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200116062625.32692-1-dja@axtens.net>
References: <20200116062625.32692-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Uhihq+6r;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1042 as
 permitted sender) smtp.mailfrom=dja@axtens.net
Content-Type: text/plain; charset="UTF-8"
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

The memcmp KASAN self-test fails on a kernel with both KASAN and
FORTIFY_SOURCE.

When FORTIFY_SOURCE is on, a number of functions are replaced with
fortified versions, which attempt to check the sizes of the operands.
However, these functions often directly invoke __builtin_foo() once they
have performed the fortify check. Using __builtins may bypass KASAN
checks if the compiler decides to inline it's own implementation as
sequence of instructions, rather than emit a function call that goes out
to a KASAN-instrumented implementation.

Why is only memcmp affected?
============================

Of the string and string-like functions that kasan_test tests, only memcmp
is replaced by an inline sequence of instructions in my testing on x86 with
gcc version 9.2.1 20191008 (Ubuntu 9.2.1-9ubuntu2).

I believe this is due to compiler heuristics. For example, if I annotate
kmalloc calls with the alloc_size annotation (and disable some fortify
compile-time checking!), the compiler will replace every memset except the
one in kmalloc_uaf_memset with inline instructions. (I have some WIP
patches to add this annotation.)

Does this affect other functions in string.h?
=============================================

Yes. Anything that uses __builtin_* rather than __real_* could be
affected. This looks like:

 - strncpy
 - strcat
 - strlen
 - strlcpy maybe, under some circumstances?
 - strncat under some circumstances
 - memset
 - memcpy
 - memmove
 - memcmp (as noted)
 - memchr
 - strcpy

Whether a function call is emitted always depends on the compiler. Most
bugs should get caught by FORTIFY_SOURCE, but the missed memcmp test shows
that this is not always the case.

Isn't FORTIFY_SOURCE disabled with KASAN?
========================================-

The string headers on all arches supporting KASAN disable fortify with
kasan, but only when address sanitisation is _also_ disabled. For example
from x86:

 #if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
 /*
  * For files that are not instrumented (e.g. mm/slub.c) we
  * should use not instrumented version of mem* functions.
  */
 #define memcpy(dst, src, len) __memcpy(dst, src, len)
 #define memmove(dst, src, len) __memmove(dst, src, len)
 #define memset(s, c, n) __memset(s, c, n)

 #ifndef __NO_FORTIFY
 #define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
 #endif

 #endif

This comes from commit 6974f0c4555e ("include/linux/string.h: add the
option of fortified string.h functions"), and doesn't work when KASAN is
enabled and the file is supposed to be sanitised - as with test_kasan.c

I'm pretty sure this is not wrong, but not as expansive it should be:

 * we shouldn't use __builtin_memcpy etc in files where we don't have
   instrumentation - it could devolve into a function call to memcpy,
   which will be instrumented. Rather, we should use __memcpy which
   by convention is not instrumented.

 * we also shouldn't be using __builtin_memcpy when we have a KASAN
   instrumented file, because it could be replaced with inline asm
   that will not be instrumented.

What is correct behaviour?
==========================

Firstly, there is some overlap between fortification and KASAN: both
provide some level of _runtime_ checking. Only fortify provides
compile-time checking.

KASAN and fortify can pick up different things at runtime:

 - Some fortify functions, notably the string functions, could easily be
   modified to consider sub-object sizes (e.g. members within a struct),
   and I have some WIP patches to do this. KASAN cannot detect these
   because it cannot insert poision between members of a struct.

 - KASAN can detect many over-reads/over-writes when the sizes of both
   operands are unknown, which fortify cannot.

So there are a couple of options:

 1) Flip the test: disable fortify in santised files and enable it in
    unsanitised files. This at least stops us missing KASAN checking, but
    we lose the fortify checking.

 2) Make the fortify code always call out to real versions. Do this only
    for KASAN, for fear of losing the inlining opportunities we get from
    __builtin_*.

(We can't use kasan_check_{read,write}: because the fortify functions are
_extern inline_, you can't include _static_ inline functions without a
compiler warning. kasan_check_{read,write} are static inline so we can't
use them even when they would otherwise be suitable.)

Take approach 2 and call out to real versions when KASAN is enabled.

Use __underlying_foo to distinguish from __real_foo: __real_foo always
refers to the kernel's implementation of foo, __underlying_foo could be
either the kernel implementation or the __builtin_foo implementation.

This is sometimes enough to make the memcmp test succeed with
FORTIFY_SOURCE enabled. It is at least enough to get the function call
into the module. One more fix is needed to make it reliable: see the next
patch.

Cc: Daniel Micay <danielmicay@gmail.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Fixes: 6974f0c4555e ("include/linux/string.h: add the option of fortified string.h functions")
Signed-off-by: Daniel Axtens <dja@axtens.net>

---

v2: add #undefs, do not drop arch code: Dmitry pointed out that we _do_ want
    to disable fortify in non-sanitised files because of how __builtin_memcpy
    might end up as a call to regular memcpy rather than __memcpy.

Dmitry, this might cause a few new syzkaller splats - I first picked it up
building from a syskaller config. Or it might not, it just depends what gets
replaced with an inline sequence of instructions.

checkpatch complains about some over-long lines, happy to change the format
if anyone has better ideas for how to lay it out.
---
 include/linux/string.h | 60 +++++++++++++++++++++++++++++++++---------
 1 file changed, 48 insertions(+), 12 deletions(-)

diff --git a/include/linux/string.h b/include/linux/string.h
index 3b8e8b12dd37..18d3f7a4b2b9 100644
--- a/include/linux/string.h
+++ b/include/linux/string.h
@@ -317,6 +317,31 @@ void __read_overflow3(void) __compiletime_error("detected read beyond size of ob
 void __write_overflow(void) __compiletime_error("detected write beyond size of object passed as 1st parameter");
 
 #if !defined(__NO_FORTIFY) && defined(__OPTIMIZE__) && defined(CONFIG_FORTIFY_SOURCE)
+
+#ifdef CONFIG_KASAN
+extern void *__underlying_memchr(const void *p, int c, __kernel_size_t size) __RENAME(memchr);
+extern int __underlying_memcmp(const void *p, const void *q, __kernel_size_t size) __RENAME(memcmp);
+extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t size) __RENAME(memcpy);
+extern void *__underlying_memmove(void *p, const void *q, __kernel_size_t size) __RENAME(memmove);
+extern void *__underlying_memset(void *p, int c, __kernel_size_t size) __RENAME(memset);
+extern char *__underlying_strcat(char *p, const char *q) __RENAME(strcat);
+extern char *__underlying_strcpy(char *p, const char *q) __RENAME(strcpy);
+extern __kernel_size_t __underlying_strlen(const char *p) __RENAME(strlen);
+extern char *__underlying_strncat(char *p, const char *q, __kernel_size_t count) __RENAME(strncat);
+extern char *__underlying_strncpy(char *p, const char *q, __kernel_size_t size) __RENAME(strncpy);
+#else
+#define __underlying_memchr	__builtin_memchr
+#define __underlying_memcmp	__builtin_memcmp
+#define __underlying_memcpy	__builtin_memcpy
+#define __underlying_memmove	__builtin_memmove
+#define __underlying_memset	__builtin_memset
+#define __underlying_strcat	__builtin_strcat
+#define __underlying_strcpy	__builtin_strcpy
+#define __underlying_strlen	__builtin_strlen
+#define __underlying_strncat	__builtin_strncat
+#define __underlying_strncpy	__builtin_strncpy
+#endif
+
 __FORTIFY_INLINE char *strncpy(char *p, const char *q, __kernel_size_t size)
 {
 	size_t p_size = __builtin_object_size(p, 0);
@@ -324,14 +349,14 @@ __FORTIFY_INLINE char *strncpy(char *p, const char *q, __kernel_size_t size)
 		__write_overflow();
 	if (p_size < size)
 		fortify_panic(__func__);
-	return __builtin_strncpy(p, q, size);
+	return __underlying_strncpy(p, q, size);
 }
 
 __FORTIFY_INLINE char *strcat(char *p, const char *q)
 {
 	size_t p_size = __builtin_object_size(p, 0);
 	if (p_size == (size_t)-1)
-		return __builtin_strcat(p, q);
+		return __underlying_strcat(p, q);
 	if (strlcat(p, q, p_size) >= p_size)
 		fortify_panic(__func__);
 	return p;
@@ -345,7 +370,7 @@ __FORTIFY_INLINE __kernel_size_t strlen(const char *p)
 	/* Work around gcc excess stack consumption issue */
 	if (p_size == (size_t)-1 ||
 	    (__builtin_constant_p(p[p_size - 1]) && p[p_size - 1] == '\0'))
-		return __builtin_strlen(p);
+		return __underlying_strlen(p);
 	ret = strnlen(p, p_size);
 	if (p_size <= ret)
 		fortify_panic(__func__);
@@ -378,7 +403,7 @@ __FORTIFY_INLINE size_t strlcpy(char *p, const char *q, size_t size)
 			__write_overflow();
 		if (len >= p_size)
 			fortify_panic(__func__);
-		__builtin_memcpy(p, q, len);
+		__underlying_memcpy(p, q, len);
 		p[len] = '\0';
 	}
 	return ret;
@@ -391,12 +416,12 @@ __FORTIFY_INLINE char *strncat(char *p, const char *q, __kernel_size_t count)
 	size_t p_size = __builtin_object_size(p, 0);
 	size_t q_size = __builtin_object_size(q, 0);
 	if (p_size == (size_t)-1 && q_size == (size_t)-1)
-		return __builtin_strncat(p, q, count);
+		return __underlying_strncat(p, q, count);
 	p_len = strlen(p);
 	copy_len = strnlen(q, count);
 	if (p_size < p_len + copy_len + 1)
 		fortify_panic(__func__);
-	__builtin_memcpy(p + p_len, q, copy_len);
+	__underlying_memcpy(p + p_len, q, copy_len);
 	p[p_len + copy_len] = '\0';
 	return p;
 }
@@ -408,7 +433,7 @@ __FORTIFY_INLINE void *memset(void *p, int c, __kernel_size_t size)
 		__write_overflow();
 	if (p_size < size)
 		fortify_panic(__func__);
-	return __builtin_memset(p, c, size);
+	return __underlying_memset(p, c, size);
 }
 
 __FORTIFY_INLINE void *memcpy(void *p, const void *q, __kernel_size_t size)
@@ -423,7 +448,7 @@ __FORTIFY_INLINE void *memcpy(void *p, const void *q, __kernel_size_t size)
 	}
 	if (p_size < size || q_size < size)
 		fortify_panic(__func__);
-	return __builtin_memcpy(p, q, size);
+	return __underlying_memcpy(p, q, size);
 }
 
 __FORTIFY_INLINE void *memmove(void *p, const void *q, __kernel_size_t size)
@@ -438,7 +463,7 @@ __FORTIFY_INLINE void *memmove(void *p, const void *q, __kernel_size_t size)
 	}
 	if (p_size < size || q_size < size)
 		fortify_panic(__func__);
-	return __builtin_memmove(p, q, size);
+	return __underlying_memmove(p, q, size);
 }
 
 extern void *__real_memscan(void *, int, __kernel_size_t) __RENAME(memscan);
@@ -464,7 +489,7 @@ __FORTIFY_INLINE int memcmp(const void *p, const void *q, __kernel_size_t size)
 	}
 	if (p_size < size || q_size < size)
 		fortify_panic(__func__);
-	return __builtin_memcmp(p, q, size);
+	return __underlying_memcmp(p, q, size);
 }
 
 __FORTIFY_INLINE void *memchr(const void *p, int c, __kernel_size_t size)
@@ -474,7 +499,7 @@ __FORTIFY_INLINE void *memchr(const void *p, int c, __kernel_size_t size)
 		__read_overflow();
 	if (p_size < size)
 		fortify_panic(__func__);
-	return __builtin_memchr(p, c, size);
+	return __underlying_memchr(p, c, size);
 }
 
 void *__real_memchr_inv(const void *s, int c, size_t n) __RENAME(memchr_inv);
@@ -505,11 +530,22 @@ __FORTIFY_INLINE char *strcpy(char *p, const char *q)
 	size_t p_size = __builtin_object_size(p, 0);
 	size_t q_size = __builtin_object_size(q, 0);
 	if (p_size == (size_t)-1 && q_size == (size_t)-1)
-		return __builtin_strcpy(p, q);
+		return __underlying_strcpy(p, q);
 	memcpy(p, q, strlen(q) + 1);
 	return p;
 }
 
+/* Don't use these outside the FORITFY_SOURCE implementation */
+#undef __underlying_memchr
+#undef __underlying_memcmp
+#undef __underlying_memcpy
+#undef __underlying_memmove
+#undef __underlying_memset
+#undef __underlying_strcat
+#undef __underlying_strcpy
+#undef __underlying_strlen
+#undef __underlying_strncat
+#undef __underlying_strncpy
 #endif
 
 /**
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200116062625.32692-3-dja%40axtens.net.
