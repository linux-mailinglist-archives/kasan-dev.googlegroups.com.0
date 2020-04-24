Return-Path: <kasan-dev+bncBDQ27FVWWUFRB2P3RP2QKGQE5MRR54A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 04A5C1B789D
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 16:55:39 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id q11sf9164449pfq.9
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 07:55:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587740137; cv=pass;
        d=google.com; s=arc-20160816;
        b=vdO8URLN4KBYlXSKsqk+59EX0Kw/eoIruTem9LdZ88kwJ21caEIHggaBPxzTs5+3qz
         dbSdzhQaOSkePKqCzPZEuiEqpt+UqO3Dd9PLzNVW5VvhRCwuDEZ9tU2AM9OtBZjpL9e/
         8QYkdaSTNt4W+ztpyNG67wc7Xbwi6JrBZElP5z5ei32ozZN8cGkff3Ody8GZJtG0EhZj
         4mzA/sAxHij7ec5Q8lrk3QRdCZ16n4Ydy+il9av+zrxcM2ukI7uCwtVomWiBGj6eFG9C
         NHwc/RAUSYOxyZWpQ0C5eMGuLmH7iIk+Z86QFPfvdrJCZ+EkcPFYwnku3jZzX+6HgKlf
         OHkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=87zTmeJLPHCrYhdVCmSdqcN9BKOUrYQNh70EHjNI1SA=;
        b=C0EnsN6zMo13AHgF6rfvFSakBA1mFX8R/ntZP5xPJvMPc6SQkiciDO5LriybV74sqS
         9OM2STDSyB3nmhDEVEXi3bRzsrJvPmxTabMQtTXbbVwtSd+ytiDT9isEM8dRprs3RP9r
         JEYykYaHxgaLNozXzudCsnjBEcJw0Pl9pvadSwGQXuJOW2+opTZB6SC0rNjZcpfGt6pl
         W1n/HFpi21Ju5SZaoCSUS0GCpjPPi1vShklfcKo7d+iEZ4YddedAYyMeVQulCqY2oQU/
         AqSpH36VJm17W9CNZv4QryuchrXSI8vaR91iprMOL5QNU60f4z/N3nSaHgMMRTusq/GJ
         SHMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=jw3YPGTC;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=87zTmeJLPHCrYhdVCmSdqcN9BKOUrYQNh70EHjNI1SA=;
        b=eNmmqqeg7Ab/SyvD5aUDy2Jm5CSvkOlh0wPLtOP4YE9hjvjfwXSfjocG7tjBFcxMeO
         zsuZ2EAbKHdBgW5FLP6jX6KLnTA6+bwljvYMW6TeTRYJ22DY9CmQl0p3N9NwnqiQezU1
         ZZKsDXKDVoM1xrjzTHemLaZH25qZMPcYwXDJgOTC5AaekAoPcmRwuospvhzgiNFjEQzd
         SSpOxJ55YmE7XCoZ2+GNtmGT8HwTFsP54FehTGKmyFHhgen42YruZxXgvzHSRVxz9/mE
         buL3mWCkkKsBGyaU5rN9ayXLWwlacZjcYxy9/SHXLdRULc5xBRf49BhHdfQL8ruw9IsN
         0umw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=87zTmeJLPHCrYhdVCmSdqcN9BKOUrYQNh70EHjNI1SA=;
        b=V2DnIs16NvPzvn5df9jHvknQBFkzAdZczo7zjyfZofBTiNFXmrgrQFvWWfx3JzwKg6
         xLRRzOzjGgl8heyMdoVrJG9RXb2GgUeAAr+f1/dwU/aYyyMAXvAh4CZzCsET6jzUNw7J
         I3EQr9C4FbBV3ax/qH0CGHHqQNe4ZWakGTl7f/LBPd/r7Uf4VviRPgOl18Xm296l+1bg
         kcSxJVCo9nb926rCnnYIZRyyCgd4b4+J8FUG6fWfDvtRD1NO+9oya/AQFMrwugIVsHG/
         +48svcs0dN1RF7GebfLepSGg89wsCiIEcahFXUrOhwT67gvLN4a5inRsVXrW0NF3//z+
         XU4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubAH6sJWDJNVEUdO187zlicY07mmFkLPKIQdVLc3073gha7th+W
	+bNwvZHYpNDHcr+hkDKLRkQ=
X-Google-Smtp-Source: APiQypKSTLw+C3pB9XTp+j0GL90k0zHKNVBLhEr1hApss+BtXGFHw11/rtB1eW0xgG1UZrYzYpeqSQ==
X-Received: by 2002:a17:90a:f00b:: with SMTP id bt11mr6651633pjb.121.1587740137731;
        Fri, 24 Apr 2020 07:55:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:c31a:: with SMTP id v26ls6366100pfg.2.gmail; Fri, 24 Apr
 2020 07:55:37 -0700 (PDT)
X-Received: by 2002:a63:1a52:: with SMTP id a18mr9852241pgm.422.1587740137301;
        Fri, 24 Apr 2020 07:55:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587740137; cv=none;
        d=google.com; s=arc-20160816;
        b=a+n0AGs9O7EIlLEZqO8gYX44V0fuapqN9jTSeqrx9X9wbUD/ZpEVc30CW3lASRUo9u
         IcRwEFeuysVLItd4AjTt2ekQWmX9IPR5lMZhcX96XCmJZ19xuhyva8JYGOGNUqo/NTJJ
         VttOXghYn3qd+138gE0fzZobHZQqufX3LHSROysm6h0yMXDeukAd68+AwxBwQpcMxu+G
         7sDXlNCoZzWtZ2k8j3UGUSnze5dV3gW2QJf4PtBxGbTPqbVoYwmGdpyP8Rl1DwfssVyK
         juuFRHWb06PBdVIoipUxTdKdElVbyUlndzzDx4xx+Jl/Ga5ICgbderYQCdPp66Wn2sT1
         Hd7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MyaPBmU94mv7wzJ+8hGCstQaBgwGiAO22Ok0nmEBVO4=;
        b=IcUqmQqPPjfR7h9sJJG+7OiyZPmwkrLHZ4sYeZrdu4gBVvV+2yJMqTYwq/GXUAg6qA
         wxMK7xcfAYjP20XMywmKmPi3HMQ/4t+TyxgyaDM2WRhidzYGIWnnnuBXQKDhP0Ltkv09
         FshsNSLRn2i+XhKL91ogE8+MmWUA5UAaRIaX7BSTmua+uIoX9Gh4+wFw4N6QaHAbT3Cs
         YOYahgQmAfmCaPt1mB0QL1E0bj8Xl+vua4go0MBzyPa0YGtu4OzDeauXOVPsSGw9xuua
         q5ncUNHo0OP2pOQGvekG5dDbPDDgtMy9js7bualO0SB0qckPV0CZihvSGKckijvJS1I/
         rbhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=jw3YPGTC;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id a3si427943pfr.4.2020.04.24.07.55.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Apr 2020 07:55:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id 18so3689964pfv.8
        for <kasan-dev@googlegroups.com>; Fri, 24 Apr 2020 07:55:37 -0700 (PDT)
X-Received: by 2002:a63:b542:: with SMTP id u2mr9513034pgo.352.1587740136840;
        Fri, 24 Apr 2020 07:55:36 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-fd06-aa7b-7508-4b8b.static.ipv6.internode.on.net. [2001:44b8:1113:6700:fd06:aa7b:7508:4b8b])
        by smtp.gmail.com with ESMTPSA id 18sm4862533pjf.30.2020.04.24.07.55.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 Apr 2020 07:55:36 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com
Cc: dvyukov@google.com,
	christophe.leroy@c-s.fr,
	Daniel Axtens <dja@axtens.net>,
	Daniel Micay <danielmicay@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	David Gow <davidgow@google.com>
Subject: [PATCH v4 2/2] string.h: fix incompatibility between FORTIFY_SOURCE and KASAN
Date: Sat, 25 Apr 2020 00:55:21 +1000
Message-Id: <20200424145521.8203-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200424145521.8203-1-dja@axtens.net>
References: <20200424145521.8203-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=jw3YPGTC;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as
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

Cc: Daniel Micay <danielmicay@gmail.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Fixes: 6974f0c4555e ("include/linux/string.h: add the option of fortified string.h functions")
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Tested-by: David Gow <davidgow@google.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 include/linux/string.h | 60 +++++++++++++++++++++++++++++++++---------
 1 file changed, 48 insertions(+), 12 deletions(-)

diff --git a/include/linux/string.h b/include/linux/string.h
index 6dfbb2efa815..9b7a0632e87a 100644
--- a/include/linux/string.h
+++ b/include/linux/string.h
@@ -272,6 +272,31 @@ void __read_overflow3(void) __compiletime_error("detected read beyond size of ob
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
@@ -279,14 +304,14 @@ __FORTIFY_INLINE char *strncpy(char *p, const char *q, __kernel_size_t size)
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
@@ -300,7 +325,7 @@ __FORTIFY_INLINE __kernel_size_t strlen(const char *p)
 	/* Work around gcc excess stack consumption issue */
 	if (p_size == (size_t)-1 ||
 	    (__builtin_constant_p(p[p_size - 1]) && p[p_size - 1] == '\0'))
-		return __builtin_strlen(p);
+		return __underlying_strlen(p);
 	ret = strnlen(p, p_size);
 	if (p_size <= ret)
 		fortify_panic(__func__);
@@ -333,7 +358,7 @@ __FORTIFY_INLINE size_t strlcpy(char *p, const char *q, size_t size)
 			__write_overflow();
 		if (len >= p_size)
 			fortify_panic(__func__);
-		__builtin_memcpy(p, q, len);
+		__underlying_memcpy(p, q, len);
 		p[len] = '\0';
 	}
 	return ret;
@@ -346,12 +371,12 @@ __FORTIFY_INLINE char *strncat(char *p, const char *q, __kernel_size_t count)
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
@@ -363,7 +388,7 @@ __FORTIFY_INLINE void *memset(void *p, int c, __kernel_size_t size)
 		__write_overflow();
 	if (p_size < size)
 		fortify_panic(__func__);
-	return __builtin_memset(p, c, size);
+	return __underlying_memset(p, c, size);
 }
 
 __FORTIFY_INLINE void *memcpy(void *p, const void *q, __kernel_size_t size)
@@ -378,7 +403,7 @@ __FORTIFY_INLINE void *memcpy(void *p, const void *q, __kernel_size_t size)
 	}
 	if (p_size < size || q_size < size)
 		fortify_panic(__func__);
-	return __builtin_memcpy(p, q, size);
+	return __underlying_memcpy(p, q, size);
 }
 
 __FORTIFY_INLINE void *memmove(void *p, const void *q, __kernel_size_t size)
@@ -393,7 +418,7 @@ __FORTIFY_INLINE void *memmove(void *p, const void *q, __kernel_size_t size)
 	}
 	if (p_size < size || q_size < size)
 		fortify_panic(__func__);
-	return __builtin_memmove(p, q, size);
+	return __underlying_memmove(p, q, size);
 }
 
 extern void *__real_memscan(void *, int, __kernel_size_t) __RENAME(memscan);
@@ -419,7 +444,7 @@ __FORTIFY_INLINE int memcmp(const void *p, const void *q, __kernel_size_t size)
 	}
 	if (p_size < size || q_size < size)
 		fortify_panic(__func__);
-	return __builtin_memcmp(p, q, size);
+	return __underlying_memcmp(p, q, size);
 }
 
 __FORTIFY_INLINE void *memchr(const void *p, int c, __kernel_size_t size)
@@ -429,7 +454,7 @@ __FORTIFY_INLINE void *memchr(const void *p, int c, __kernel_size_t size)
 		__read_overflow();
 	if (p_size < size)
 		fortify_panic(__func__);
-	return __builtin_memchr(p, c, size);
+	return __underlying_memchr(p, c, size);
 }
 
 void *__real_memchr_inv(const void *s, int c, size_t n) __RENAME(memchr_inv);
@@ -460,11 +485,22 @@ __FORTIFY_INLINE char *strcpy(char *p, const char *q)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200424145521.8203-3-dja%40axtens.net.
