Return-Path: <kasan-dev+bncBDQ27FVWWUFRBNHG7LYAKGQESPLF56A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 35FAA13B9CC
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 07:37:42 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id c4sf5874011oiy.0
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 22:37:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579070260; cv=pass;
        d=google.com; s=arc-20160816;
        b=lU2AwV2vZgmXLZ6HsqS99GyjDYjV8Xnt+ayUsKe1pnG7uk94MaA9SAectcEkmFn5XR
         386h/Zd/bTD/y7xAko9p3vees79NO84ywA9KpgYQE1bs3qooMHtCP/JK46hfsPArlkpR
         m+vJkUkO7J10QZssvXCqh9m5uMosPz0fiThNT+At8Jmz72E4qQxk3gU8EZVRjlOHEMZD
         fq3hJ1dlN3gad/ZMJnkiwaC2zQhd1DdZLmGLMLFrk8HikhTzj3ekkbJSdZtiCaHRsTF1
         1AfbFzYBjQY+/ow7HaKTTZvkWxMB3tBZ34gR9ZUx4acDbhMem/VYyo1heOF/yP039cZv
         SD9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=AqXtWsJnChJ/MzyMr0rrz0vQLYKJb4okcyKxTWoGK+k=;
        b=riWyaqNfCSetts5VQS+PwnUGgDqY9J/FPrVfNxVclOhqLcpQoCZABOsaNzqkFSaAuP
         gqO5dk/fFtb05dBWvVedLoPqytdlImfUR2T+aEGCxTiBDXLIcs/4T/dnH0M0yv9VlWFT
         VJKNTTVIgU18SNgAlWkmqNNN+AFobQBMnVnOyN/VU0LOow5gnBedcSDssnsyHvXT5gwB
         ZA+M2lYrqD3RPhWyLxksA/WQxoWM06TzspTEqkT9WEV3E4xkV1JHe8TnLfG8UnmUVj0n
         ktJPCN/5j4f7LMtTa13kIJMoWtL7XptbJ+r8IqtD96TA7OqkchTa8vq8kJ1RyDpagjCj
         IQ7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=jF35eyuW;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AqXtWsJnChJ/MzyMr0rrz0vQLYKJb4okcyKxTWoGK+k=;
        b=TdjlgwoGpnf/fc/33Z5YSQm57YvM63a6RQnpMJzpt8jCFAjyWwg9VKr1/xCqqiw4KS
         i1gPQJrN2TIpmqqVHFnlstpp3emLppbOqt0El6AnhyjYDYCyz25ONAtVmrDkfWSaT8CN
         hLW+f5zXHq7pg2hDB6pB6AWaBAjCglUDwVaQykYL1xOzJOFNdsAB5ZQSobOqXv7gs/3U
         m1U6h0VwIT6LKUIgrSHKhGXl7KnfiLp/l9KCm8qGDtexyqtWcughaxM4/+X8BNhYFT5+
         X3jJo7XzqAHm/rQbP4SRbAKQVP31qzVdDUMXyJcgH7FU40ji3haL6HktJse3t9dza322
         Wdxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AqXtWsJnChJ/MzyMr0rrz0vQLYKJb4okcyKxTWoGK+k=;
        b=d6VCFb3VVVJVd0AvfM3QcN8hvw/fkG1NVvogca8BtC1HPTPGxzs815+utLo/Tutq+b
         ANvCtM/xthNQUorqv5hopGn9CXLQtxqsyPf5yecvuhfZXAwzWDNEMKZrCCk880Yuhh8M
         la6TR3y4OiHWhcDKBRwVn/epRzxzpeiKanV1X/54WvInsvXha5JcqHtkYBEG6T4ggEOF
         /LXnyxsLR4hzdnpys2bFywkjAf31/SRcAgOhUi6bbNsz9G7Hyh9eSlasodeKOe4Csg5w
         E0ISN42Tw+x+OfY4OyvePfIttEhUlFtCJwqM1Qi80KG8sdK/h9J6YTrLk7Myyi550gx2
         +21A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV1fQx4GoeFujyeHjeFXsZDtA8/viPp8eX1EOhO1KYgmwpsCION
	wDxKrfntf4Lh7k1rEVafJK4=
X-Google-Smtp-Source: APXvYqw2Gdsa1Mezr7wvpdAiGdlx5WaHm/Kwo003d14L+GmItXtv/9EDG9zd/TzAumrKURV83uKoZg==
X-Received: by 2002:a9d:32c7:: with SMTP id u65mr1731575otb.224.1579070260722;
        Tue, 14 Jan 2020 22:37:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:af4a:: with SMTP id y71ls3200108oie.16.gmail; Tue, 14
 Jan 2020 22:37:40 -0800 (PST)
X-Received: by 2002:aca:dfd5:: with SMTP id w204mr20473788oig.95.1579070260291;
        Tue, 14 Jan 2020 22:37:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579070260; cv=none;
        d=google.com; s=arc-20160816;
        b=U0Wt8zw+rTBPZMrCNgr8vZ0ebrCHEITZYJmeMOyiPNfB+AJYDu4Bnpa08luMfsdm0q
         lbQtO14pBv34thiTmpBb7EjPV0FqJXlslR5w6ibG7iCiTfdFpuc/sr6ZFgKvp+Drv3tV
         tsR4yZAmFDiaJk2NIQTnpFjtasGzBBmksYZ4fBzUYNrMs9ut8SlMLy+z4elNU+qVK3PR
         F01D5iP5xgP/UVFfPHAPfuFOso/gmbOydoK1XrN3xIlkw+KiKV73zxZ5stOtDW9kvtWb
         sxMPW5Hu13AoPGeuMN212EopkKzUgShk+Tv1x2VbP0TovAvBcqzT3pr5oEi8zCpHamtC
         M8gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=47TfoOm/Ot7psKePVSna5lKaeSaaEjfGGPpf3dZ7N5k=;
        b=hLuGz0joIeU7eOy4rgV1Euykrv1tyLkxc58O2zPcUqHd18M6QP3Th/wDwStRrY2yjX
         +C4qr9rO/Hvi08wdhQ6nUIi0elXBNE3srwKIyv2ndkoasWp09Jr2hfK89ciAYMu7r5At
         4/+zNtGUtrko2R1hNoKrsEP9HggOn2rm2alf3owbTyh/raNeeWVXq5UZFKz5FE5At1o3
         TSLMWlp1wq0+bT1fV0Oe9Q61ItHbe9g6AsMWYHMQM101ns6HIUSJl5cPYYdgU+I3s7Lj
         gaBrgESsyHxV5t6ArF32OzwLuJEipcOVa/93LaSmvW7U8p0CyAw+AdeGHF0Lu672SWvr
         4XZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=jF35eyuW;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id d16si740582oij.1.2020.01.14.22.37.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Jan 2020 22:37:40 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id 62so1382539pfu.11
        for <kasan-dev@googlegroups.com>; Tue, 14 Jan 2020 22:37:40 -0800 (PST)
X-Received: by 2002:a62:868f:: with SMTP id x137mr29859489pfd.228.1579070259533;
        Tue, 14 Jan 2020 22:37:39 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-8d73-bc9d-5592-cfd7.static.ipv6.internode.on.net. [2001:44b8:1113:6700:8d73:bc9d:5592:cfd7])
        by smtp.gmail.com with ESMTPSA id v13sm20960031pgc.54.2020.01.14.22.37.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Jan 2020 22:37:38 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Cc: linuxppc-dev@lists.ozlabs.org,
	linux-arm-kernel@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-xtensa@linux-xtensa.org,
	x86@kernel.org,
	Daniel Axtens <dja@axtens.net>,
	Daniel Micay <danielmicay@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: [PATCH 2/2] string.h: fix incompatibility between FORTIFY_SOURCE and KASAN
Date: Wed, 15 Jan 2020 17:37:10 +1100
Message-Id: <20200115063710.15796-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200115063710.15796-1-dja@axtens.net>
References: <20200115063710.15796-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=jF35eyuW;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
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

I'm pretty sure this is backwards: we shouldn't be using __builtin_memcpy
when we have a KASAN instrumented file, but we can use __builtin_* - and in
many cases all fortification - in files where we don't have
instrumentation.

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

Remove all the attempted disablement code in arch string headers.

This makes all the tests succeed with FORTIFY_SOURCE enabled.

Cc: Daniel Micay <danielmicay@gmail.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Fixes: 6974f0c4555e ("include/linux/string.h: add the option of fortified string.h functions")
Signed-off-by: Daniel Axtens <dja@axtens.net>

---

Dmitry, this might cause a few new syzkaller splats - I first picked it up
building from a syskaller config. Or it might not, it just depends what gets
replaced with an inline sequence of instructions.

checkpatch complains about some over-long lines, happy to change the format
if anyone has better ideas for how to lay it out.
---
 arch/arm64/include/asm/string.h   |  4 ---
 arch/powerpc/include/asm/string.h |  4 ---
 arch/s390/include/asm/string.h    |  4 ---
 arch/x86/include/asm/string_64.h  |  4 ---
 arch/xtensa/include/asm/string.h  |  3 --
 include/linux/string.h            | 49 +++++++++++++++++++++++--------
 6 files changed, 37 insertions(+), 31 deletions(-)

diff --git a/arch/arm64/include/asm/string.h b/arch/arm64/include/asm/string.h
index b31e8e87a0db..eafb2c4771fc 100644
--- a/arch/arm64/include/asm/string.h
+++ b/arch/arm64/include/asm/string.h
@@ -59,10 +59,6 @@ void memcpy_flushcache(void *dst, const void *src, size_t cnt);
 #define memmove(dst, src, len) __memmove(dst, src, len)
 #define memset(s, c, n) __memset(s, c, n)
 
-#ifndef __NO_FORTIFY
-#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
-#endif
-
 #endif
 
 #endif
diff --git a/arch/powerpc/include/asm/string.h b/arch/powerpc/include/asm/string.h
index b72692702f35..952c5934596b 100644
--- a/arch/powerpc/include/asm/string.h
+++ b/arch/powerpc/include/asm/string.h
@@ -43,10 +43,6 @@ void *__memmove(void *to, const void *from, __kernel_size_t n);
 #define memmove(dst, src, len) __memmove(dst, src, len)
 #define memset(s, c, n) __memset(s, c, n)
 
-#ifndef __NO_FORTIFY
-#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
-#endif
-
 #endif
 
 #ifdef CONFIG_PPC64
diff --git a/arch/s390/include/asm/string.h b/arch/s390/include/asm/string.h
index 4c0690fc5167..e0b66d8c89a1 100644
--- a/arch/s390/include/asm/string.h
+++ b/arch/s390/include/asm/string.h
@@ -75,10 +75,6 @@ extern void *__memmove(void *dest, const void *src, size_t n);
 
 #define __no_sanitize_prefix_strfunc(x) __##x
 
-#ifndef __NO_FORTIFY
-#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
-#endif
-
 #else
 #define __no_sanitize_prefix_strfunc(x) x
 #endif /* defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__) */
diff --git a/arch/x86/include/asm/string_64.h b/arch/x86/include/asm/string_64.h
index 75314c3dbe47..ec63d11e1f04 100644
--- a/arch/x86/include/asm/string_64.h
+++ b/arch/x86/include/asm/string_64.h
@@ -76,10 +76,6 @@ int strcmp(const char *cs, const char *ct);
 #define memmove(dst, src, len) __memmove(dst, src, len)
 #define memset(s, c, n) __memset(s, c, n)
 
-#ifndef __NO_FORTIFY
-#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
-#endif
-
 #endif
 
 #define __HAVE_ARCH_MEMCPY_MCSAFE 1
diff --git a/arch/xtensa/include/asm/string.h b/arch/xtensa/include/asm/string.h
index 89b51a0c752f..8cf04c5a33fb 100644
--- a/arch/xtensa/include/asm/string.h
+++ b/arch/xtensa/include/asm/string.h
@@ -132,9 +132,6 @@ extern void *__memmove(void *__dest, __const__ void *__src, size_t __n);
 #define memmove(dst, src, len) __memmove(dst, src, len)
 #define memset(s, c, n) __memset(s, c, n)
 
-#ifndef __NO_FORTIFY
-#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
-#endif
 #endif
 
 #endif	/* _XTENSA_STRING_H */
diff --git a/include/linux/string.h b/include/linux/string.h
index 3b8e8b12dd37..4364c106355e 100644
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
@@ -505,7 +530,7 @@ __FORTIFY_INLINE char *strcpy(char *p, const char *q)
 	size_t p_size = __builtin_object_size(p, 0);
 	size_t q_size = __builtin_object_size(q, 0);
 	if (p_size == (size_t)-1 && q_size == (size_t)-1)
-		return __builtin_strcpy(p, q);
+		return __underlying_strcpy(p, q);
 	memcpy(p, q, strlen(q) + 1);
 	return p;
 }
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200115063710.15796-3-dja%40axtens.net.
