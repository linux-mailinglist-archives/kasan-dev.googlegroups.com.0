Return-Path: <kasan-dev+bncBCT4XGV33UIBB2X5ZWZQMGQEVCXCEFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id D39A690FAAE
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:59:23 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-375dada31b4sf333745ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:59:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845162; cv=pass;
        d=google.com; s=arc-20160816;
        b=mKMnA7yRUiGBh+xWRWpiogHKV6GvHS3+7SypFq2HSB/8AsoYd9A6BbERtSQzoDf13Q
         Yhd143xJSiMh1zwRkzSwCUSWsiDw9oTko6vdMXmuyQ4NUILuZyMbxL3zc9e+flV1TAs/
         mHRtJt3DmEfRyuKIDPob9Ik9p6fcVwZOVv/ittRNivKEZni09CUMhquQWncPE6WY/SGO
         IgpXyND/ycaK0CziTmeKmzsjkgYSVwCz/1aUT7AtMcqogLCMddbxU0y3RJrdxunkU5O3
         wFD/dc2NPvMgZRggnDhh8WP5ETd2UN+Tb7JZNbdV6nEvPTzxdB8LRpu0GNnwQ56A5r7Q
         4aFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=aWKIB7rJQnhGlNMlyNbtJKKih+qWohgf1FiQ9JwZt4k=;
        fh=OBJ92ZUArtG5+tupDfF7+Lu6VSTRVO4za8oOBZmYRxg=;
        b=p0+FZQnew+YhFWkW1L4JCh3+qeDw6E7dQFe2+LZCGEGuegkUjOpxRCJfnQUEUnmvrJ
         myu1EPn3Judlz1eL/fcNT6cgRO8IRFQdU29gB15ChyS7am7Bq2CAlvAXC0qUd6qP428G
         69vlfQUPPnuEnfdURQo6n5uAlZOdursxO2r840CjPQTcCekkHyc717My8UdmbbY1mXhM
         LphVYHqSARAIT++bbDo2AYubUCJYNLDgIb9Rq7k180WFr8TkdBAMNGoTnJT6RSQgmMOF
         U95y9IJ4T69E0zJgWiOFM2AwJvd9m4vfiXz7v+3zxJnhO9QBHmiEhbcWbFMZvGbX8yim
         InWA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=rgvBO3Vr;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845162; x=1719449962; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aWKIB7rJQnhGlNMlyNbtJKKih+qWohgf1FiQ9JwZt4k=;
        b=ZBZt1qEaQre7QauXa6g+YbIugkG3xpAkwUPiCtnvguoxWBrOb/jw6/x0bPFj89yzkJ
         F56yTUTdUnpXnoW0tOKkYe9VIRrUHeTfyIUtHWkzdLG1bqHz8qQERyiDdpMthGdJ/rnh
         m+ZvxewK3mwTkVe5v+l5PJykVCKzfthzyxBqxlP1TDcDK+sqgmLiTLEl3MfE0qm+jFVC
         KsT9WoFkTSxYfhQ2XiBmvLcd5RmfgWj1pr6HLdz6MrV3MOb+0z0gqZQzeBHncQ/x1jbp
         c5eqWa9e0fU+tjkQTBkRphGHjZFQBNQwqZGOuSPqOf6FdDBzC4lUJPzGqeyKFbfmpahb
         71yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845162; x=1719449962;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aWKIB7rJQnhGlNMlyNbtJKKih+qWohgf1FiQ9JwZt4k=;
        b=NYjV3a2+qC/bUYQjv/jJGJ3Cawx7gsgWCschfnsmrCD1xcy4E4dKkf2XZF9aU5vxl8
         olCCR7dX/piDqa/9RMu1ueM5jJoNfedwioOX5Ihw5BOId3vvQOqv1gEO2rvf/RqZEk27
         UvQNK8MiG6YHSwL+s+e22jwiFQEgxRwLaXOQHExPXBq9bz0jlq9ffc5J2GFIwV41YLGj
         tie9RlEm5MuarBYal6IMtHLZzWI/QkAnN7UxWGgDketeWvnOfvMnsOoUE8my9n2rWPg3
         LsvPiQftC4R8ChXccgQluFSTahnVI0PBI2w3XmgOjpDiayoogNZ24E11XXJlVkkNc8o2
         wQkA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUpr3ngGh0e3IS9BF/p1TNppYWrr0UEECsRgpQotc1Xjq371kW8+Kn0hXy8tTyEw1oLsvvdM1X25Iod4BlrzrtCIB1aLPgRFg==
X-Gm-Message-State: AOJu0YxssneBc5fbvGX1z8oKYPMJY5pLycWDChQtyecxNGwgK7R5lTA9
	DF7IoUIy3VmYfiKNSFZu47F1fYRda16eNOtQDMHDRcTCPRu9Rq7l
X-Google-Smtp-Source: AGHT+IFwuKdw3OJvtNOHLTlx9+8XJmyOQB9ZJH103viecf2GTlUv77M5f9C1wi1DxefhnY21Xfnn1A==
X-Received: by 2002:a05:6e02:3888:b0:375:efb4:372e with SMTP id e9e14a558f8ab-3761f779c1bmr3605355ab.21.1718845162626;
        Wed, 19 Jun 2024 17:59:22 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:216e:b0:375:9d70:4e85 with SMTP id
 e9e14a558f8ab-3762692cc44ls3228125ab.0.-pod-prod-03-us; Wed, 19 Jun 2024
 17:59:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU8lGD1Zz9bIXjlZOd71TwtzZ+lQhF6vFkt0jRzMI1XKf+oZLfuXIoMGc6cHPbcfmo+fsyQ4OgTxC43fu/YZ+6+JhXHXDO5rokYXw==
X-Received: by 2002:a05:6602:6c13:b0:7eb:6a37:89d1 with SMTP id ca18e2360f4ac-7f13ee8fbfbmr492542739f.15.1718845161678;
        Wed, 19 Jun 2024 17:59:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845161; cv=none;
        d=google.com; s=arc-20160816;
        b=V0q1NX/AmKA7buailtfPejAiMP6F1NMYAkq2fNd5FUeY/27fFKCsnWRW2VXf1HR8FO
         YO8bjB4Wl/6z95O0vswuqmVGVWJYGTbsZXcOkN9xm7atnLHPcC97y4TOCFJxFvuwWJSZ
         J2hjNptF6qjLDEwtkhGmPaYHHLDKANJI9cmSjsUobq1ZIq/oTC8k1kQMtDMKkTrsq8Wo
         3sp1vzkFtUtKsM4K++Qefp5DSAuKyswgWtHb7O8gFaHWWzr3UKZqWfHZq89qjkXSxmQo
         oDc/SCpvQZUe++akDxrMaZY1VjQAsXdq2LgzoqY6WgESvvoFKwTS1s+u8qK2UOVHQ9RA
         PXrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=XdNSmijd7vK40Vg1K/0Jgjyzy2nDTat2vYKrruQatSs=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=pcFK8akKsVttlIVJntFq1rQKjFC1VI0CchBfDfdeyZhunD/PkDLbNVwbBQPce6Dn8p
         YcmJSPgV68R2H1OTNl8BIw5HlaB/m2h9m9rt3z38SvYxTVPHl9575DOtDs6fmlMPak0f
         nRdSDBg7x97g0Gabx4xAVK6Um0EOR2TmPOfTPoNCxfAiebCXUlbWHeeq6D1ugQKVjxKq
         GjMA5/52NR8k3/hxCpwQs9gm4YEq55BjhUi2aQ1fbVMFfLDjby4rrRFN/w1d+jHNmRAO
         SsOIVYX0YOTbjFvFiI6xwj04JpJ4CHxCMbaLgty0CfUUfNpVyHSG0P78u2rttiqefbV6
         b3hg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=rgvBO3Vr;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-7ebdba20e5csi77921439f.1.2024.06.19.17.59.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:59:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id EF2C4CE22D6;
	Thu, 20 Jun 2024 00:59:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3B18DC2BBFC;
	Thu, 20 Jun 2024 00:59:18 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:59:17 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + s390-string-add-kmsan-support.patch added to mm-unstable branch
Message-Id: <20240620005918.3B18DC2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=rgvBO3Vr;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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


The patch titled
     Subject: s390/string: add KMSAN support
has been added to the -mm mm-unstable branch.  Its filename is
     s390-string-add-kmsan-support.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/s390-string-add-kmsan-support.patch

This patch will later appear in the mm-unstable branch at
    git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

Before you just go and hit "reply", please:
   a) Consider who else should be cc'ed
   b) Prefer to cc a suitable mailing list as well
   c) Ideally: find the original patch on the mailing list and do a
      reply-to-all to that, adding suitable additional cc's

*** Remember to use Documentation/process/submit-checklist.rst when testing your code ***

The -mm tree is included into linux-next via the mm-everything
branch at git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm
and is updated there every 2-3 working days

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: s390/string: add KMSAN support
Date: Wed, 19 Jun 2024 17:44:06 +0200

Add KMSAN support for the s390 implementations of the string functions. 
Do this similar to how it's already done for KASAN, except that the
optimized memset{16,32,64}() functions need to be disabled: it's important
for KMSAN to know that they initialized something.

The way boot code is built with regard to string functions is problematic,
since most files think it's configured with sanitizers, but boot/string.c
doesn't.  This creates various problems with the memset64() definitions,
depending on whether the code is built with sanitizers or fortify.  This
should probably be streamlined, but in the meantime resolve the issues by
introducing the IN_BOOT_STRING_C macro, similar to the existing
IN_ARCH_STRING_C macro.

Link: https://lkml.kernel.org/r/20240619154530.163232-32-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: David Rientjes <rientjes@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: <kasan-dev@googlegroups.com>
Cc: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Masami Hiramatsu (Google) <mhiramat@kernel.org>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Steven Rostedt (Google) <rostedt@goodmis.org>
Cc: Sven Schnelle <svens@linux.ibm.com>
Cc: Vasily Gorbik <gor@linux.ibm.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 arch/s390/boot/string.c        |   16 ++++++++++++++++
 arch/s390/include/asm/string.h |   20 +++++++++++++++-----
 2 files changed, 31 insertions(+), 5 deletions(-)

--- a/arch/s390/boot/string.c~s390-string-add-kmsan-support
+++ a/arch/s390/boot/string.c
@@ -1,11 +1,18 @@
 // SPDX-License-Identifier: GPL-2.0
+#define IN_BOOT_STRING_C 1
 #include <linux/ctype.h>
 #include <linux/kernel.h>
 #include <linux/errno.h>
 #undef CONFIG_KASAN
 #undef CONFIG_KASAN_GENERIC
+#undef CONFIG_KMSAN
 #include "../lib/string.c"
 
+/*
+ * Duplicate some functions from the common lib/string.c
+ * instead of fully including it.
+ */
+
 int strncmp(const char *cs, const char *ct, size_t count)
 {
 	unsigned char c1, c2;
@@ -22,6 +29,15 @@ int strncmp(const char *cs, const char *
 	return 0;
 }
 
+void *memset64(uint64_t *s, uint64_t v, size_t count)
+{
+	uint64_t *xs = s;
+
+	while (count--)
+		*xs++ = v;
+	return s;
+}
+
 char *skip_spaces(const char *str)
 {
 	while (isspace(*str))
--- a/arch/s390/include/asm/string.h~s390-string-add-kmsan-support
+++ a/arch/s390/include/asm/string.h
@@ -15,15 +15,12 @@
 #define __HAVE_ARCH_MEMCPY	/* gcc builtin & arch function */
 #define __HAVE_ARCH_MEMMOVE	/* gcc builtin & arch function */
 #define __HAVE_ARCH_MEMSET	/* gcc builtin & arch function */
-#define __HAVE_ARCH_MEMSET16	/* arch function */
-#define __HAVE_ARCH_MEMSET32	/* arch function */
-#define __HAVE_ARCH_MEMSET64	/* arch function */
 
 void *memcpy(void *dest, const void *src, size_t n);
 void *memset(void *s, int c, size_t n);
 void *memmove(void *dest, const void *src, size_t n);
 
-#ifndef CONFIG_KASAN
+#if !defined(CONFIG_KASAN) && !defined(CONFIG_KMSAN)
 #define __HAVE_ARCH_MEMCHR	/* inline & arch function */
 #define __HAVE_ARCH_MEMCMP	/* arch function */
 #define __HAVE_ARCH_MEMSCAN	/* inline & arch function */
@@ -36,6 +33,9 @@ void *memmove(void *dest, const void *sr
 #define __HAVE_ARCH_STRNCPY	/* arch function */
 #define __HAVE_ARCH_STRNLEN	/* inline & arch function */
 #define __HAVE_ARCH_STRSTR	/* arch function */
+#define __HAVE_ARCH_MEMSET16	/* arch function */
+#define __HAVE_ARCH_MEMSET32	/* arch function */
+#define __HAVE_ARCH_MEMSET64	/* arch function */
 
 /* Prototypes for non-inlined arch strings functions. */
 int memcmp(const void *s1, const void *s2, size_t n);
@@ -44,7 +44,7 @@ size_t strlcat(char *dest, const char *s
 char *strncat(char *dest, const char *src, size_t n);
 char *strncpy(char *dest, const char *src, size_t n);
 char *strstr(const char *s1, const char *s2);
-#endif /* !CONFIG_KASAN */
+#endif /* !defined(CONFIG_KASAN) && !defined(CONFIG_KMSAN) */
 
 #undef __HAVE_ARCH_STRCHR
 #undef __HAVE_ARCH_STRNCHR
@@ -74,20 +74,30 @@ void *__memset16(uint16_t *s, uint16_t v
 void *__memset32(uint32_t *s, uint32_t v, size_t count);
 void *__memset64(uint64_t *s, uint64_t v, size_t count);
 
+#ifdef __HAVE_ARCH_MEMSET16
 static inline void *memset16(uint16_t *s, uint16_t v, size_t count)
 {
 	return __memset16(s, v, count * sizeof(v));
 }
+#endif
 
+#ifdef __HAVE_ARCH_MEMSET32
 static inline void *memset32(uint32_t *s, uint32_t v, size_t count)
 {
 	return __memset32(s, v, count * sizeof(v));
 }
+#endif
 
+#ifdef __HAVE_ARCH_MEMSET64
+#ifdef IN_BOOT_STRING_C
+void *memset64(uint64_t *s, uint64_t v, size_t count);
+#else
 static inline void *memset64(uint64_t *s, uint64_t v, size_t count)
 {
 	return __memset64(s, v, count * sizeof(v));
 }
+#endif
+#endif
 
 #if !defined(IN_ARCH_STRING_C) && (!defined(CONFIG_FORTIFY_SOURCE) || defined(__NO_FORTIFY))
 
_

Patches currently in -mm which might be from iii@linux.ibm.com are

ftrace-unpoison-ftrace_regs-in-ftrace_ops_list_func.patch
kmsan-make-the-tests-compatible-with-kmsanpanic=1.patch
kmsan-disable-kmsan-when-deferred_struct_page_init-is-enabled.patch
kmsan-increase-the-maximum-store-size-to-4096.patch
kmsan-fix-is_bad_asm_addr-on-arches-with-overlapping-address-spaces.patch
kmsan-fix-kmsan_copy_to_user-on-arches-with-overlapping-address-spaces.patch
kmsan-remove-a-useless-assignment-from-kmsan_vmap_pages_range_noflush.patch
kmsan-remove-an-x86-specific-include-from-kmsanh.patch
kmsan-expose-kmsan_get_metadata.patch
kmsan-export-panic_on_kmsan.patch
kmsan-allow-disabling-kmsan-checks-for-the-current-task.patch
kmsan-introduce-memset_no_sanitize_memory.patch
kmsan-support-slab_poison.patch
kmsan-use-align_down-in-kmsan_get_metadata.patch
kmsan-do-not-round-up-pg_data_t-size.patch
mm-slub-let-kmsan-access-metadata.patch
mm-slub-disable-kmsan-when-checking-the-padding-bytes.patch
mm-kfence-disable-kmsan-when-checking-the-canary.patch
lib-zlib-unpoison-dfltcc-output-buffers.patch
kmsan-accept-ranges-starting-with-0-on-s390.patch
s390-boot-turn-off-kmsan.patch
s390-use-a-larger-stack-for-kmsan.patch
s390-boot-add-the-kmsan-runtime-stub.patch
s390-checksum-add-a-kmsan-check.patch
s390-cpacf-unpoison-the-results-of-cpacf_trng.patch
s390-cpumf-unpoison-stcctm-output-buffer.patch
s390-diag-unpoison-diag224-output-buffer.patch
s390-ftrace-unpoison-ftrace_regs-in-kprobe_ftrace_handler.patch
s390-irqflags-do-not-instrument-arch_local_irq_-with-kmsan.patch
s390-mm-define-kmsan-metadata-for-vmalloc-and-modules.patch
s390-string-add-kmsan-support.patch
s390-traps-unpoison-the-kernel_stack_overflows-pt_regs.patch
s390-uaccess-add-kmsan-support-to-put_user-and-get_user.patch
s390-uaccess-add-the-missing-linux-instrumentedh-include.patch
s390-unwind-disable-kmsan-checks.patch
s390-kmsan-implement-the-architecture-specific-functions.patch
kmsan-enable-on-s390.patch

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005918.3B18DC2BBFC%40smtp.kernel.org.
