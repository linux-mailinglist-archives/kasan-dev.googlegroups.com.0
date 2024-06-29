Return-Path: <kasan-dev+bncBCT4XGV33UIBB6HD7WZQMGQERA2W4VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id D7CF791CAA4
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:21 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-1fa2e9e8762sf8063325ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628280; cv=pass;
        d=google.com; s=arc-20160816;
        b=oAHsswz4nAgipiWz1FmlJNjmznX5tOMp+FqZnSwylTJWx7lYC1U+cl6hvTVJODgkQG
         Gv9pFaHcrynwJRJ1JoPb6Wimpfsm++YYiz6N4M7vrXjpJRJ9NUEZjzRaD2haf7eorH9+
         x6xwCWn263UVNra5IDYKsT4V3tY79H0vG+T7A5Y0M2qY7TDJQa4C5dkkXcp21W5bzGEu
         QMVeEd8XelwO+IWLJxVS5eekO4yw2uZZis+ajbVaBOHT268JCN2DIBapJ2ZDXq/frtNc
         sle4ak0P5NRLD3Sfiurmv4JZqCG3CSfUtK9Jt77jT2mq8xpvhCfdjRezg9nA44C631UA
         9j0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=gmsDrnHf5CtGI1k232uv9GnaznRN5PzKaRIZ7y+nFTU=;
        fh=NoOVrX9eJDwRj+cZtlYuAoFMQnI6YOkHKeqvJu0+Myc=;
        b=M4V/B+n4QWpCa/hV9rvZJXgQkaSvVauAdLp18luCgLR3jku38zB9PvLm5t54nYQ59e
         u+l3hR3Mni0K9iypp0SAyiQg2T03JjFUhcag4T2KaYkH7W91njBthRNNGbXbPcLhezUp
         D/QEvUSUsqP0i7lfGIyY2vFvl7yGI7II2Pdt1I3yAf4plNll3xceNkPpTDC6/DrWbzry
         7LNUcqttOxTjMwtEUeBuVl+/3XQyu0zonu3mCD/MiSXKohzaL3bqqoJ9gsaQgD3807BR
         viS7E1Nssurb7A4WbmXGRcxvLMUUTzxTmI1+KryLGVB8SpX6d2W67q3twe0l0MdHY9Ra
         8j7Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=inD040qo;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628280; x=1720233080; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gmsDrnHf5CtGI1k232uv9GnaznRN5PzKaRIZ7y+nFTU=;
        b=Vs05mL2mHtp/VQeWWU3zAnE1NpHksyhuqIAxILXMTphUHQi3YiKBNsKFE21u22ER7D
         bNrg+c+9tkBowjyHF5atTT9H1+mzps829i8QxcNWNL92HHM6a/UfAmq2edZyBYLWYjKH
         sC5UiFxN2bYOQoIvs/fGhgkh3TWvqfp4CsclIYe4xeFbh9bnciwu/gMg+fWOnd6IQ20g
         ZzKFWBhinvPM/DAm1dAZUNjPrNZtmPqgLrsPeL5QLVFIWceSqMczYd3SujA1OdElSApR
         CHkt67ayt8OlMTGlLT/QscZNcRfb6uYpj7E2xgzPcp2GFrYJGm+aA0w3x4SaIa5l1hlx
         PGQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628280; x=1720233080;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gmsDrnHf5CtGI1k232uv9GnaznRN5PzKaRIZ7y+nFTU=;
        b=Arqs7x7YT0A8EmlY+mg7/1+JZqu69QGd3KQm7FepKT+3h4T+XUp1d5NWSOo7YJFm5J
         n6RzmJKHIaBTFGTJ+uw3ihpnnEbMRngas4+aKezuEFwf9eOuXb03UdiBlrbstb0qvJVX
         /B4lKjGeSOSf9VyxZnEYJ3RLv4IfrEeFVknziVTZv5MDMOC30DWPlx/BuGMN2drJJZxE
         ic3d/yAXb7CQQhaiWTIRjYruHBAoJCg+XJu970nYpWhOlDKKNvwrWgZS650epktD0/si
         1sYU+UipdFhujP47IljsTvgK9OTjBcJdeGvSsWE+Ikhn6CKXiPSzrDvu5/w9ZAHzabLq
         qsug==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWzT2ymO503HUhng/fWfTt48yOoOvdgiMcWehFAgqhBDkimkYfu9RIK/LNeBlNDWALPqqu6Fei9In6Wsdc76DWoJbtmkv8zHg==
X-Gm-Message-State: AOJu0YxUXSTK1RswDVMWIbtTG1e+PFjLqtUBFS3Lbi1cGCbdTABOoz2j
	Tu94T/nwtoUOpjhlO3kNMDb4oMXh5CMefFtye6dpVDcfFx7xyPhs
X-Google-Smtp-Source: AGHT+IGxnCqq0XUFZgSrGPhSnhDgjLkBDhCjmS+GOnGSnzZ1aeiHyX1q6Muc4oanr6m2/MJ0UeYGhA==
X-Received: by 2002:a17:902:c212:b0:1f9:f559:d8c8 with SMTP id d9443c01a7336-1fa1d3de5f8mr150306485ad.4.1719628280389;
        Fri, 28 Jun 2024 19:31:20 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2343:b0:1f7:38a2:f1eb with SMTP id
 d9443c01a7336-1fac478c22fls7624475ad.1.-pod-prod-03-us; Fri, 28 Jun 2024
 19:31:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXNKs5AlEVnOp1OCF0NrWwYKgktqJPMJknEFoRQudAMr02n25DIS99IJSGEpopb3eSVKAbMvM+un+l4n+Ic9W4fordWX4kBp/03Fg==
X-Received: by 2002:a17:902:d2ce:b0:1f6:e20f:86b4 with SMTP id d9443c01a7336-1fa1d683d39mr204011015ad.61.1719628279073;
        Fri, 28 Jun 2024 19:31:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628279; cv=none;
        d=google.com; s=arc-20160816;
        b=AnXnxhH6nvABYdM6QcmgPuI6vGLudUgGQLw9Ht0AjdZiySFDWNHQRNeoT3KD7nnos9
         g/6pviu41qjndpsAnPDmZ6UZi8gjseIqUN957JGJSBQK6/rKm4134BqoVX6Y4dkRHXE2
         yZkhlUOtM211VAqSvncMTusG1xHFd1zM0GnU7q7XXv5lBg5TlL7YW3BlW3HuC3YLzrpV
         EAqBHEHZrbYVPajyslTXJart+Ep/fWFYYkb8K9dK3iGSHdUHQBmKjgzD2YyJSJiFgXFB
         R8bM4JdMs5af93GSVrZR7wADZ4r0s0W6Q1vBJltiRRYuTYj61oWPQym3G6AChmEKJ/Cg
         z8Fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=9w4rya6H6qm8KSTo2j9lTTqi1K8U/Trh+n6HZ7TJuhs=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=fdXNR1crajHs0lEbzgBMBhaTdU3g3Ir7RURZUD5Yxu1l/+U/zHnbYPF82shI9foscj
         IOZathcIEdFJiG5dMNKOpV/l78nRhZvvYpbpBbqzk6Jj9F5RnHUMoEYH441vVZ1hf1+1
         NRoRu5F3cM7egk+UrCbhhNLWxx7TSTlbjycezh3WO+vcehDE3YdqkCUfR45MdUhoP3/r
         jEHzlxFp0fQZjjZuQ/C1HO4dqB43klwozXX00WiO7VeG0/ew3gYIxqGFdZa0R0lpKloS
         DH2yYjfNg2NVUBfvBLGaWsV5eqVRfWlJ0WIxgimmR6sds9SbR3ISIvHXqOJik0bQJNve
         YFGQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=inD040qo;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1fac12f6710si1176065ad.2.2024.06.28.19.31.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 8592A622C6;
	Sat, 29 Jun 2024 02:31:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2C81DC116B1;
	Sat, 29 Jun 2024 02:31:18 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:31:17 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] s390-string-add-kmsan-support.patch removed from -mm tree
Message-Id: <20240629023118.2C81DC116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=inD040qo;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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


The quilt patch titled
     Subject: s390/string: add KMSAN support
has been removed from the -mm tree.  Its filename was
     s390-string-add-kmsan-support.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: s390/string: add KMSAN support
Date: Fri, 21 Jun 2024 13:35:16 +0200

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

Link: https://lkml.kernel.org/r/20240621113706.315500-33-iii@linux.ibm.com
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


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023118.2C81DC116B1%40smtp.kernel.org.
