Return-Path: <kasan-dev+bncBDE6RCFOWIARB6MG2D2QKGQE5P6LL3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id D41171C8B46
	for <lists+kasan-dev@lfdr.de>; Thu,  7 May 2020 14:47:54 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id z8sf5617532qki.13
        for <lists+kasan-dev@lfdr.de>; Thu, 07 May 2020 05:47:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588855674; cv=pass;
        d=google.com; s=arc-20160816;
        b=eSAx3Mw2L4X0mTbLfaaW0z9zbYPcCf81IVn6TE31lUUJTbl479jownCk92ecM0eeYA
         bIep3MHJ0k5pG9sHok7wbt2vg8pxfYdKNpxb4Iw0BYrzxpXISbzaDPoMAkgcbsA95CcM
         a1UK/5kdOxhCdL8L2bTnZCpHmsVDay72u99F7I4sfkoDkPEFMR4aMprRGmG4Oof5S0G7
         Dn/KUqlXlEf7rO6/StlxFr3n0WKcCOlns1PJSNr8HWc8fx4e9nruE2rcFUcOpLS7DF5c
         5VEil3r+9Aased1G//WtIhII+NT4KF3GBPHDptvJYjrjcFZgCYtvBwPn2CRLzFvS2YPg
         LBDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hyL0OdbpCjIkuamCzuDM9qR3viS0k8el2ntE4s8F3pU=;
        b=AwHP2kwapxpbbn/2xZPm3yqQjWmlZEXh44wxukZwoXBdJdHFceFq5jRqQPOnPs6K2b
         eD4rTujihe4tBjl1VlWzllWt9r3nqFN3kF7pA5TH4s62v1jxok032ebsfLZHuUmT+fFo
         4naLjLuEUR66txlu6gYTGTbG95QCJb1w7VunNi0b1iC28cDUk2WjAb0vDRd86jMgFMuk
         WOCKQAkDgxPlpLqUtxkxoKQz+wrxrZZ4OZ/lwBWJtRflXaEByhJq/AjcooqSbC01hS0z
         N6O/t+stQU2CuBDvFsT87R94Ucuo4m//Y3yi9ywPyYnRWHRwjIm17bGoUCWyy/+frO/j
         aoPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=loBHrv8y;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hyL0OdbpCjIkuamCzuDM9qR3viS0k8el2ntE4s8F3pU=;
        b=LaxZvlHPf8n20kLYVfDHHiaY8LBo1xv+TaD0mMbMtySIS0P5Q9/oulaQiwj/R7ugWc
         GLw5VWkRWeh8IxPX51nZw6ayCGRnl2lodLhC6GenrVj9o6S3jF2pWRtsKgK/xAXPe0Ae
         lreMUXYaRgDbSs387Pgq7J9w/BItVa8aWcwRbiiaEKaWh23ROlAamhDv+ONG9ZiFGDOd
         7NO/EUq9xvyYqwZMF1rqzk11ECErnQq8eW43OGsHcxmDFNJNLuRAwjBKLCk+e1UkysV9
         e5AshKQvuG5WsaaGbhbwVBbQ+376K1uXZROp1YsqsvA+mY468xbRmqYX8OwtQkZ21zCq
         qo4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hyL0OdbpCjIkuamCzuDM9qR3viS0k8el2ntE4s8F3pU=;
        b=EmJ56DQ4f1XQ6EeSvWEfqOnkXUlbkxmYtrCSw39G66uxhvn1ueFpvYC8SkxxARUrNx
         vCXWb4rOK37q8NkPu/uLln9c8Blmu7uyMNG8v1ytwjZ0K4a1v7VXHYpQVWsbaaLmYDX4
         xo+Tn7/bW20NjCRoQNBS7UcbjxJgy7TigmRf5uGvnXImndDb/2sHysNCeV/oYLlaLmHU
         Zmpkj6WeeTOGTG8eUjYlJOJOA0mjYV0qyb1oEjQPzrNyW0fOAsSHSk85jr0UmRF/4CDs
         uUK+NLZR+oJEdRXmrchmvLoK4s4OJmFuNwTyjL/r+VlPnDhflBpK5uOQgWkcigHARQ9A
         rWMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYYdYiXLelCouS9m2w66+RWteASjnozavNb/wpNxAAjLziGCFvx
	XhdzNdtGLtMDz37Xs2p6LWo=
X-Google-Smtp-Source: APiQypIIv4j9YD7ZQaJx7045flMRS+EBp287AxZeRTNAIEpojcCnWQyvd+/aaah1zeNcauMdJrJksA==
X-Received: by 2002:ac8:66d8:: with SMTP id m24mr13819433qtp.175.1588855673805;
        Thu, 07 May 2020 05:47:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:3fd5:: with SMTP id w21ls4237450qth.7.gmail; Thu, 07 May
 2020 05:47:53 -0700 (PDT)
X-Received: by 2002:a1c:ed0b:: with SMTP id l11mr10961003wmh.31.1588855673441;
        Thu, 07 May 2020 05:47:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588855673; cv=none;
        d=google.com; s=arc-20160816;
        b=hfYogbWcXT3oPOj6WWi3OAnkFNFQoYuDIJD/ixTxWXpRPBxnF/L3qcqLtmLDO/Xfh/
         8qvvYWqiVORXg+CsQDtcnSy+SkYJ6AWaUuo4oQ8g6TdDQHzjCCaRvaQXPO2r5ky95SAH
         3xjqPT+vOHs2f/52YEBZdiuOV7W3+XQtRMuOOzsCJD57junAIFUwdKmspYkaf+4JWj3o
         HFaBotXCqlMjPjqN6dfJIPLpAsObUz9py1C6jS5xYbt/LBG9wssAed8FZI4uzqcDw/jB
         7tUFVrlrveRf8Nawugz1/qVToe/t0C1GvLto0gumZW1BI3Kd8wVEVYLTQfb4ZRDk9GrL
         F31w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YYkNToxGZUMGPX9WJcRr1Cp2dwvtaKoN0WkoOFKKBiE=;
        b=AulAjT9UgyY65bZQj8RphsCqzk7qjtReKbnY4iY77jjcVt94+OvgfTLIXZlp5XXdSL
         VVgqAVvv1XsKhMHtFNy94ySRHIKNJFiANe9u5TdI52GziuriozhqOVV+8aRwjFVSRtDW
         EbBCMg6e/+YChSbhrCUdYpfqTpVtfKaXgX1nVtTvVw77eaZb7YKprW25OIIfPBJss1fQ
         pNdMhpbn4OhHMrJa9zt/54wan3b2QQldt7stZ8wXsRDc+vt1NKtC8uoP07UNmeUVtgjO
         Af3wN8VWne0aSk6G0U0Z+HS25q0glPzWbsI4LnUgLduzt0uMd0aIngPq6xGdoKqulnq6
         lQ4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=loBHrv8y;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x244.google.com (mail-lj1-x244.google.com. [2a00:1450:4864:20::244])
        by gmr-mx.google.com with ESMTPS id x11si235337wmi.1.2020.05.07.05.47.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 May 2020 05:47:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) client-ip=2a00:1450:4864:20::244;
Received: by mail-lj1-x244.google.com with SMTP id f18so6115618lja.13
        for <kasan-dev@googlegroups.com>; Thu, 07 May 2020 05:47:53 -0700 (PDT)
X-Received: by 2002:a2e:7508:: with SMTP id q8mr8523566ljc.234.1588855672792;
        Thu, 07 May 2020 05:47:52 -0700 (PDT)
Received: from localhost.localdomain (c-f3d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.243])
        by smtp.gmail.com with ESMTPSA id b4sm3730126lfo.33.2020.05.07.05.47.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 May 2020 05:47:52 -0700 (PDT)
From: Linus Walleij <linus.walleij@linaro.org>
To: Florian Fainelli <f.fainelli@gmail.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Russell King <linux@armlinux.org.uk>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: linux-arm-kernel@lists.infradead.org,
	Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Linus Walleij <linus.walleij@linaro.org>
Subject: [PATCH 2/5 v8] ARM: Replace string mem* functions for KASan
Date: Thu,  7 May 2020 14:45:19 +0200
Message-Id: <20200507124522.171323-3-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.25.4
In-Reply-To: <20200507124522.171323-1-linus.walleij@linaro.org>
References: <20200507124522.171323-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=loBHrv8y;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

From: Andrey Ryabinin <aryabinin@virtuozzo.com>

Functions like memset()/memmove()/memcpy() do a lot of memory
accesses.

If a bad pointer is passed to one of these functions it is important
to catch this. Compiler instrumentation cannot do this since these
functions are written in assembly.

KASan replaces these memory functions with instrumented variants.

The original functions are declared as weak symbols so that
the strong definitions in mm/kasan/kasan.c can replace them.

The original functions have aliases with a '__' prefix in their
name, so we can call the non-instrumented variant if needed.

We must use __memcpy()/__memset() in place of memcpy()/memset()
when we copy .data to RAM and when we clear .bss, because
kasan_early_init cannot be called before the initialization of
.data and .bss.

For the kernel compression and EFI libstub's custom string
libraries we need a special quirk: even if these are built
without KASan enabled, they rely on the global headers for their
custom string libraries, which means that e.g. memcpy()
will be defined to __memcpy() and we get link failures.
Since these implementations are written i C rather than
assembly we use e.g. __alias(memcpy) to redirected any
users back to the local implementation.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Reported-by: Russell King - ARM Linux <linux@armlinux.org.uk>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
---
ChangeLog v7->v8:
- Use the less invasive version of handling the global redefines
  of the string functions in the decompressor: __alias() the
  functions locally in the library.
- Put in some more comments so readers of the code knows what
  is going on.
ChangeLog v6->v7:
- Move the hacks around __SANITIZE_ADDRESS__ into this file
- Edit the commit message
- Rebase on the other v2 patches
---
 arch/arm/boot/compressed/string.c | 19 +++++++++++++++++++
 arch/arm/include/asm/string.h     | 21 +++++++++++++++++++++
 arch/arm/kernel/head-common.S     |  4 ++--
 arch/arm/lib/memcpy.S             |  3 +++
 arch/arm/lib/memmove.S            |  5 ++++-
 arch/arm/lib/memset.S             |  3 +++
 6 files changed, 52 insertions(+), 3 deletions(-)

diff --git a/arch/arm/boot/compressed/string.c b/arch/arm/boot/compressed/string.c
index ade5079bebbf..8c0fa276d994 100644
--- a/arch/arm/boot/compressed/string.c
+++ b/arch/arm/boot/compressed/string.c
@@ -7,6 +7,25 @@
 
 #include <linux/string.h>
 
+/*
+ * The decompressor is built without KASan but uses the same redirects as the
+ * rest of the kernel when CONFIG_KASAN is enabled, defining e.g. memcpy()
+ * to __memcpy() but since we are not linking with the main kernel string
+ * library in the decompressor, that will lead to link failures.
+ *
+ * Undefine KASan's versions, define the wrapped functions and alias them to
+ * the right names so that when e.g. __memcpy() appear in the code, it will
+ * still be linked to this local version of memcpy().
+ */
+#ifdef CONFIG_KASAN
+#undef memcpy
+#undef memmove
+#undef memset
+void *__memcpy(void *__dest, __const void *__src, size_t __n) __alias(memcpy);
+void *__memmove(void *__dest, __const void *__src, size_t count) __alias(memmove);
+void *__memset(void *s, int c, size_t count) __alias(memset);
+#endif
+
 void *memcpy(void *__dest, __const void *__src, size_t __n)
 {
 	int i = 0;
diff --git a/arch/arm/include/asm/string.h b/arch/arm/include/asm/string.h
index 111a1d8a41dd..947f93037d87 100644
--- a/arch/arm/include/asm/string.h
+++ b/arch/arm/include/asm/string.h
@@ -5,6 +5,9 @@
 /*
  * We don't do inline string functions, since the
  * optimised inline asm versions are not small.
+ *
+ * The __underscore versions of some functions are for KASan to be able
+ * to replace them with instrumented versions.
  */
 
 #define __HAVE_ARCH_STRRCHR
@@ -15,15 +18,18 @@ extern char * strchr(const char * s, int c);
 
 #define __HAVE_ARCH_MEMCPY
 extern void * memcpy(void *, const void *, __kernel_size_t);
+extern void *__memcpy(void *dest, const void *src, __kernel_size_t n);
 
 #define __HAVE_ARCH_MEMMOVE
 extern void * memmove(void *, const void *, __kernel_size_t);
+extern void *__memmove(void *dest, const void *src, __kernel_size_t n);
 
 #define __HAVE_ARCH_MEMCHR
 extern void * memchr(const void *, int, __kernel_size_t);
 
 #define __HAVE_ARCH_MEMSET
 extern void * memset(void *, int, __kernel_size_t);
+extern void *__memset(void *s, int c, __kernel_size_t n);
 
 #define __HAVE_ARCH_MEMSET32
 extern void *__memset32(uint32_t *, uint32_t v, __kernel_size_t);
@@ -39,4 +45,19 @@ static inline void *memset64(uint64_t *p, uint64_t v, __kernel_size_t n)
 	return __memset64(p, v, n * 8, v >> 32);
 }
 
+/*
+ * For files that are not instrumented (e.g. mm/slub.c) we
+ * must use non-instrumented versions of the mem*
+ * functions named __memcpy() etc. All such kernel code has
+ * been tagged with KASAN_SANITIZE_file.o = n, which means
+ * that the address sanitization argument isn't passed to the
+ * compiler, and __SANITIZE_ADDRESS__ is not set. As a result
+ * these defines kick in.
+ */
+#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
+#define memcpy(dst, src, len) __memcpy(dst, src, len)
+#define memmove(dst, src, len) __memmove(dst, src, len)
+#define memset(s, c, n) __memset(s, c, n)
+#endif
+
 #endif
diff --git a/arch/arm/kernel/head-common.S b/arch/arm/kernel/head-common.S
index 4a3982812a40..6840c7c60a85 100644
--- a/arch/arm/kernel/head-common.S
+++ b/arch/arm/kernel/head-common.S
@@ -95,7 +95,7 @@ __mmap_switched:
  THUMB(	ldmia	r4!, {r0, r1, r2, r3} )
  THUMB(	mov	sp, r3 )
 	sub	r2, r2, r1
-	bl	memcpy				@ copy .data to RAM
+	bl	__memcpy			@ copy .data to RAM
 #endif
 
    ARM(	ldmia	r4!, {r0, r1, sp} )
@@ -103,7 +103,7 @@ __mmap_switched:
  THUMB(	mov	sp, r3 )
 	sub	r2, r1, r0
 	mov	r1, #0
-	bl	memset				@ clear .bss
+	bl	__memset			@ clear .bss
 
 	ldmia	r4, {r0, r1, r2, r3}
 	str	r9, [r0]			@ Save processor ID
diff --git a/arch/arm/lib/memcpy.S b/arch/arm/lib/memcpy.S
index 09a333153dc6..ad4625d16e11 100644
--- a/arch/arm/lib/memcpy.S
+++ b/arch/arm/lib/memcpy.S
@@ -58,6 +58,8 @@
 
 /* Prototype: void *memcpy(void *dest, const void *src, size_t n); */
 
+.weak memcpy
+ENTRY(__memcpy)
 ENTRY(mmiocpy)
 ENTRY(memcpy)
 
@@ -65,3 +67,4 @@ ENTRY(memcpy)
 
 ENDPROC(memcpy)
 ENDPROC(mmiocpy)
+ENDPROC(__memcpy)
diff --git a/arch/arm/lib/memmove.S b/arch/arm/lib/memmove.S
index b50e5770fb44..fd123ea5a5a4 100644
--- a/arch/arm/lib/memmove.S
+++ b/arch/arm/lib/memmove.S
@@ -24,12 +24,14 @@
  * occurring in the opposite direction.
  */
 
+.weak memmove
+ENTRY(__memmove)
 ENTRY(memmove)
 	UNWIND(	.fnstart			)
 
 		subs	ip, r0, r1
 		cmphi	r2, ip
-		bls	memcpy
+		bls	__memcpy
 
 		stmfd	sp!, {r0, r4, lr}
 	UNWIND(	.fnend				)
@@ -222,3 +224,4 @@ ENTRY(memmove)
 18:		backward_copy_shift	push=24	pull=8
 
 ENDPROC(memmove)
+ENDPROC(__memmove)
diff --git a/arch/arm/lib/memset.S b/arch/arm/lib/memset.S
index 6ca4535c47fb..0e7ff0423f50 100644
--- a/arch/arm/lib/memset.S
+++ b/arch/arm/lib/memset.S
@@ -13,6 +13,8 @@
 	.text
 	.align	5
 
+.weak memset
+ENTRY(__memset)
 ENTRY(mmioset)
 ENTRY(memset)
 UNWIND( .fnstart         )
@@ -132,6 +134,7 @@ UNWIND( .fnstart            )
 UNWIND( .fnend   )
 ENDPROC(memset)
 ENDPROC(mmioset)
+ENDPROC(__memset)
 
 ENTRY(__memset32)
 UNWIND( .fnstart         )
-- 
2.25.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200507124522.171323-3-linus.walleij%40linaro.org.
