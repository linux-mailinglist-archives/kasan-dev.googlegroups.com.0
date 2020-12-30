Return-Path: <kasan-dev+bncBDTZTRGMXIFBBFXVWH7QKGQEND6T3LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id D2C642E78CB
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Dec 2020 14:03:19 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id j22sf11840887otq.16
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Dec 2020 05:03:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609333398; cv=pass;
        d=google.com; s=arc-20160816;
        b=hSEOOOKJg1rPOhhSNavvzkc9jUulLAAClNws3/7UdOMKqKURYUtOeC5Hnj4jWgLG4O
         FiGNJ0VyI+rigK2xbEkrZ/1Q7uJOL85AfSSruEEXRgdDfzeWd1SkeqiXsHwJmQdeWXsH
         HO1nY9G0hwup5oFIG6LdP5qoBL6r/ah2y5HWvZVtv+vVrNns4m8REqBZYXIOs9fv2u6a
         ZEHyi/tLM5kReBuYfIFmpJu+fBPqFr2SmLRptgcDT70KuSLpQpg8tiNiH0I21ssGqB6m
         dnYjm3sxeQ4jBXsr/4dHFeB5MR+0mltloY5RjemEyQhuxCF53yVFCSqEfE2MDkKqtASf
         D2Ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=IXolCAxO7B2s/+kq2Jq963to/0AWbOP1AZfv6Ipvhjo=;
        b=mXJp7AacmWyQ5KgANe4Zie7oDFXYUw6IdHc2YIOKgL008UiWdC3TdUyes2xNiOE5jT
         m5Ta7x+sATcBSyOBFjesNkOuLdtSGCKJe4hcQVumAlhKTV53YOJjb1uzGrWmRr47Mb6x
         nkxOqHXzVtoVWFEJYeOpdn6lMO+vV1EgP0dI9AXeJeQgepgBbvgXLHNv1uuC9AnWMb5t
         ihE6pCDtH6qBUWYwCC0qh+7iAI2FbHltr3Hvld9TWRxZRv6Jkl/obQpQtWzkCuTkWRP+
         /8mEJPtFwyQTJp3YeYw0g6uGyuuIJxaDSioIAYzql/r0pIl0MO84gX4LH2ykGlwOJStc
         W2Uw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NC1TE7S+;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IXolCAxO7B2s/+kq2Jq963to/0AWbOP1AZfv6Ipvhjo=;
        b=DwVmfWrATKiWOjB8iPvtnxA2zrNiytK0B59HI65Bc/NPxjtrEST1urSTpIQiT5elH+
         3V/hU1RjHetOAlvieiFKqeJBf39gF8jRAObdGLtaPL5g5uzQ9wiZnelKVFNjF0QswERh
         vc+bnySZa+pEXSqRjWV7rpt+GYXJ2zW9aD0v3hnmUGcuJdqwluLBi9MKx9ylb2EmpDAj
         XBxg2U17RiqlAouvmCkPC+uNgDazaCrAsi+/jsiFWmpRGKDgrrUFL2IFuOyTWtl4DIZb
         7XlSlYzPrGCwluRVRQ0tTelhtTDY9/Rpf7lmtSfdzNW8MXm93EA21/V/IqUcKp6qNJ72
         XLzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IXolCAxO7B2s/+kq2Jq963to/0AWbOP1AZfv6Ipvhjo=;
        b=iZKN0av+MbH77xKaV8YZ3nJnk7xbLykug/xUSaeb/qx1Ubqh7MiK42c+gvg3iZN9vS
         ic/vwxxm0spn01NawQu8ZyrQE9ikUqKB3Gf6Jh74svfcmAzMmkbkvJATIr2wbTnhGQFw
         e/3rWnjQrNxCFGdO94D075DplC1u5Ubv72IVHJ+nyzpEovo0913I87DYgGLq3pvpNoBD
         UHy9Be9fj973M49FkqOgz9K9pr+pqTxYptWqkXqOpbLLN00wQJg5YA/YlS/PWVc9h1ys
         OlsDgefyC3Gmts/G2/wmvm+4Tz6zMzBeIsbgy7mLS9dy3qRcpQUcjwC6A1Do/qyNoKx3
         rdEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532vwDTxAq0SQ8y3ciUIJrjUrpWEWwhyz6ddrpxtRdSBeTPsSggd
	uhgENKMouHALClfNvf+tRLQ=
X-Google-Smtp-Source: ABdhPJy+Lwjc6O20TQUaYWxKdW4I/UbLiE4Mh3O6MI1C+KXnHeYia0XSisD1DHt+6Up7rFv9O/FDmw==
X-Received: by 2002:aca:cf95:: with SMTP id f143mr5084058oig.149.1609333398343;
        Wed, 30 Dec 2020 05:03:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:24b0:: with SMTP id v16ls16650861ots.10.gmail; Wed,
 30 Dec 2020 05:03:18 -0800 (PST)
X-Received: by 2002:a05:6830:1c34:: with SMTP id f20mr38585141ote.147.1609333398048;
        Wed, 30 Dec 2020 05:03:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609333398; cv=none;
        d=google.com; s=arc-20160816;
        b=C5kef2BUcTdsNt3RhxT26vSktyU1T4ecJdQE2L9voGetlxsG/tZC+CYD9/4IjNCFjS
         hpcv8/IYI3VDzJTfPtHGVutmPtEeHRbUCIhRWE+ldM7Dk+gj4r+IySroIHU6+/rEiYLa
         Ou0ceS3YTJL4BUnbLA+kBpEmZ2Upsi2Zi+jwm8svRnV9CvGxk9ftF4CtfpMJgmEZvhmb
         oyBATcqeDTPtSmBdGMHojL2d5JWvpoijeZHVn2pBUv1LwM5OoaWX0Ayr0gt+cMpup/jg
         R0DGt/hsmnYU691XtmMwwQLNds2NOsKxX4CbDt28xRbF/DMV/sbW9xl4Lx+MJUB15W8Z
         Q9xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=6q6ZXA8Vn2CQy0w7CH8xbtG0IbScLh6GNYeagsq4unc=;
        b=ZzJx4w6dUHQdUsTAFGRoXy0xFXmXkhsV4PtZ5ynn1/58Uz+4wW2A0HL6+B05LAP7Cz
         /cKTfCQbBF6KoDI/RDxQ8Xby3UDt6SB750oBARn8QxMXRBFw2MlZeEc1rvOymxVNTm7f
         ehZQhhF8QiBfj4nErba9iHzz/R4MvEDrMz3uCy6MllZPHS6wzl2nKdcvJ7J4x+ycDMlD
         Y7OHD5Zy8uMYIL062fDCTZbXDD9s0Mdkq4U2mRZuse6uH/fIbXNlZ0n/7CYfNOW2A179
         bo673aBfO7bZvnxlKmA0FPy8H6ruE0+0EuxnjXTOsAGovTn7RwSAaQIyD1cQudxw7iD1
         40Sg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NC1TE7S+;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u25si3426268oic.0.2020.12.30.05.03.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 30 Dec 2020 05:03:17 -0800 (PST)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 763B42220B;
	Wed, 30 Dec 2020 13:03:15 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Linus Walleij <linus.walleij@linaro.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Ard Biesheuvel <ardb@kernel.org>,
	Florian Fainelli <f.fainelli@gmail.com>,
	Ahmad Fatoum <a.fatoum@pengutronix.de>,
	Russell King - ARM Linux <rmk+kernel@armlinux.org.uk>,
	Abbott Liu <liuwenliang@huawei.com>,
	Sasha Levin <sashal@kernel.org>,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH AUTOSEL 5.10 01/31] ARM: 9014/2: Replace string mem* functions for KASan
Date: Wed, 30 Dec 2020 08:02:43 -0500
Message-Id: <20201230130314.3636961-1-sashal@kernel.org>
X-Mailer: git-send-email 2.27.0
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NC1TE7S+;       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Linus Walleij <linus.walleij@linaro.org>

[ Upstream commit d6d51a96c7d63b7450860a3037f2d62388286a52 ]

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
Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
Tested-by: Florian Fainelli <f.fainelli@gmail.com> # Brahma SoCs
Tested-by: Ahmad Fatoum <a.fatoum@pengutronix.de> # i.MX6Q
Reported-by: Russell King - ARM Linux <rmk+kernel@armlinux.org.uk>
Signed-off-by: Ahmad Fatoum <a.fatoum@pengutronix.de>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
Signed-off-by: Russell King <rmk+kernel@armlinux.org.uk>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 arch/arm/boot/compressed/string.c | 19 +++++++++++++++++++
 arch/arm/include/asm/string.h     | 26 ++++++++++++++++++++++++++
 arch/arm/kernel/head-common.S     |  4 ++--
 arch/arm/lib/memcpy.S             |  3 +++
 arch/arm/lib/memmove.S            |  5 ++++-
 arch/arm/lib/memset.S             |  3 +++
 6 files changed, 57 insertions(+), 3 deletions(-)

diff --git a/arch/arm/boot/compressed/string.c b/arch/arm/boot/compressed/string.c
index ade5079bebbf9..8c0fa276d9946 100644
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
index 111a1d8a41ddf..6c607c68f3ad7 100644
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
@@ -39,4 +45,24 @@ static inline void *memset64(uint64_t *p, uint64_t v, __kernel_size_t n)
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
+
+#ifndef __NO_FORTIFY
+#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
+#endif
+
+#endif
+
 #endif
diff --git a/arch/arm/kernel/head-common.S b/arch/arm/kernel/head-common.S
index 4a3982812a401..6840c7c60a858 100644
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
index 09a333153dc66..ad4625d16e117 100644
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
index b50e5770fb44d..fd123ea5a5a4a 100644
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
index 6ca4535c47fb6..0e7ff0423f50b 100644
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
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201230130314.3636961-1-sashal%40kernel.org.
