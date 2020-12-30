Return-Path: <kasan-dev+bncBDTZTRGMXIFBBWXVWH7QKGQE2MLX5CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id BC3B92E78E4
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Dec 2020 14:04:27 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id q10sf4229813pjg.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Dec 2020 05:04:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609333466; cv=pass;
        d=google.com; s=arc-20160816;
        b=XQYjLo6Sb9IaAa9n9+MxneIJyzC/YJ34mdwrUwiwhK/kC/37Frnxi25dfrSu6J/Isv
         mFM1MHrM99Zj9rEu+J4M0FOYMxz5p8YJvahRSsKjbjunbIrhLQ0Y+hmpVgClfqDD+ziJ
         zU8FbPAhTYIUdmJSRrO5SlvK4H/LNnOYI5JEdt3Dq1slElehk18NOl358+Co49uOkqmE
         EBsb35XBCwNialMNQYTM23yGkwS+XQXVaVBqBRAvBx/s/dlCKguqeBCFpdhlX7qaEJDH
         Pp6lalE0MWIf0Bg21QsZ7k0q3Z1sEom+WsSb9Wi2PvhdI7vwMLrULktjwouvJ7Hw/yET
         DwuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=AHipjrPW0QT1mUVe3HxIcdJ82R24NFefUFBKkwBVwaQ=;
        b=tcqpgQcvUb3T0qL6dXx+aWkwXxRdLOkNEgt414jCd5HEyGJmhHQhgeTDARW5BrqSkh
         yJd4R7pt2YzBIwEBipS0J5rldCcMz/t+ZaIbZIAsMwxiYnrB9mtkr+Sr/v9ciHkZX+lD
         Xw5DTThPAlpTU/IbVEBa2B/4WYOrTKsK3Pg/hf1O71iBjkit3+KGAQno/Qk6LUo5B59s
         z8THZK+vWAK9hsR0TxMz44YMJtkf6dai18a2oq19CDDBeEzoQf4iytP4/o82gM0P+LGk
         ETICJFkqcF1HJjUXu0/8cuGQQ/3QfMy2Ns5mjs6xyrLNuginAkMelRX5Pug3uXXIWAAA
         FhOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AnKUXHtc;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AHipjrPW0QT1mUVe3HxIcdJ82R24NFefUFBKkwBVwaQ=;
        b=P1fDluluKLKxm3b+HMX3yYkRywgejUfGCF8nNooG/JGeK/v2itVCcS8+sz7NtdEWb7
         bcURD15KiZCTAkLvEHZwuxyMiGk+dg2FgDHcGsVhmvDojWXJGhbZDz6jxzBKST2SMod9
         j9jhKppziDPkhN6yP95sDAVXAaGoBKysVsRdm72IYyO7/QUdk/RZHrVDA4mCMakIHlG0
         Sm4jg8kGN2WITZi1FMJncVa/MP7+IBiqaIW5BfdW0BuADMuxx3TtpBpddu3FEOhNx/S9
         u9SkY+oUCxEwSJZQ2XuGBBMF8II/N6ThfQ/GXS8oMcmaP0z35lbiwH+zK1HYnSDbjVf/
         J4yQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AHipjrPW0QT1mUVe3HxIcdJ82R24NFefUFBKkwBVwaQ=;
        b=OwA6jHJFENodpYtMFsL51rkT6+Q59NX553XYeQpoq36b1lToZ1E4jieLJ93Muc/bPE
         1VcwC/3e2lenBh7f/Zjdv0lDOD3S6jayF1gSRGDN5qobSt8lmowU7j8GRrV/O6wL3CLG
         ASShUp2Djw+CTjM/d5XxUJBlw90dtDU5XG+p+L793jOMgxe8MFZrzMXfP5biTMeElphh
         ykD/MiyrmFV8+EFR3yDUmt2u15RBr4sq5Nhi4/rRNsAbY4E7iSKddEnFuVOFpxv+f+g5
         hzlYDpPWALrXQVVZqWvC+JQ7Dh3FG7kG2+3fSxv/FrW7u5crJz6kgPfXwxrPed5jMVX6
         c6Vg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531cb7wWqGnt8pjysbPiukHoDyAarQlStWAAa7K2GMA0oOIJ4++I
	WJgyFaBFgJ5ykKO9HO30iyY=
X-Google-Smtp-Source: ABdhPJwgeRIR1Y+7bqSRhuiIHUFGfXJZIqiHSb+uNL/EvqupDO4BmsSOEgtRgL0SFbeBRi3pk15jBA==
X-Received: by 2002:a63:700c:: with SMTP id l12mr8994751pgc.137.1609333466190;
        Wed, 30 Dec 2020 05:04:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5612:: with SMTP id k18ls25491440pgb.7.gmail; Wed, 30
 Dec 2020 05:04:25 -0800 (PST)
X-Received: by 2002:a62:1a56:0:b029:19d:b6eb:291a with SMTP id a83-20020a621a560000b029019db6eb291amr30617938pfa.10.1609333465654;
        Wed, 30 Dec 2020 05:04:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609333465; cv=none;
        d=google.com; s=arc-20160816;
        b=oXEdQ5rW8dPPo9lKroV/QRu6BRIPWr4Du8tYuEqKZ/5TRagl8JiotIcNzTbk8Uor3p
         B7XIHwVYoZuvEX8qnu+kuvcO0Fahk8rCpGM9s/kDJs199dDQzvYEbMZjfz2u3gzTsg7G
         r+1nrfr28zkFPTp3yZ5waR+jRZ8fPJYricGNesaNK21aQMs8+0j/UYCaVzsMiln8z1B5
         d9mnOx+DbfPtW4YQpSdxIBaojfqKNiAJXeKB8G67zkg3/hHnK2SDtI/gw9EfS1mr15H8
         YS9kc8OO2RlcLU0dzcAlKnP2GRBHvTaU8CvXB4qjKia4Wshn4YEE8q5DAUVBvlaGY5TN
         uhrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=h4GchTa56iok1wfFR+nRBntFowNtv5iCGJPhqI7DWRo=;
        b=bS6MeoblNrFg2fQ5Ne2fzOPxyM7V5sB++0U4VTSItt52Ro3W9F5RyvYrM2+CNkFfeL
         De69L9RoU3doIYpttOUS5CNQVrJ8LUgT3l7ooJPpvY6sw+2gb2Ni5WAzx1PjRGDCwJbW
         JrgoZhqsWE/IpFhCRLWRGzJrKmzJVkmrXpICNzaFRgp0HDpME5euXeIhv7rVYki6pVGK
         3mpNfeUel4ar3nwbfCD4BOCfy8y3DYZe3qpnjikdFn3vzMIq2wEcGZ31VrXOAmfuLlnl
         LKFU5Y7bOkR+8FhnUxVwEItio58fytKjLJMzd7gDBgu+oW+BGH2Z4GMzhjYHbv5Ypq2x
         Rx5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AnKUXHtc;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h11si432801pjv.3.2020.12.30.05.04.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 30 Dec 2020 05:04:25 -0800 (PST)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id C849122582;
	Wed, 30 Dec 2020 13:04:23 +0000 (UTC)
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
Subject: [PATCH AUTOSEL 4.19 01/10] ARM: 9014/2: Replace string mem* functions for KASan
Date: Wed, 30 Dec 2020 08:04:13 -0500
Message-Id: <20201230130422.3637448-1-sashal@kernel.org>
X-Mailer: git-send-email 2.27.0
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AnKUXHtc;       spf=pass
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
index 9328f2010bc19..053e59f81aaba 100644
--- a/arch/arm/kernel/head-common.S
+++ b/arch/arm/kernel/head-common.S
@@ -99,7 +99,7 @@ __mmap_switched:
  THUMB(	ldmia	r4!, {r0, r1, r2, r3} )
  THUMB(	mov	sp, r3 )
 	sub	r2, r2, r1
-	bl	memcpy				@ copy .data to RAM
+	bl	__memcpy			@ copy .data to RAM
 #endif
 
    ARM(	ldmia	r4!, {r0, r1, sp} )
@@ -107,7 +107,7 @@ __mmap_switched:
  THUMB(	mov	sp, r3 )
 	sub	r2, r1, r0
 	mov	r1, #0
-	bl	memset				@ clear .bss
+	bl	__memset			@ clear .bss
 
 	ldmia	r4, {r0, r1, r2, r3}
 	str	r9, [r0]			@ Save processor ID
diff --git a/arch/arm/lib/memcpy.S b/arch/arm/lib/memcpy.S
index 64111bd4440b1..79a83f82e1742 100644
--- a/arch/arm/lib/memcpy.S
+++ b/arch/arm/lib/memcpy.S
@@ -61,6 +61,8 @@
 
 /* Prototype: void *memcpy(void *dest, const void *src, size_t n); */
 
+.weak memcpy
+ENTRY(__memcpy)
 ENTRY(mmiocpy)
 ENTRY(memcpy)
 
@@ -68,3 +70,4 @@ ENTRY(memcpy)
 
 ENDPROC(memcpy)
 ENDPROC(mmiocpy)
+ENDPROC(__memcpy)
diff --git a/arch/arm/lib/memmove.S b/arch/arm/lib/memmove.S
index 69a9d47fc5abd..313db6c6d37f1 100644
--- a/arch/arm/lib/memmove.S
+++ b/arch/arm/lib/memmove.S
@@ -27,12 +27,14 @@
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
@@ -225,3 +227,4 @@ ENTRY(memmove)
 18:		backward_copy_shift	push=24	pull=8
 
 ENDPROC(memmove)
+ENDPROC(__memmove)
diff --git a/arch/arm/lib/memset.S b/arch/arm/lib/memset.S
index ed6d35d9cdb5a..64aa06af76be2 100644
--- a/arch/arm/lib/memset.S
+++ b/arch/arm/lib/memset.S
@@ -16,6 +16,8 @@
 	.text
 	.align	5
 
+.weak memset
+ENTRY(__memset)
 ENTRY(mmioset)
 ENTRY(memset)
 UNWIND( .fnstart         )
@@ -135,6 +137,7 @@ UNWIND( .fnstart            )
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201230130422.3637448-1-sashal%40kernel.org.
