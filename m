Return-Path: <kasan-dev+bncBDE6RCFOWIARBSWM7X5AKGQEJJ6HUHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 61A36268B5D
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 14:47:07 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id u11sf2439917lfk.22
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 05:47:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600087627; cv=pass;
        d=google.com; s=arc-20160816;
        b=dlvH3ELjW6q8HBfdNJnAsr9WI2zbSJM5OHvyELBSU8jyndjYYkvl/8pnhl+NsbtYOa
         Rp4UQ4/Qc0cHmgEQq2UTSUhgiBfiHfXZ+AAJIl3syZiA/+uWEPqyKvdEQ4d6bfM00Z8q
         t6ZafTWsKNqqdrJprCQhbPR5KAXuGFfBZNyqft7Fx18KJc/s4sJNWzXpDGyVw2ELlXg4
         4oBaNBnOdjjJyqLJKg87020SN0a+MxwLat3pWqBY7Wz15Bsb0VRM9F6wubshVBqIrB5Y
         69ElS7RK6Hbv2Jenhbd17le95CMvc62sO5xHJxz5VtXVCcjyfNqSUs4oleFT7Y22Ou8O
         3fdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=EwdnEmjlzec88u4GcFAHWv32EbBr7Oeq/q3JZR9lBTM=;
        b=E1i8cZj5GQpNI1BN5pcui0WL9obnVwqC/uy+eCx7fz1V8WwZH4DE3jEdMJBmRUqCTz
         7wbPnOwfqaeJ1oP5sWs/hMw4Jjeep+7/lF0L5PsDiOIyOIOTsZseMe7AMyM9xqVMxHd4
         exKYhO7hzHoklNlg+MkIzcIm+82NvmL9QiWAV39fnqBTPcQKYRP2CCtdJ0U4H65tQxwJ
         5J7fV4cXAc18sLJIFJPJ14EBegmR1cfIr1XvcfgPEnqzdcy+zQDhSgnlOTKphPHVP2zN
         9D0LcPxqKGhlwiBtPocNnh8cuEtWONuTPYrBTCu/zHKdw8epfaKQ8c/pLmsGFBdPU9dZ
         /vVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=zRRub1he;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EwdnEmjlzec88u4GcFAHWv32EbBr7Oeq/q3JZR9lBTM=;
        b=Wr6YvCvuJFVO7XOhFDuvJG76euIMoWUHlw81KUiKdjwxwjyf9fjr4jqGruQEvft+Tl
         YUEmVui4wh0AS//aQRHEbtwenoGd5fkJYeuPeD+I9+crpnMxZYE44h8OMD08r974dm8I
         3d/JzXmANxFJWJT7ict34LFkJdPnXNKeFdPh29+CqX1Y+35RXqOXoEuw1iGcIoooUEVh
         /PxhCeFYex3S4fu9PmSp2OY6GTGAULSq7lZGboErOpjhoizEvNODMs5PS5Gv7SN8QaII
         lqdRNeWgs+c60vT3LYyPpIKrPRnmTw59XafhuV/fpPlPTwR34d61dDQ5dgBRjndPlZ9R
         zL5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EwdnEmjlzec88u4GcFAHWv32EbBr7Oeq/q3JZR9lBTM=;
        b=rtwErmgM7U5e1a04ctW6ggr0Lk+OFr5qOdwwIeyaKYmIHiJSmeOuDLWxv8F0VfJ2cD
         N1SwRy4ZsLy9dF53c6BCjip2o9u3U/I3350xssj/k0KrIjPDFrtHDL+q2XWGRVnaPXSN
         bZeSB98Cp8YrPbLUy201fmZYO81NMuApYmSNFHkAovdnRkNqyiGDw2h60eprzxap18SQ
         Fj0x324d+HviFOtWNKjBZ27TG9GH3zU59jI2kZYEX9oplo3e6gS4fV6fFA+8pWxTyRNj
         +XVjbcfkjwETLqyiQoLisMxqk0KI7yJD570RwzXmaF4xbLInqbV/r7WxldQ9TId5N3ZI
         gOcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533t4QuaJvJSOtLxEmZmOUL83br4UfBFqvIDwB2mR1kxuQBKUuFT
	kPFoL515+Xg2cfMoqtYtrBg=
X-Google-Smtp-Source: ABdhPJwTHYzgGrYW4LIiBTI7KZ4k+RQXIftKbzTyHK0MAc1Kwq52t9aafog0WHwZgsNGkHs9sFI33Q==
X-Received: by 2002:a19:e602:: with SMTP id d2mr4793606lfh.514.1600087626819;
        Mon, 14 Sep 2020 05:47:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:544e:: with SMTP id d14ls3283821lfn.2.gmail; Mon, 14 Sep
 2020 05:47:04 -0700 (PDT)
X-Received: by 2002:ac2:546f:: with SMTP id e15mr3983602lfn.358.1600087624315;
        Mon, 14 Sep 2020 05:47:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600087624; cv=none;
        d=google.com; s=arc-20160816;
        b=jZTTISp96Q8mCnMso6ENHu8KErHbXd1i/G8RY7yVQxbalu+CWZFkrXV44Ft2IXugbj
         jnZShEPyvggpTmjoXQcrkuy2nDxAfG/exGHX8wqUmEIXR0YRNhwP2TOzuQtffZX0Lc+7
         vpFBYlogAFRm/WJhud8FxZYB8W5NyZoSW/zMbjrCT0E72jdpnNm87A6sIQCXkTsczxDD
         X6N35Zyp9PyK8mHVtkWcwhzC38AUI4R7madepMbf/YVxdf1QOAY+NCmdFCnEBQIfTfVV
         QY6bJ/JoSLn2ZF1jFRp6Mp562922FUNxuowqoqMFIl6gQYIzHE3gcjR1HZEmiPH+o8QM
         jtAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gNCsNPzEVjCYJt11yxYRCxsdlOf8zfrSCGFSdOZPkIk=;
        b=K23ZYI0s7TJQxC7tFfbf3MgeWVfCI7K/H8+/UCTkms6ifUoprJsDBRqOB/s5bzMUgE
         0UojTiT5sjBgmpnq4/vqM86spf1UMy6crL/+YCk679gIKwZEEc/Q8zjS2ozpw3wFOJT9
         bWKADPMfZ4tdpcZVwmKZ19wJ5SbWsaJR2aeCAXHBlcyx3DmL42l9Eb9RYI/WpdEjdU5o
         Q3vY2/7HyRuJx6FxC9GeO8CgdEQ9jc0xQQT2/Cxg427R9yUSpXMpxVP8BpuR1/Kvh2tz
         90DFZdXrzfZnr9R0EoWyOs6MGcMsoD1m8Mctcpv6fXe2dFIZg/AbSwVd06soHENQbWjR
         MEoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=zRRub1he;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x143.google.com (mail-lf1-x143.google.com. [2a00:1450:4864:20::143])
        by gmr-mx.google.com with ESMTPS id z6si282459lfe.8.2020.09.14.05.47.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Sep 2020 05:47:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::143 as permitted sender) client-ip=2a00:1450:4864:20::143;
Received: by mail-lf1-x143.google.com with SMTP id z19so13284061lfr.4
        for <kasan-dev@googlegroups.com>; Mon, 14 Sep 2020 05:47:04 -0700 (PDT)
X-Received: by 2002:a19:b55:: with SMTP id 82mr2154663lfl.43.1600087624038;
        Mon, 14 Sep 2020 05:47:04 -0700 (PDT)
Received: from localhost.localdomain (c-92d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.146])
        by smtp.gmail.com with ESMTPSA id e17sm4050173ljn.18.2020.09.14.05.47.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Sep 2020 05:47:03 -0700 (PDT)
From: Linus Walleij <linus.walleij@linaro.org>
To: Florian Fainelli <f.fainelli@gmail.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Russell King <linux@armlinux.org.uk>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Mike Rapoport <rppt@linux.ibm.com>
Cc: linux-arm-kernel@lists.infradead.org,
	Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Linus Walleij <linus.walleij@linaro.org>
Subject: [PATCH 2/5 v13] ARM: Replace string mem* functions for KASan
Date: Mon, 14 Sep 2020 14:43:21 +0200
Message-Id: <20200914124324.107114-3-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20200914124324.107114-1-linus.walleij@linaro.org>
References: <20200914124324.107114-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=zRRub1he;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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
Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
Reported-by: Russell King - ARM Linux <linux@armlinux.org.uk>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
---
ChangeLog v12->v13:
- Rebase on kernel v5.9-rc1
ChangeLog v11->v12:
- Resend with the other changes.
ChangeLog v10->v11:
- Resend with the other changes.
ChangeLog v9->v10:
- Rebase on v5.8-rc1
ChangeLog v8->v9:
- Collect Ard's tags.
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
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200914124324.107114-3-linus.walleij%40linaro.org.
