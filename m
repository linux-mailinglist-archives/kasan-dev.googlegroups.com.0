Return-Path: <kasan-dev+bncBDE6RCFOWIARBP777H2QKGQE6BWV4XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id CF2E91D4CCA
	for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 13:40:48 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id w9sf1071666wrr.3
        for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 04:40:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589542847; cv=pass;
        d=google.com; s=arc-20160816;
        b=eOKPmxtBZObLf29d61ei/zn1YA8fOdw2QbyysDlwzIDZ2BaEAwct0rIRy4gBBerunA
         bnWwZcW1Vd58NnKi2jH9FCdSYwQEZLTPA6yEg1EA+QTFGkggeppzJKQNJ9c3wL5yrt2e
         WFjt8K1j08U6zCTS08MLs2Bv/aulmsd+ukTNrS5yYWFCb62nqc5JUAteRS4wrT58G1cs
         iLZFBRxTvglKa4Op4f9IvgQq/zbnLCoZW42H4FGH/aBkLKpDi7w4rytWJtheWJBEXLGQ
         OIqlx+XcAGsR/OgLJYwgEdy5iljDmBB6T3mMiPBfNqvAJlzsg5ZgEXRBOjLa15BJH5eP
         ff7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PYH08GQixaWOIVDD/u7x0D417n0JoRSD23MOsRI3Mpc=;
        b=fCqzcqCRHJzD6Fcm7XXdO0Vf+szJjnoQ7CCQRt8fpTI84AMnjf5pD4w1NqVTvaGbxI
         u4Hz5FIbNoumSK05j5i3mSfxSY5h3+6xi97N5Oz3amHd5+kVW2bMhOmTEnNcuwVICqpJ
         wqnPiuG7Lbl+NYSZQbxdViuKRpsYtJ4TN4fb1KkH5Q5+b5d89K+rvWVzLeu04HDiMB4A
         idgHs7stW8PXkTYNI292ljVQoIPu4YirAsUGBzmktckDkPAFWF8PFmd7YbgmzVSRrLV5
         Skqr/yQw7orFUWGG4WNGz9MjkWP1JwO5eJgaWB/k/ATLV5RgivgYHUBPgaozU/Qsvc3J
         w24Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=skzDZSt3;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PYH08GQixaWOIVDD/u7x0D417n0JoRSD23MOsRI3Mpc=;
        b=gFyZoxv0YhRBHRsphfCdI4E24Bpi+u++3i6ATHLY+PvH2fiOXZGiIVeGdaj7U4fjhb
         Gr27J4oUR2HkmPvTguLJv5kSR7EuFfT7EAMYutUZb2ydAqCLNToG7WDPUq37ezcoTd6+
         zDkFmxE0OlXJxODTi1sYZSpE3BgTQEhesncpk6ljAVtDAJTE3iqri0A52tKYFHDpvQdk
         Ykl8sxOYIoUQMQ9XXEdC4UUjbI8r+MNkGgbX0/YOp30cb/qYVsFM6uWiDqhhwU/tXxoy
         E3J8CDw2/h63dTVYMBlFDW+Gzq4L1JXPls7eJgUbTbrGVXh+fFZ9wY1OAsuqHSDfTHQc
         PDsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PYH08GQixaWOIVDD/u7x0D417n0JoRSD23MOsRI3Mpc=;
        b=emUsLKAkX8S9btx4yrb3fWpnnot/x2eNdEgniPlZvvVdFzJAYGTo8mehocUeUU2tHM
         mHNjffpS7ENhdjfEuIcNzkPSWko8cNx1njOJ2ev5hq+UWwk62J8UggMKK05RBWaU1/ud
         o0zfbSHE7OuFddmjV7ckAw7Ew3+T6uO+khqtKbu7gKV6eLe764SsQd8rRWi19DcIm9Za
         rvp1RNQnjWfdyTkfH0ltGzo+yxMbNAz1xrQfup/Xys0KkbJ9LxX+QkvhyqnA25rGTq1I
         EyFJpOzj/MSiUvRvV63tpPOpU3hq/2+jDkEaBrWHOpKe7GDhgr+GBtYdFSm2wEB9eNjm
         g62Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531n+OizdRnZToanUjAIuPqqqWVR/Nh7Dl1J2XCw3h0qhgAJii5L
	yZCaW+HWzxWk248jWBjnM+k=
X-Google-Smtp-Source: ABdhPJzqJB/SZmCYFC9+8h1hEn+DQFMblav1x7bVG1s/sXCD0q2sNewenX6UNxKCFJZTKK8v1X0eWw==
X-Received: by 2002:a5d:5183:: with SMTP id k3mr3797445wrv.159.1589542847476;
        Fri, 15 May 2020 04:40:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a502:: with SMTP id i2ls836656wrb.11.gmail; Fri, 15 May
 2020 04:40:47 -0700 (PDT)
X-Received: by 2002:a5d:6541:: with SMTP id z1mr3874702wrv.264.1589542846973;
        Fri, 15 May 2020 04:40:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589542846; cv=none;
        d=google.com; s=arc-20160816;
        b=kYMRpMl/Y4I2RWshI9alGv/3iBlsKJUoFx3JZA7i+4u/I/YPe0ZrZQre0LSEe2pfA4
         zLablhhVHjNLaAzxsrpuQG9nwgwlRJBljlCUV3reAw8iKXY7zSThC/1/FcQnkL8BDpDn
         TtVbKRAX18k946ednXI+Eo/H2qwgtj4cZqUgIn1YshngyXhHrj0p4c8kFsot0V6z22BE
         zcmhLEnnUzIi6qVYLuv4iuLEtAnzoN6VsNTom3pZnulmamVOtEL2ipbnXyLTBRPIqsoZ
         Y2c0c9KrMt872jhjH1b5of7/CJ38ZS/XuYxK36bfkkmSwsOabYQfOi9BBDmFwVv36cPA
         jtSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=suAZSfqtSa2IuWWcDwq0lHLogcOqlFx3MdZogf86ZOU=;
        b=YtIlyxrr15yTXzDF3Qi/tmwbWxA51g5FbxaskRk+D/F1FN/5uSyy3c0gOxTBOGVB29
         f89aTky5qDt7u2dHcu9FbYnN9Vzn+i2oVa4IxoXUg9/OM9B44tlvSn8DDoWfn/Lfyzca
         rlHIBogifgWjO6YK6vp4En6hqaOFYC7V5SUJ0MhsFZHCGh1tBNklKWymaVvXdI3eSLPk
         j+Gc8dD6jomb90SF3mhNBJPC9S0Y1z0oaQMMEm6xEJSUNPrX3nni1V2z2fRoIEMFfwxg
         ccSeCRey3jgTaAwfbzErHHqjZUsD+18QxFea7nuX6pAQWEWyFoUg0Gli/diV8mD9OS5f
         cbOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=skzDZSt3;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x242.google.com (mail-lj1-x242.google.com. [2a00:1450:4864:20::242])
        by gmr-mx.google.com with ESMTPS id a22si1440568wmd.4.2020.05.15.04.40.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 May 2020 04:40:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) client-ip=2a00:1450:4864:20::242;
Received: by mail-lj1-x242.google.com with SMTP id g4so1894819ljl.2
        for <kasan-dev@googlegroups.com>; Fri, 15 May 2020 04:40:46 -0700 (PDT)
X-Received: by 2002:a2e:b4a5:: with SMTP id q5mr2187591ljm.58.1589542846020;
        Fri, 15 May 2020 04:40:46 -0700 (PDT)
Received: from genomnajs.ideon.se ([85.235.10.227])
        by smtp.gmail.com with ESMTPSA id 130sm1218445lfl.37.2020.05.15.04.40.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 May 2020 04:40:45 -0700 (PDT)
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
Subject: [PATCH 2/5 v9] ARM: Replace string mem* functions for KASan
Date: Fri, 15 May 2020 13:40:25 +0200
Message-Id: <20200515114028.135674-3-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.25.4
In-Reply-To: <20200515114028.135674-1-linus.walleij@linaro.org>
References: <20200515114028.135674-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=skzDZSt3;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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
2.25.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200515114028.135674-3-linus.walleij%40linaro.org.
