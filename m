Return-Path: <kasan-dev+bncBDE6RCFOWIARBKEB5X3QKGQE3JSAUQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id CEA2A20F5E6
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 15:39:52 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id yw17sf13036740ejb.12
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 06:39:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593524392; cv=pass;
        d=google.com; s=arc-20160816;
        b=rEpvcIuSaQ6QNY9OF8VuEHHD1UEIV/OtoJ8a8wCnkHYz+YXaVVVMeY8zmnCKsprf3S
         kWRFtk69dhU1bZh5n7mbd+suqIrJN6q33N8iulR/666tIQIn3Xj4TkfaD6iTjl1HfG9M
         I4loe7O+caH1TTKWnqhFd102BPDn9uqES00KsqPo5eO6xRGsjV3wC7aBxfe2N5d+8z0w
         jWV6BAqY8PdEWbbJg4f2R7cYVchuW7uUHu//BRURYTB+oZaiCHqPG8lkE8HFm8E5lyLO
         zAXlQzhiVKDvtSMOuTtK8PVsYyAliV2W+xyPr1Xi6DvMWs4GW7Jcg32tzGNsPzyOD2h+
         7rPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xfnZpnGwAadGmxy8TuzpXA6pxRVpIBCTyeR+A7ustBI=;
        b=lrw4a4EK53pG6WA5Tl9bwvOSI3/+NngRjgec1GcRrfmFptPCTDHnW1ojSyEMsOj/aB
         ktE5lmFUJjTILwnHXEMus3muoGyShS6ZFyazc0QstcNoNKchg1KhsjYzcqBLog1gVquL
         DSOAFPPrlMxBe/i+tcOjQu+CHnbX/xQhcPv0xboRX4iJxJophTc98D6Pi5J4/t/g0JIf
         2KyevOFWz7M/AzDUT82Pl9WPZE+OdHDEiR6sx+WKkg0qZxo2LcviG/ehiqwU2ziCE7MM
         3q3fxekNPwc4RZ2PK2u0sxIOGtJRZ4z4JESdaetzeiMtvfqdx+1dgue7xJtjBj+TGkyg
         +8Tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=XeVv7m3I;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xfnZpnGwAadGmxy8TuzpXA6pxRVpIBCTyeR+A7ustBI=;
        b=JX8revyttpc57ZeixZ/ufX5dGdm2ltmlEyJcG7VvEq8fxfxVjyC4z4SLp5+L0e4Pst
         Dmeq+FsChUN4zHLfNZK7W1aB/TaAIsA/evycsTq71gycX3HOqcm4JaNbCWqRC0YJst/r
         v0lM29vTVmbqifhsqXVJAPwVKI1cKnOfvqUhreo2vyzRKtR88LcYiBUXnO6C3bTFV6tD
         COEKMCqlGunr6f+A2u9hF0oO9+vXYjYune/IV3GS6FCVOKMNKhxATUAkvOxBlVRec0QS
         cMYalDj+nV/5n5xDWee68evLRrxhdyHrwA6IhZd9vm6g2AUGFPWV0T/J2ROHTzFcWW3h
         KJ+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xfnZpnGwAadGmxy8TuzpXA6pxRVpIBCTyeR+A7ustBI=;
        b=TcMjSIMGVO4gfeKtRkoB51nvSKWXk1ZCjitVQXD7/3ONi08BwmCGus8MbOzbwLQDZh
         nNRydRUTo07U71+aNhGw1s8fRnQ0cnzRJ4UY21n8lSKlPIK6Erhk2ds4rc4ZfYj15IIj
         orOjNsqDnAvg3PgHvm2/YtxaK49sK461pAdPm4eYpGM55graLcDPQvf8TZerYP3oI2q5
         t+pBHatAU/UPJnoJQDSBTcoiSC2HmAkzzIZlREfwfi4rSVU+6gepWlpgz6+ckktrz4hN
         uwwFs2YCV03PbnlYRpjhwrI2HbyRIO/qr1T0+O3v6ETjA7x9CxetjE18gpyea5wgwh9m
         BVYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ZgJ2FAcvg9ymXRmHxk7nQawrd3p6GMo3i2tLp9PmJ5GeQQNdF
	NwpxJ0fVgQuB/aNJBrTLVEo=
X-Google-Smtp-Source: ABdhPJyVsKuXz+KitinqkScUn+ZV/Gm3Gh9RBEtBwzBPOfxqKXi+gvzxptkEcsS0JhgdcmyIYleM6Q==
X-Received: by 2002:a17:906:c415:: with SMTP id u21mr18120399ejz.45.1593524392492;
        Tue, 30 Jun 2020 06:39:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:7f92:: with SMTP id f18ls6415240ejr.8.gmail; Tue, 30
 Jun 2020 06:39:52 -0700 (PDT)
X-Received: by 2002:a17:906:3fd2:: with SMTP id k18mr19369516ejj.387.1593524392042;
        Tue, 30 Jun 2020 06:39:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593524392; cv=none;
        d=google.com; s=arc-20160816;
        b=QSRZ1vyPvK84OymtRoEjMDkVMHAoMllloyOALALpsomyZ28bG2qoxPaytoGevgVrVB
         6AhJH8QltH4H1ZTJ0dI6jZbXE45T+7xSXa65P6F8bMFx8zue3hy9/IPNJYEHQgSVH4dd
         EBfrqHgTx08LJ5F0pc38CpX43+fEV/qSFEtrjpcFP477jMC92UxufN7KulJNp9An8RAt
         i15SVD4+CT5KmH+WpV9HWo4dIH84ss6HsU5Xl3/F6mZmvZUvF6pwecsGntKetekXElXd
         q+vByNLomhG/hgnUDYCgCHjdayehHV3EhiLzXOFQmZZNxEz/rJ3CmEvNbW4X+YtcuzGh
         TYpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=bpEy9qmsvyt+K7Yf5sX0tVjtvoTfehks76WRJQovFpw=;
        b=dg2kLuZlCdU8JcFU8/JIu4NjBvYFjIRVNWg4rYPX+yEmc/oe6K1zB0/MA+zeQcPBkT
         bgZNtNE2Rx4/9GGt2GoRQakPyBWZEBiBVPJYwyVuG05ILuiP/lFmmdQhBa6DogPDkBRn
         qmI5HieohzrsWGrlulZBs1SVe5oeoz5tuk+rTEYJHRtJjlnCp/4CVVlvL13SIlRzTGv0
         WZgs+EnH1v3dP42Et6TYsFvG5EwF/mfICLeGoJUe2hwuT2VhGee6AJK8iKm0NraHjE7L
         0+256NTESnVlokBsS2nSlvq8zY49MYSpl1Ve85eIQaof3zyKuf8WDn+9r2mQfLLzTOz0
         aVRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=XeVv7m3I;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x244.google.com (mail-lj1-x244.google.com. [2a00:1450:4864:20::244])
        by gmr-mx.google.com with ESMTPS id i18si175246edr.1.2020.06.30.06.39.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Jun 2020 06:39:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) client-ip=2a00:1450:4864:20::244;
Received: by mail-lj1-x244.google.com with SMTP id 9so22589636ljv.5
        for <kasan-dev@googlegroups.com>; Tue, 30 Jun 2020 06:39:52 -0700 (PDT)
X-Received: by 2002:a2e:a484:: with SMTP id h4mr10823692lji.468.1593524391699;
        Tue, 30 Jun 2020 06:39:51 -0700 (PDT)
Received: from localhost.localdomain (c-92d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.146])
        by smtp.gmail.com with ESMTPSA id a15sm737819ljn.105.2020.06.30.06.39.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Jun 2020 06:39:51 -0700 (PDT)
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
Subject: [PATCH 2/5 v11] ARM: Replace string mem* functions for KASan
Date: Tue, 30 Jun 2020 15:37:33 +0200
Message-Id: <20200630133736.231220-3-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.25.4
In-Reply-To: <20200630133736.231220-1-linus.walleij@linaro.org>
References: <20200630133736.231220-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=XeVv7m3I;       spf=pass
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
Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
Reported-by: Russell King - ARM Linux <linux@armlinux.org.uk>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
---
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
2.25.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200630133736.231220-3-linus.walleij%40linaro.org.
