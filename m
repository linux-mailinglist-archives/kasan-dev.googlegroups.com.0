Return-Path: <kasan-dev+bncBDE6RCFOWIARBU5CWX6AKGQEHWED2IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id C4D252923CE
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 10:41:55 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id s6sf377727lfc.19
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 01:41:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603096915; cv=pass;
        d=google.com; s=arc-20160816;
        b=v6uR/d9hg7Veh3rP0QUO2C436tG+eMjlWtEyu3Z2XlPbwIkYA3SRpoxPmYCatXuhpK
         g+xeXAcW8eQDt7E3jhIBC2lsTBiCFvO6tSKxV1hrsdOQo+vONX+2HrY8Mah9LbbRBV7T
         hkojCeFCowXULGvzuu4fNri0qPCT0kFk73jgBKhp4/aYUuEoEwg6vkZsLp/+MPF3dbjO
         DBPL+1Gi6y6jBVjwdjuA6Wt6JEeQY3+NACvalDQ9Pk7towIr4G3U9RUq3v2B/M7Lq7GB
         DZHbFp2+1ImxwCnRK34Y657JPRpR5MLDRVvlpndCYMfZed4cqt+XuKQenzZO++PrAdW/
         U1SA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=mDsADEdp2CLBq6MT5sWYcLPpXo3gRZimPCQg1NuY664=;
        b=Gv+Y4Qsdh0bgyCDKHLWLRha/3x2rbY2sTtoZhan0Hb6usyYkbeMdUQDeBDoKqSvdxd
         0foruTQfpnaYNoZub+Nk7zAXdMfiiJyVS+lz3KX7y87rDc7kTv4sz/BTgY31uqxZS5kb
         XpCex93qCsnqw8h7BRJ4jndrGnXCfNDy9xbiwg5XKWmzJdjrELQFmJ0jBfrhu2ip7csE
         WX6k1Sl8U7kY+Tdp2iXnPfTSuWSS6kayiw1aY+p/eTRJVVIDynMx3Wn1vJSF0+ljKv9L
         8NfTXm1kMl4HwJu8nxKUupfLSUmwwUINCkg9Pu+j8fiXvI5UCsW70DfOOCtmNIAANn8w
         gn/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=qsq4dLf9;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mDsADEdp2CLBq6MT5sWYcLPpXo3gRZimPCQg1NuY664=;
        b=Ub0KOT7NVZt2Ys2oRhSn4aVKqW7mlH+j0qwqi75XkJ6JF8uyVq1Cp1RLhyc0FT8mB3
         s/6kyFUXXR0ajbNZ+mhU9LCTSyiXu8nUpNUuV+7gRvpKzBSdknnZzPkpVseB4oBu4iYY
         AWCY7Wl2fqD6Tz4PKjIvv5OtSBVYt0cQCuaukcdSdXaI9ItNnyO1RL5ld90tta9IlcCp
         Ynfd1ILZxxmVtTWVyVO508Ui6sxHfKQ+bGLbRAaUeBH0cmCUwl4h7qIg2qwPUwAPSxY9
         OBJxvXyglIgyL5H2d+OSeOLMBb7B1IeLEVEkiSGq7KXGpl9ydIuwV+UKj8M+9Qqxkyps
         qNMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mDsADEdp2CLBq6MT5sWYcLPpXo3gRZimPCQg1NuY664=;
        b=lQcOdGrFdAJ+GWpCp5rKGDtrSeKKzdNtkiP6a1fdLejPDE6b05UadynI4xrxpKpjcu
         5gdsD8lXfkmeVWG4lGH1TtNfyEKSYgzo+PwNy9+hHeyyRzOQGVKteHp8dKs9z4oYnbKj
         A4MnQBf+DEbjBNOboBjT29wXAz3Z5M0jpnSw9Ox9N+snhTxwkYDAsc1Hai/al/OVje9g
         1TqLCI6kDocAfZrAOSNsek7qe4OqvYwLfg7/Mr6JXCDmdK0teAmlz4t3UOeeWki2JL7c
         mFzYb2/r5Zxn8tROx+kCtl5Z44y/OAgI6xLBs1IMFsLcFlretyNIZ0tbO5FThDtoKoN3
         54Pw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530mPnlvdCC4gp37DUmanZubyOonU55iWCE3E1SHxGKfYCiva1lc
	Io1+RlHsKucxmY6yU7FZfnk=
X-Google-Smtp-Source: ABdhPJw4b7EWEIOa8S6WOL2Jdaz5fcWzLFDRsy0lOe2LH9YhrVJ3glU5kscZbQ2sP2eqWABpCx7zQg==
X-Received: by 2002:a2e:9052:: with SMTP id n18mr6158422ljg.78.1603096915300;
        Mon, 19 Oct 2020 01:41:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c111:: with SMTP id r17ls3507829lff.0.gmail; Mon, 19 Oct
 2020 01:41:54 -0700 (PDT)
X-Received: by 2002:ac2:5e6c:: with SMTP id a12mr5936614lfr.568.1603096914293;
        Mon, 19 Oct 2020 01:41:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603096914; cv=none;
        d=google.com; s=arc-20160816;
        b=pDhkRUyFA4v7JvsBsLbRxl1mzlqB5w/G7XUMs2BJzQ/ZIF9fCAvEzmnmCZLFrwhFUA
         YdqxdJLQjdw9i8z0w83+QPIpslYCOC48DPh/eJhwI5hjMV5NymuVLzOXrNuWK/dAOlBJ
         s3Vcn2beCkoDQGjwHkNrcB7rI3goAccew2pLn4C4BxpIgNWEJkV9XvSR2wqhW1xrNFO1
         cZEl6nosv7d41PiEr4/QUR9B4NtMQcAedQE6iBr4XRLINopuk5CG16RRqpLSzKDnaOIG
         nKc7ThmmPhR+A0VXjIEiOVpQCh7L7HL1NRXQU6Duuafk6G9ddVHSOYE21wuErtfivCoK
         i5kA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vn04MCz3nQQlEjWuzcsQEInScrBGmOey85YcbtanHhs=;
        b=JrG5OH7O282g958VgpVSAcJm2PFk0tUa/GjutCbQY7oOYXl8RleYn2Ht+AIkNlTcGY
         dF6T9o3bVc2/0gg1icv3doIZ3WmTkPD7uZ5rbFcLwgt7DQapnM+xUYx3jwYWeGXP+s/w
         vieHS2uOEVxmgVF3+/gGiiBvew4gk59cfzTYVmr9WU0gOsXVOVhvk0hqMN3EeOHBLyba
         rXo1aFfWBj3yMb1HUzbbv27+YXgFS3QZVDq8Gq8v5NrId65+0fnVSgczWgtcNp/jNTji
         xixR9rZD5L04LQJxzkQzyIQPK3BEZGoB5OSLkIRSZWkVf3609M4oUWBpeLMHFIKt35hy
         +Law==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=qsq4dLf9;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x142.google.com (mail-lf1-x142.google.com. [2a00:1450:4864:20::142])
        by gmr-mx.google.com with ESMTPS id r22si243600lfe.0.2020.10.19.01.41.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Oct 2020 01:41:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::142 as permitted sender) client-ip=2a00:1450:4864:20::142;
Received: by mail-lf1-x142.google.com with SMTP id 77so13172392lfl.2
        for <kasan-dev@googlegroups.com>; Mon, 19 Oct 2020 01:41:54 -0700 (PDT)
X-Received: by 2002:ac2:58f6:: with SMTP id v22mr5784298lfo.431.1603096913901;
        Mon, 19 Oct 2020 01:41:53 -0700 (PDT)
Received: from genomnajs.ideon.se ([85.235.10.227])
        by smtp.gmail.com with ESMTPSA id b18sm3174795lfp.89.2020.10.19.01.41.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Oct 2020 01:41:53 -0700 (PDT)
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
	Ahmad Fatoum <a.fatoum@pengutronix.de>,
	Linus Walleij <linus.walleij@linaro.org>
Subject: [PATCH 2/5 v16] ARM: Replace string mem* functions for KASan
Date: Mon, 19 Oct 2020 10:41:37 +0200
Message-Id: <20201019084140.4532-3-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20201019084140.4532-1-linus.walleij@linaro.org>
References: <20201019084140.4532-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=qsq4dLf9;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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
Tested-by: Florian Fainelli <f.fainelli@gmail.com> # Brahma SoCs
Tested-by: Ahmad Fatoum <a.fatoum@pengutronix.de> # i.MX6Q
Reported-by: Russell King - ARM Linux <linux@armlinux.org.uk>
Signed-off-by: Ahmad Fatoum <a.fatoum@pengutronix.de>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
---
ChangeLog v15->v16:
- Fold in Ahmad Fatoum's fixup for fortify
- Collect Florian's Tested-by
- Resend with the other patches
ChangeLog v14->v15:
- Resend with the other patches
ChangeLog v13->v14:
- Resend with the other patches
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
 arch/arm/include/asm/string.h     | 26 ++++++++++++++++++++++++++
 arch/arm/kernel/head-common.S     |  4 ++--
 arch/arm/lib/memcpy.S             |  3 +++
 arch/arm/lib/memmove.S            |  5 ++++-
 arch/arm/lib/memset.S             |  3 +++
 6 files changed, 57 insertions(+), 3 deletions(-)

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
index 111a1d8a41dd..6c607c68f3ad 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201019084140.4532-3-linus.walleij%40linaro.org.
