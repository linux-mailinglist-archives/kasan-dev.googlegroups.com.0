Return-Path: <kasan-dev+bncBDE6RCFOWIARBLFRRT4AKGQEHIS2Q6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id E67F921572F
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Jul 2020 14:27:24 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id h7sf2503412ljc.13
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Jul 2020 05:27:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594038444; cv=pass;
        d=google.com; s=arc-20160816;
        b=R7AuH2noBDkvpI/z/V+uqBB9dGGTbjY+InE+bnhfyqoBdaNUzIqg29o+Lr7sjj611E
         +3EuDX1UW08pV9OKd2lRKuDSLoh9hwCB5MlGx17H6xf68mDG2s7/6mhsloSHOMJZaQau
         y9rSz3GpOayvlT/iidUvUxJ5GAd0j6M4FeVlLmtpXhUTm4924b3lcIVbeewQ3mm7QwUG
         0LWIUwEfP8tpc5wgu8OQwmAikmIFlvyy0jcLw6hcaydd8pyYJCQ59n/SInVAh0JPa69O
         /FNAhdLeZmDA0RpEhKoopjTfmewIpPHtUbIYlQDfeQnXLCoLk18YVy7eiiNMW/qAX+mG
         3RfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Bu7hMzEdZ8woG6pozvQdAzODeyGoQyVqDxjFSHiM0Dc=;
        b=GUpkAualS16JCpMas1/CLqrLEtty7Iey5IcKb0OT6YSKS41QEFhTs2Q2noSCpIE7vR
         mhtsVhyMefC/4z3xPgU3RXu27kB0wAVDjWMzhhwSKWR+6YmShBHemWrer5K0wSwPQ+Bl
         Fus2jsIUWQFz3w5OBJ9qXvH2wug5gaY07Odz8sREQXpUXiV3x83W+k/ZL3jGuZElfOCM
         hr/gvqLWvQpS1lpVxq86J+OK40cmkljCXWdh2F5xOk4mxaormBTZEBa7yUKu+p3q4Qzv
         chcPmoZEfLGINAU4KhXTPdfzrF9pww6vxudSmyGrolzCY6BoT02p5B2LDNeq5Q+Zv78T
         FwJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=ibgq0jKV;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Bu7hMzEdZ8woG6pozvQdAzODeyGoQyVqDxjFSHiM0Dc=;
        b=dbX+CPHJJGX+S6+UAY56e9AhhlLvOL9Q8RGpbVdSfc/CFyJzQOcU7evZqGuUSCcyyP
         5CBpmIPejv0xhMztBezNVLtWZmBNFpi4BQ087sgCUtVviCSpyo/b/2Q5NqbwLYUlWpst
         oBNmcbt6Nia9RQBuXD6/f4gF34yhfF9bjOAGRaqoq/QZEWewdT78NcHdyP5yKqXMaGRT
         uv5h8ISJqU4XJk3gOu9LLFD7erlJcoZt/qjDTZ/H7fmwisxx84/JB6tugPXKF2krVfAa
         xQqO3+12S+0x5gFaCM/EqorlfTPs46LoVE9PDgi+sHTDqJdfX9nOabX52YAIdTTIZETK
         dWcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Bu7hMzEdZ8woG6pozvQdAzODeyGoQyVqDxjFSHiM0Dc=;
        b=j93d5KNytMNqegaNVmicrBd/N9AHoEYmS7za/7rhww27/GGKTKkAqnlJl3Gm9tW7jY
         1aoiiTTgVxN8m+Tbhn39y7RoV/sHGtPhH62Yyt6yZ8awddh/UNi5hdvEp65wrqFZCcZ4
         pnv0sCF68806hOCM6Tw82m8HevApcl/gkEvZiotOWCgRYHE/xm7Pq9AyeyKloIXpo8iZ
         cJ5yiYvT605U6jVgS+lZRD8WoBxUuOy/QNqCY0dzB0Az9UP1OzZWJk5mjpaRqluJnWyo
         Y0rS5efaIiRZOyj1CpIwVKFo17D7jyxudlM67oKpgc/TS26HGlIYH1PxUmgF3Fl2/IRz
         8TDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531LRAxTqKpWFvza8KeZZEpDzyDNwVgcYNjk/ur0Acng3CXwwfu4
	zi4za+nvS+5r0zaSLEe0uMo=
X-Google-Smtp-Source: ABdhPJzuKDLV2mcspEZ9DCGCtu1Lw8cKJETziAPM0qYsSMggcNjiweO6bR3+k6czYsBUp3xTnO6yOQ==
X-Received: by 2002:a19:8253:: with SMTP id e80mr30902170lfd.199.1594038444447;
        Mon, 06 Jul 2020 05:27:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9b09:: with SMTP id u9ls1190060lji.3.gmail; Mon, 06 Jul
 2020 05:27:23 -0700 (PDT)
X-Received: by 2002:a2e:3202:: with SMTP id y2mr25891014ljy.465.1594038443567;
        Mon, 06 Jul 2020 05:27:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594038443; cv=none;
        d=google.com; s=arc-20160816;
        b=KnBJev4aVo/NuOe/CIQ2uofXYwRtvCzjai/PLv/oGQ7HdgGe04eIy8WzSkI4SzAH6A
         eH6MjPfpiPUoFnP32t/Ze7OUjQGS2tS6ZmiGC9jtEnwFb9oiCA9UOBiUsXnbwejYDhkj
         xb3+6LJx1CBy55oe+mEXO8Re4Oaxz3DvBSc2mV/BPSS6USgTWItNQLC28UGqg9TFQZN3
         nMq3KO/PZjfl8i6uHMhhXVGrUncYM2szzQp+5H88v+9TRdQVnDqWSr+xP6HdYAgtODfI
         XddTJ+gMBfspTSwjZTMF7MoWf+tuLIs8LBBPRAdj4Di1197CdU+dr5q7SHCJLMMZ5+iS
         4b6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1A8YCq50wExCr2hUW80GcWITtwg/32luf7UVFQetnb4=;
        b=yIskeS4A4lk/aJqKLaJJem48RYpe49cWVpn19Lo+p3tDZ7w/K5njR3JdIhEEQu4Pop
         TPfFDe+Krvw4aNyN2hTZiTHCUPtLptIreQCQz5+RiEO13nXRpRUpO/0TjAAVCq8vTdxf
         GSKuQE2LZjdlsCrFHRK9hmqXcMfDGu8nmU969XyjrdgonJMLRKaoiT+Vb4SePnRUb5Ty
         3qHgHhnkzvDg8qowLZQjVYZAZLebJ9wksZiJfZpeqa39Xrfyjshoy3nWqhXFL8/i4o7r
         L6k9C9eMnUqaebm90sltDy+QOPFr4UGBq6WrFptrCyyYeP17GEI6PcIYFUSfyoNAlf9P
         HGXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=ibgq0jKV;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x244.google.com (mail-lj1-x244.google.com. [2a00:1450:4864:20::244])
        by gmr-mx.google.com with ESMTPS id k10si1128564lji.2.2020.07.06.05.27.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Jul 2020 05:27:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) client-ip=2a00:1450:4864:20::244;
Received: by mail-lj1-x244.google.com with SMTP id z24so20170785ljn.8
        for <kasan-dev@googlegroups.com>; Mon, 06 Jul 2020 05:27:23 -0700 (PDT)
X-Received: by 2002:a2e:7615:: with SMTP id r21mr18478201ljc.124.1594038443258;
        Mon, 06 Jul 2020 05:27:23 -0700 (PDT)
Received: from localhost.localdomain (c-92d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.146])
        by smtp.gmail.com with ESMTPSA id v20sm8534223lfr.74.2020.07.06.05.27.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Jul 2020 05:27:22 -0700 (PDT)
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
Subject: [PATCH 2/5 v12] ARM: Replace string mem* functions for KASan
Date: Mon,  6 Jul 2020 14:24:44 +0200
Message-Id: <20200706122447.696786-3-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.25.4
In-Reply-To: <20200706122447.696786-1-linus.walleij@linaro.org>
References: <20200706122447.696786-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=ibgq0jKV;       spf=pass
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
2.25.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200706122447.696786-3-linus.walleij%40linaro.org.
