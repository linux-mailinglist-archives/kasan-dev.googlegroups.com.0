Return-Path: <kasan-dev+bncBDE6RCFOWIARBOXTTT3QKGQEH2JKE7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FF701F92A4
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 11:04:59 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id l18sf6833608wrm.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 02:04:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592211898; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZkXglmnRcJ3aknrbtUq7qk0l5DsDOWqxXHhZWK9UVY7eN9a/e893BZrumWPUl66nUg
         aTwxTK07GZP5W4C5xWT5O2tgsFHA5mvKproeNihUik+FBrm5K1wQ8URAsns2AuFj0S1L
         TJVHBUZqBGp3cZtNrR6KtbEW3axyBqXU0KTku3Bbya/JGlSlQDxO6/5hIqD0OqFl411e
         f0d4/fNZeNzV+SDS0mE75t0sT1x+gKv9NMDFXAsVYZ2EkUPKM3Ss0Y5ziM+cqxTNiX3N
         gQ/WTp1KAa8bXrLMcxI6sp0+DkMGMX3TaJc21xD3Z+cyPEJTHs3cT/cMdBniClU0JS1A
         Tucw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=eXixCMnTmIIc4Ad9AzBotcPTWVnKI8rUWfAWd9Ef2l8=;
        b=ixMN/Xp6r3Z0rJ5dQLM2DtGBACyoA1w0LvbIp3e4HQawisJDR6KnRddQRhZjQRKs/U
         fSyNp8yOLTBTZWLRnye/SQngP0aoYLbUJbnKYOoeFNHQRtDl2CmqdnQOoQm1DFDBGLjW
         Jf/Fjo7FkU4mYnjxeerCkqj6yFH9bPeIVerNtBqLJaDreTzxBH2bvvwgTs0RpQL5SRto
         hvU5KmoiLxTpMDZlaNgPHtlR8NMgMCixybvYOFC5Fqr+eckL81BI+7vdUfhHvOVFCKAz
         BjJBubqH2IEZLZHBQZrp08u0AIKJTSSE0M9x0SDNKeOZeSw4MEYLfXPAGELvGfwaLU9R
         xmfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=X8CHaxPb;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eXixCMnTmIIc4Ad9AzBotcPTWVnKI8rUWfAWd9Ef2l8=;
        b=eQL2f8TOi8+FHv3NRLxIsv9UMVUXMfpB5EM+K8c7W8XvcuDR1kAdZPAEw1B8v4pQ+n
         +hVrO7URaQc8cGqvXhieRTgih6WBObVDt8c6Dux5MmuD2se/PDRTDAfCfzSzWkQ4Hr6/
         Zka9d6sAP3T7878GJZlUmjGYfSmaumcSRDyNYSwx+nGqopZCLoxPp4uaPwB8sq1Ki91a
         5NxKeKQyDgfIW2gMpg6gdjrOiTKda1etexWE05tnuS6WTREy9EsrH3wBPCH5mcEHx0W2
         OYu6cEgVR5tCxFlZT5ZvgEFzOebV0KSlxyc79WpsdAeqtar9InsKdI84RSZj13qWZlTg
         NlaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eXixCMnTmIIc4Ad9AzBotcPTWVnKI8rUWfAWd9Ef2l8=;
        b=Pp7LZ9VtfbH/39e5m3La2kd6fgSj+m2E1EJsxMxAscplsJ/2xGZEGN3dl89NNRcZy4
         p5syjCdlaxKX2InWUZsaL28lawa22V1MzzRWo6QhQ95UR8gwqa7Bf60reZF8Kgoju3s9
         WpQcItSGwvBzNsF4QQIAY70VIwostRz1shWtsF+qM3s4Q78jwxGaQDJKbQqgRi/fN+Ll
         7YzsN35gePIYrRStv6xwBpGEstx63X+DNcaC2d8evRGk9dGQVg1U2MKgpNezlC0OZLZM
         pWy3fumd5qiahKwlKV9OxiWLwPPdUi5Gp48aexG81p77FFsl0vugiKzteg6RWzLKZmDO
         ELgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ngHej0qe0dRbGnkjKkx6Tbl+eotwRYq8S0wsoWMUKMAjafIIT
	63m7Y6iQzGHtiUVHOjJk22w=
X-Google-Smtp-Source: ABdhPJzcWjeKSqN/w/ucc55e586ArgQgdtpnn0pNyhY4bhzBI4wLjUctHO06fY2LE4zXtvqzZaQ/lQ==
X-Received: by 2002:adf:e749:: with SMTP id c9mr30121686wrn.25.1592211898740;
        Mon, 15 Jun 2020 02:04:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2885:: with SMTP id o127ls6297995wmo.0.canary-gmail;
 Mon, 15 Jun 2020 02:04:58 -0700 (PDT)
X-Received: by 2002:a1c:2d4d:: with SMTP id t74mr12848109wmt.177.1592211898256;
        Mon, 15 Jun 2020 02:04:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592211898; cv=none;
        d=google.com; s=arc-20160816;
        b=SUMczVMgXbLzsgvCkrQaoosLDQkfNTcRuNL+25Bx45ph9ZrfhgRYqUR89VVGcZ8odI
         SmVgHS1CjZ/TqqAlMLWTjjKOnmOXiz3sTMvn2/dIlUCLbPjC1APzZf2z4kdqqk/0dP5+
         FruMJFGWM33uWFgT08b3hKtSR0m4u4MbkBEyEUDaQNSj3zMxkM7bTFTP3KFyoPSeTcCN
         DA02zIS7m0P2d4cnoZTWeIFdl25T0c2JPxxJrf1GnpmQxX3da54mbqn8L+qOF2AKZjgD
         pfNIydF3v+oJT36H/8hFiivpwgZhloLxCM5APWZ2ojlQtU9kYkBY9hasz1uOscdN+75V
         1YZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ha1AQyVj4DRUvyXwEFSTntA3g7Ne5gREhowQe8O2ELc=;
        b=T7Fnr7+xgK1RBzzwp425cWHV2Ew+gzQ9qHSVsR+mUuBjhptcYwvwDr/9sBUuHNPNB2
         IYHLpdNRM5ZMxOEX6/SAbqo586xb+q2NjhQAtjraefFC00pBTunXk8clVtnXc7ipvqH9
         vTcknNkjb33TjxY3viEQQvPIFusEKToYbnUSIhFWMz94qerYTcIGV81h1F8rAHDtKpZl
         js9Yr0Fsj+VVq2m8ezQkZrcSfgN691E9866csnvSVnxl46aL6rQUtKjf9Pp8udmlfnLn
         Atm7gW7OBlyJfG5Qk0jmBp+GVdLMgXoU1FaF9fV/sT0/vZ5J6KCY5Euh8nFS1pP9ysgq
         03xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=X8CHaxPb;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id m20si830260wmc.0.2020.06.15.02.04.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Jun 2020 02:04:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id s1so18244806ljo.0
        for <kasan-dev@googlegroups.com>; Mon, 15 Jun 2020 02:04:58 -0700 (PDT)
X-Received: by 2002:a2e:1311:: with SMTP id 17mr12148476ljt.122.1592211897651;
        Mon, 15 Jun 2020 02:04:57 -0700 (PDT)
Received: from localhost.localdomain (c-92d7225c.014-348-6c756e10.bbcust.telenor.se. [92.34.215.146])
        by smtp.gmail.com with ESMTPSA id c78sm5284434lfd.63.2020.06.15.02.04.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jun 2020 02:04:56 -0700 (PDT)
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
Subject: [PATCH 2/5 v10] ARM: Replace string mem* functions for KASan
Date: Mon, 15 Jun 2020 11:02:44 +0200
Message-Id: <20200615090247.5218-3-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.25.4
In-Reply-To: <20200615090247.5218-1-linus.walleij@linaro.org>
References: <20200615090247.5218-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=X8CHaxPb;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615090247.5218-3-linus.walleij%40linaro.org.
