Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBUMXT6QKGQEPCBPTKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 643812B282E
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:43 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id c8sf4681106wrh.16
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305863; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qqyb2XRafITq9OlayefVo8a+wweQ9s7ioQUe27ME4KzXA41n8DtxfFS5K3b61Foh5K
         tfp03zJC+Hmo9sg4NLqLnPZtN8ephr9ZbY0Hiqp6CHBsvJL6GtzGDiCDehQJHfMC3z6M
         wtPi3B/aTK1w5cG+CGBAgU+GH0AYbgj5ezR6CLhieloZgvDGCwYVmGq1HZxbwQYf1clY
         HsLU8DyjpoioAuE5jdZ9iaJ5IOXJkUhhDJc09ni1P3Wvsc5+SoCMuEOR/F9hvO96cQtm
         ktX01hx95DQ089ZdAqyE275ba/pRWKCixsbGuHM5MNmtkhJBrfEIAswFxcQULoScJH4Y
         ERvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=4PB/jI+KlgNv03joUXRUM9l/vZsA5l4UyTq+KzOV/EU=;
        b=yaVnJMIqf8MMgUb0FlqG+N7++LCk0pK8KgXHj2fkCtqzVI8QxnYABFJnK/+Lviavl5
         d8s30w7Jc+oCEVmRdHp5er3is+C6Bo/EbCXa/jGqKh4tkDzYH6P3ye7kX3cLysGKHbTQ
         +9wzzjy4NO6Q5xEFAPX6Lcjo17uxBLgUwWUQy5HiGv05W2GT/JNGDZCJ/wqLHDWWbwU6
         GYElZ+X+md4+YDMKXKLGo11cJZsJr3sgZ8sEmiiDlXrvnAwHWhZiZUv7VvFm6TVOHFZu
         auU2P/vj0U1Were84wn2g/3yZx+kmtjhdYLu2srLnhtLIVGKDpvtIGEOIdN0CMTJ3Q8d
         yo6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Zc1brT0O;
       spf=pass (google.com: domain of 3bqavxwokcdaw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3BQavXwoKCdAw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4PB/jI+KlgNv03joUXRUM9l/vZsA5l4UyTq+KzOV/EU=;
        b=BKfGGUN3nbVyEDGCYYWEK6G97DcFpU8jyCbo0ZCZsoB/JNCv5Ut+C/NV+PkpQJJCpX
         gXMF/z6F3CZ19QTrXrCQHcvKB4ht7rTgbN4Chm52TtF+I04flMnVmQI7ucUXdpKD+K1k
         UNaRYUvt3ajUjqXAJHcW6dCjkb8QvcfcoepUdxn+oUFiKMw1CjXoO1j8FVPCCFC6B7AX
         U+qxtYthAo/SlLPvBdk4bt5sjNVZVlxTd1xjmPM8ljmfpXebfs4MM7uOJrdV+WH90zeP
         rcpDayve2TKS535GtBJCiduvmrFIKHq3M9gW/VaE0jX3dViPASba3ws5KLGzlmB2+E4f
         8+QQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4PB/jI+KlgNv03joUXRUM9l/vZsA5l4UyTq+KzOV/EU=;
        b=XM1qUx2LvffvUqLoffrmlhMOhDULvLSHYwSg42mm55FgUbkv/P4mzHcbRPwGuYl7Uq
         pQdBYxF0ciTUWWr++7HxZcZ1YpdyvWpV2IflCIcFp9u9oIb9BB52Wm21VYA9JivWGqac
         KrtoVGTEjWqbd5I3qravh/F25JpfE//P8e1CJ4YDb4wDxGf0jr2p4OKC2zer225Ij8xH
         94hr/y8UAgvsLvng5RSjSYhipJmiGqPiyN0GUKM163vkrvq32obk8Nk1+M0yRSivm+//
         HcI0UFPis2ekWFPhE51WQoviwMZiOFPUsMbV+5TKemdWSX0NbJyuUAwUtOLpnenQO+b1
         f6Zg==
X-Gm-Message-State: AOAM532T/iJFyeqsnIJowSdXhuSd71BfTyOC8TaQBfbdFNK9owVsayGV
	zW/5L3MnI2RFDXEz7uuYQBM=
X-Google-Smtp-Source: ABdhPJy85fAKoKv46PKEzfQMldWvqTMRayFiWjYqyoFYFj8lDD/xzYT+B0ZlnbAhlfPaAh0jnZqh6A==
X-Received: by 2002:a1c:c302:: with SMTP id t2mr4703216wmf.189.1605305863073;
        Fri, 13 Nov 2020 14:17:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:3d87:: with SMTP id k129ls3719429wma.3.gmail; Fri, 13
 Nov 2020 14:17:42 -0800 (PST)
X-Received: by 2002:a7b:c848:: with SMTP id c8mr4506652wml.86.1605305862191;
        Fri, 13 Nov 2020 14:17:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305862; cv=none;
        d=google.com; s=arc-20160816;
        b=ur+ioBoCJjQOknjZej7cowXOBspqTd3xoWJDaYnkd98qtk5ahWOxFnlxZj3F+Re0Zv
         xuOd7O1OByh5XISohS66hEAfoW6xwWM+StTNWe/3BTkvt6X+ImvqMCuoBzB6piH7+IpG
         /RUTgPndz0JlAAQWsHmbyGDpJZYWKBq1hM0qT2Q+iMdbJV0qbjn2tGaX7M3RjTRR4pxM
         6KOnOTEQrAQlSa5Cji3uitKXKweCwqVfaQDb/2+Y9pEcdfV15ZHBeqTvrhqUAY9jCE4B
         BAipXx/5oePFpKOdUmi1GrUxaIwZjcfNNHD8p6S1p8HqgHPNPPEw6lLLrOh3s3IIccFb
         zS/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=PhsKgt0KbD6/iQ9mx8Qd5Hkwe5dKUS1gqPkSLXypIOM=;
        b=v4dxda9ViTe+0DqjyJ6kFX2w/4XZ8JM+gRONP0kCeeKBn8g8c0jfISvvRAEaOhU6uo
         qUL3RHq9GwS9nkff6zR81X12rS7jh/Pdd07w5z/Y5C9KthE1r0dMwk3gR30dARdINov3
         z+Nn6NYLEI3u+oTnXelrpqI0l4I7+3jzE9qliU5nFhkET6gF8G/e+mLV5okZukoFFE/s
         tYDCbdfzYgUjLPCg78uQO56jW/a68+IUWKh6uuUqZ1M+2ZSOMJ5JaiicVulY4X3QHyuk
         mCMr62yYXqjPr2oCz2or/YD+VUsZK/j1oUxnaxQ8O6TodPiomOcleakxLZB6WaDOakxc
         NqIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Zc1brT0O;
       spf=pass (google.com: domain of 3bqavxwokcdaw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3BQavXwoKCdAw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id r21si363312wra.4.2020.11.13.14.17.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:42 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bqavxwokcdaw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id f21so4884872ejf.11
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:42 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6402:370:: with SMTP id
 s16mr4706748edw.50.1605305861635; Fri, 13 Nov 2020 14:17:41 -0800 (PST)
Date: Fri, 13 Nov 2020 23:16:04 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <3c20c41d464ce3d994a9fa0fee2ce2f3dd378cba.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 36/42] kasan, arm64: expand CONFIG_KASAN checks
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Zc1brT0O;       spf=pass
 (google.com: domain of 3bqavxwokcdaw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3BQavXwoKCdAw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Some #ifdef CONFIG_KASAN checks are only relevant for software KASAN
modes (either related to shadow memory or compiler instrumentation).
Expand those into CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I91e661e2c1627783cb845d877c6371dfc8779505
---
 arch/arm64/Kconfig                 |  2 +-
 arch/arm64/Makefile                |  2 +-
 arch/arm64/include/asm/assembler.h |  2 +-
 arch/arm64/include/asm/memory.h    |  2 +-
 arch/arm64/include/asm/string.h    |  5 +++--
 arch/arm64/kernel/head.S           |  2 +-
 arch/arm64/kernel/image-vars.h     |  2 +-
 arch/arm64/kernel/kaslr.c          |  3 ++-
 arch/arm64/kernel/module.c         |  6 ++++--
 arch/arm64/mm/ptdump.c             |  6 +++---
 include/linux/kasan-checks.h       |  2 +-
 include/linux/kasan.h              |  7 ++++---
 include/linux/moduleloader.h       |  3 ++-
 include/linux/string.h             |  2 +-
 mm/ptdump.c                        | 13 ++++++++-----
 scripts/Makefile.lib               |  2 ++
 16 files changed, 36 insertions(+), 25 deletions(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index b7d1f1a5705d..b732c8280fc1 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -333,7 +333,7 @@ config BROKEN_GAS_INST
 
 config KASAN_SHADOW_OFFSET
 	hex
-	depends on KASAN
+	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	default 0xdfff800000000000 if (ARM64_VA_BITS_48 || ARM64_VA_BITS_52) && !KASAN_SW_TAGS
 	default 0xdfffc00000000000 if ARM64_VA_BITS_47 && !KASAN_SW_TAGS
 	default 0xdffffe0000000000 if ARM64_VA_BITS_42 && !KASAN_SW_TAGS
diff --git a/arch/arm64/Makefile b/arch/arm64/Makefile
index 50ad9cbccb51..0b31a3f06f15 100644
--- a/arch/arm64/Makefile
+++ b/arch/arm64/Makefile
@@ -141,7 +141,7 @@ head-y		:= arch/arm64/kernel/head.o
 
 ifeq ($(CONFIG_KASAN_SW_TAGS), y)
 KASAN_SHADOW_SCALE_SHIFT := 4
-else
+else ifeq ($(CONFIG_KASAN_GENERIC), y)
 KASAN_SHADOW_SCALE_SHIFT := 3
 endif
 
diff --git a/arch/arm64/include/asm/assembler.h b/arch/arm64/include/asm/assembler.h
index ddbe6bf00e33..bf125c591116 100644
--- a/arch/arm64/include/asm/assembler.h
+++ b/arch/arm64/include/asm/assembler.h
@@ -473,7 +473,7 @@ USER(\label, ic	ivau, \tmp2)			// invalidate I line PoU
 #define NOKPROBE(x)
 #endif
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define EXPORT_SYMBOL_NOKASAN(name)
 #else
 #define EXPORT_SYMBOL_NOKASAN(name)	EXPORT_SYMBOL(name)
diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 3bc08e6cf82e..cd671fb6707c 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -72,7 +72,7 @@
  * address space for the shadow region respectively. They can bloat the stack
  * significantly, so double the (minimum) stack size when they are in use.
  */
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
 #define KASAN_SHADOW_END	((UL(1) << (64 - KASAN_SHADOW_SCALE_SHIFT)) \
 					+ KASAN_SHADOW_OFFSET)
diff --git a/arch/arm64/include/asm/string.h b/arch/arm64/include/asm/string.h
index b31e8e87a0db..3a3264ff47b9 100644
--- a/arch/arm64/include/asm/string.h
+++ b/arch/arm64/include/asm/string.h
@@ -5,7 +5,7 @@
 #ifndef __ASM_STRING_H
 #define __ASM_STRING_H
 
-#ifndef CONFIG_KASAN
+#if !(defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS))
 #define __HAVE_ARCH_STRRCHR
 extern char *strrchr(const char *, int c);
 
@@ -48,7 +48,8 @@ extern void *__memset(void *, int, __kernel_size_t);
 void memcpy_flushcache(void *dst, const void *src, size_t cnt);
 #endif
 
-#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
+#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
+	!defined(__SANITIZE_ADDRESS__)
 
 /*
  * For files that are not instrumented (e.g. mm/slub.c) we
diff --git a/arch/arm64/kernel/head.S b/arch/arm64/kernel/head.S
index d8d9caf02834..fdcb99d7ba23 100644
--- a/arch/arm64/kernel/head.S
+++ b/arch/arm64/kernel/head.S
@@ -448,7 +448,7 @@ SYM_FUNC_START_LOCAL(__primary_switched)
 	bl	__pi_memset
 	dsb	ishst				// Make zero page visible to PTW
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	bl	kasan_early_init
 #endif
 #ifdef CONFIG_RANDOMIZE_BASE
diff --git a/arch/arm64/kernel/image-vars.h b/arch/arm64/kernel/image-vars.h
index c615b285ff5b..4282edd2fe81 100644
--- a/arch/arm64/kernel/image-vars.h
+++ b/arch/arm64/kernel/image-vars.h
@@ -37,7 +37,7 @@ __efistub_strncmp		= __pi_strncmp;
 __efistub_strrchr		= __pi_strrchr;
 __efistub___clean_dcache_area_poc = __pi___clean_dcache_area_poc;
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 __efistub___memcpy		= __pi_memcpy;
 __efistub___memmove		= __pi_memmove;
 __efistub___memset		= __pi_memset;
diff --git a/arch/arm64/kernel/kaslr.c b/arch/arm64/kernel/kaslr.c
index b181e0544b79..e8e17e91aa02 100644
--- a/arch/arm64/kernel/kaslr.c
+++ b/arch/arm64/kernel/kaslr.c
@@ -151,7 +151,8 @@ u64 __init kaslr_early_init(u64 dt_phys)
 	/* use the top 16 bits to randomize the linear region */
 	memstart_offset_seed = seed >> 48;
 
-	if (IS_ENABLED(CONFIG_KASAN))
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
+	    IS_ENABLED(CONFIG_KASAN_SW_TAGS))
 		/*
 		 * KASAN does not expect the module region to intersect the
 		 * vmalloc region, since shadow memory is allocated for each
diff --git a/arch/arm64/kernel/module.c b/arch/arm64/kernel/module.c
index 2a1ad95d9b2c..fe21e0f06492 100644
--- a/arch/arm64/kernel/module.c
+++ b/arch/arm64/kernel/module.c
@@ -30,7 +30,8 @@ void *module_alloc(unsigned long size)
 	if (IS_ENABLED(CONFIG_ARM64_MODULE_PLTS))
 		gfp_mask |= __GFP_NOWARN;
 
-	if (IS_ENABLED(CONFIG_KASAN))
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
+	    IS_ENABLED(CONFIG_KASAN_SW_TAGS))
 		/* don't exceed the static module region - see below */
 		module_alloc_end = MODULES_END;
 
@@ -39,7 +40,8 @@ void *module_alloc(unsigned long size)
 				NUMA_NO_NODE, __builtin_return_address(0));
 
 	if (!p && IS_ENABLED(CONFIG_ARM64_MODULE_PLTS) &&
-	    !IS_ENABLED(CONFIG_KASAN))
+	    !IS_ENABLED(CONFIG_KASAN_GENERIC) &&
+	    !IS_ENABLED(CONFIG_KASAN_SW_TAGS))
 		/*
 		 * KASAN can only deal with module allocations being served
 		 * from the reserved module region, since the remainder of
diff --git a/arch/arm64/mm/ptdump.c b/arch/arm64/mm/ptdump.c
index 807dc634bbd2..04137a8f3d2d 100644
--- a/arch/arm64/mm/ptdump.c
+++ b/arch/arm64/mm/ptdump.c
@@ -29,7 +29,7 @@
 enum address_markers_idx {
 	PAGE_OFFSET_NR = 0,
 	PAGE_END_NR,
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	KASAN_START_NR,
 #endif
 };
@@ -37,7 +37,7 @@ enum address_markers_idx {
 static struct addr_marker address_markers[] = {
 	{ PAGE_OFFSET,			"Linear Mapping start" },
 	{ 0 /* PAGE_END */,		"Linear Mapping end" },
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	{ 0 /* KASAN_SHADOW_START */,	"Kasan shadow start" },
 	{ KASAN_SHADOW_END,		"Kasan shadow end" },
 #endif
@@ -383,7 +383,7 @@ void ptdump_check_wx(void)
 static int ptdump_init(void)
 {
 	address_markers[PAGE_END_NR].start_address = PAGE_END;
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	address_markers[KASAN_START_NR].start_address = KASAN_SHADOW_START;
 #endif
 	ptdump_initialize();
diff --git a/include/linux/kasan-checks.h b/include/linux/kasan-checks.h
index ac6aba632f2d..ca5e89fb10d3 100644
--- a/include/linux/kasan-checks.h
+++ b/include/linux/kasan-checks.h
@@ -9,7 +9,7 @@
  * even in compilation units that selectively disable KASAN, but must use KASAN
  * to validate access to an address.   Never use these in header files!
  */
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 bool __kasan_check_read(const volatile void *p, unsigned int size);
 bool __kasan_check_write(const volatile void *p, unsigned int size);
 #else
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 8b8babab852c..118a57517281 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -237,7 +237,8 @@ static inline void kasan_release_vmalloc(unsigned long start,
 
 #endif /* CONFIG_KASAN_VMALLOC */
 
-#if defined(CONFIG_KASAN) && !defined(CONFIG_KASAN_VMALLOC)
+#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
+		!defined(CONFIG_KASAN_VMALLOC)
 
 /*
  * These functions provide a special case to support backing module
@@ -247,12 +248,12 @@ static inline void kasan_release_vmalloc(unsigned long start,
 int kasan_module_alloc(void *addr, size_t size);
 void kasan_free_shadow(const struct vm_struct *vm);
 
-#else /* CONFIG_KASAN && !CONFIG_KASAN_VMALLOC */
+#else /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASAN_VMALLOC */
 
 static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
 static inline void kasan_free_shadow(const struct vm_struct *vm) {}
 
-#endif /* CONFIG_KASAN && !CONFIG_KASAN_VMALLOC */
+#endif /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASAN_VMALLOC */
 
 #ifdef CONFIG_KASAN_INLINE
 void kasan_non_canonical_hook(unsigned long addr);
diff --git a/include/linux/moduleloader.h b/include/linux/moduleloader.h
index 4fa67a8b2265..9e09d11ffe5b 100644
--- a/include/linux/moduleloader.h
+++ b/include/linux/moduleloader.h
@@ -96,7 +96,8 @@ void module_arch_cleanup(struct module *mod);
 /* Any cleanup before freeing mod->module_init */
 void module_arch_freeing_init(struct module *mod);
 
-#if defined(CONFIG_KASAN) && !defined(CONFIG_KASAN_VMALLOC)
+#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
+		!defined(CONFIG_KASAN_VMALLOC)
 #include <linux/kasan.h>
 #define MODULE_ALIGN (PAGE_SIZE << KASAN_SHADOW_SCALE_SHIFT)
 #else
diff --git a/include/linux/string.h b/include/linux/string.h
index b1f3894a0a3e..016a157e2251 100644
--- a/include/linux/string.h
+++ b/include/linux/string.h
@@ -266,7 +266,7 @@ void __write_overflow(void) __compiletime_error("detected write beyond size of o
 
 #if !defined(__NO_FORTIFY) && defined(__OPTIMIZE__) && defined(CONFIG_FORTIFY_SOURCE)
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 extern void *__underlying_memchr(const void *p, int c, __kernel_size_t size) __RENAME(memchr);
 extern int __underlying_memcmp(const void *p, const void *q, __kernel_size_t size) __RENAME(memcmp);
 extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t size) __RENAME(memcpy);
diff --git a/mm/ptdump.c b/mm/ptdump.c
index ba88ec43ff21..4354c1422d57 100644
--- a/mm/ptdump.c
+++ b/mm/ptdump.c
@@ -4,7 +4,7 @@
 #include <linux/ptdump.h>
 #include <linux/kasan.h>
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 /*
  * This is an optimization for KASAN=y case. Since all kasan page tables
  * eventually point to the kasan_early_shadow_page we could call note_page()
@@ -31,7 +31,8 @@ static int ptdump_pgd_entry(pgd_t *pgd, unsigned long addr,
 	struct ptdump_state *st = walk->private;
 	pgd_t val = READ_ONCE(*pgd);
 
-#if CONFIG_PGTABLE_LEVELS > 4 && defined(CONFIG_KASAN)
+#if CONFIG_PGTABLE_LEVELS > 4 && \
+		(defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS))
 	if (pgd_page(val) == virt_to_page(lm_alias(kasan_early_shadow_p4d)))
 		return note_kasan_page_table(walk, addr);
 #endif
@@ -51,7 +52,8 @@ static int ptdump_p4d_entry(p4d_t *p4d, unsigned long addr,
 	struct ptdump_state *st = walk->private;
 	p4d_t val = READ_ONCE(*p4d);
 
-#if CONFIG_PGTABLE_LEVELS > 3 && defined(CONFIG_KASAN)
+#if CONFIG_PGTABLE_LEVELS > 3 && \
+		(defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS))
 	if (p4d_page(val) == virt_to_page(lm_alias(kasan_early_shadow_pud)))
 		return note_kasan_page_table(walk, addr);
 #endif
@@ -71,7 +73,8 @@ static int ptdump_pud_entry(pud_t *pud, unsigned long addr,
 	struct ptdump_state *st = walk->private;
 	pud_t val = READ_ONCE(*pud);
 
-#if CONFIG_PGTABLE_LEVELS > 2 && defined(CONFIG_KASAN)
+#if CONFIG_PGTABLE_LEVELS > 2 && \
+		(defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS))
 	if (pud_page(val) == virt_to_page(lm_alias(kasan_early_shadow_pmd)))
 		return note_kasan_page_table(walk, addr);
 #endif
@@ -91,7 +94,7 @@ static int ptdump_pmd_entry(pmd_t *pmd, unsigned long addr,
 	struct ptdump_state *st = walk->private;
 	pmd_t val = READ_ONCE(*pmd);
 
-#if defined(CONFIG_KASAN)
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	if (pmd_page(val) == virt_to_page(lm_alias(kasan_early_shadow_pte)))
 		return note_kasan_page_table(walk, addr);
 #endif
diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
index 94133708889d..213677a5ed33 100644
--- a/scripts/Makefile.lib
+++ b/scripts/Makefile.lib
@@ -148,10 +148,12 @@ endif
 # we don't want to check (depends on variables KASAN_SANITIZE_obj.o, KASAN_SANITIZE)
 #
 ifeq ($(CONFIG_KASAN),y)
+ifneq ($(CONFIG_KASAN_HW_TAGS),y)
 _c_flags += $(if $(patsubst n%,, \
 		$(KASAN_SANITIZE_$(basetarget).o)$(KASAN_SANITIZE)y), \
 		$(CFLAGS_KASAN), $(CFLAGS_KASAN_NOSANITIZE))
 endif
+endif
 
 ifeq ($(CONFIG_UBSAN),y)
 _c_flags += $(if $(patsubst n%,, \
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3c20c41d464ce3d994a9fa0fee2ce2f3dd378cba.1605305705.git.andreyknvl%40google.com.
