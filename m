Return-Path: <kasan-dev+bncBDX4HWEMTEBRBI5P5T6AKGQERGTDUEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A8C329F511
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:27:33 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id w78sf2946116pfc.15
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:27:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999652; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wj9id5RwmzxbkMB8O4mGbZSkjWMHiPrQRm12kHeA9qkgLS54dG9u5w5Qw60rdVzEmF
         OFaWK2iS79BdH0zHifSAX8TWsxRTAbWflVcx8gUAR1sZwS0YbLTPsfLMyvsEk167LDQx
         p3PSPGEu6JQJsJohqDiEFvmpx4Jx/TwltEgEJOgxKNeTF4zkMuu/QNEvXwZWyvWQWh4K
         2VJCa1EX3cP1+SpUtRAMSL7tAQwHk4nE/AHJjZwkQBx5HWIztWo/5b4nqZd+oVEkK0gW
         sR9OsxvXcBh8Etrr3LYJWR1HjZs9QS2b0w4oG5Og79RSIS5UE1+UjT6aa0ezTypFkXeS
         w94g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=kVWbKgbmZRPAK/AAoAnDfCblCWbSr0Y/zVrEmf/FnA8=;
        b=xTtbJXYVvofe/7quYM52ax+eGK52Tqa/mXmatJIa9q+NTor/DTui9h05+CYmljczkX
         QpNdu4ZF5FBbeJHPQ2XED48U3YrHAeJdbZdNnwp5c46qOm3zAPeg0qB3BsRixjWSNGmo
         VKrnUEu6Dt3XDUE3p1FHwH68GlI9AxwbVLrflJDdxoZYbxTuwe23lNUweJHubm3WYs52
         fwiufRVnR0B4Nb8dVnsxzc66YvO7kHr2auv/LFXmg97V/YEm2WssEixp7+exxoVQCluB
         CD8Kag+n1HE7f0KOBbb6sFRD4V97aoUvdLzxqD8viA4kB2YovAcJwM1YYFRwE70avRZr
         ybUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CvCmWldp;
       spf=pass (google.com: domain of 3ohebxwokcuedqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3ohebXwoKCUEdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kVWbKgbmZRPAK/AAoAnDfCblCWbSr0Y/zVrEmf/FnA8=;
        b=AlGlIb2hkh/tlfUpU0mVVKz1KL1OD848vzxIr0/bHPwa0zeQ0YnuLCKtPfTIgWKsOZ
         MuSnm7vGQs/8UZj3W8NcLtZmh3Xn1Qm5dhY/smjeTROugaVx6I35xzAAfMQHmPYluYZK
         LjF/n5qJbDmlwgqGG/G4w0+rfH2yOClp83I/xPizUy4h2FlzSRaUeolo25jYMZ1nm0Bn
         jyBD41d39WbXpQYTZ3gfMkwHnCT8yQOwJ5WHzRqmEu8/GQFHlofbaqf+iDIqHEqtCZtS
         rZ8WMdajtoNTUOepG6iedu2sd2+LQweCRDILPw61YWMlfwxkaCVjui19Y+x7kuJGbSg1
         D4Ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kVWbKgbmZRPAK/AAoAnDfCblCWbSr0Y/zVrEmf/FnA8=;
        b=JfrU9t2aKtUsqzDM04GUBicqiksyDcehCOKGvyTeG6Gvi9EAUg224+7+WRF7CjQlLC
         2fF99rkGgZbvpVQpTCf2bmx1d2gHldkX5AIN7vEdjSLLGqju21P3/mhIfH/G1yBameH3
         K4LwQXTifqBqOUw/LBQxvANTjPNuZ0yMja7tW5uGIEeNOn9tIxngbhoVYcQmtG3cCQGw
         gTojEuuIRiQdaqD+/aJQtQxcvyxXkPaz/aF1FDOOLAjg9nWtcFynEkPZXEKjJC3UCGGR
         14+IJnMBiV6M4vrwalB0oIEThGob9x6ZiPYQ7gpNycJ2sP3cxD669b+SkMT6iy8sIrdU
         jq8w==
X-Gm-Message-State: AOAM533GkvyNsGEwWYZDgwUz64i5LJuRjio9FGsQrW+0BTyxvDWRFIqv
	ZTNTM2Qes8AtSfLopgli8Z0=
X-Google-Smtp-Source: ABdhPJzMj7HZ3+ijp9npgKgI1I4+aXQxbPKRTts9LaO7xxXeR3h5v3KNsx62mBY8tXysDzSwHRe0VQ==
X-Received: by 2002:a17:90b:509:: with SMTP id r9mr702893pjz.125.1603999651867;
        Thu, 29 Oct 2020 12:27:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d246:: with SMTP id t6ls1423864pgi.3.gmail; Thu, 29 Oct
 2020 12:27:31 -0700 (PDT)
X-Received: by 2002:a63:1e5a:: with SMTP id p26mr5403965pgm.85.1603999651329;
        Thu, 29 Oct 2020 12:27:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999651; cv=none;
        d=google.com; s=arc-20160816;
        b=lnMXwKME5V6a8CdSedSP9ACLdjgJpB/QWWRQp0fFxnV6ybz1MoWnqQIUmjaSJjX2Ay
         cXPsLrgiEJqbkD8FfecQR9F78WiZ0lm0c4phUjpIXvi95GN+gWtTT9DZuxK4tq6dI6lP
         pyovD15MHfMmJYKR7CMsSK2shqplVhogHB4AD3NOZPXbuMHGfqYTse7PYAo0O2e015Mj
         bGtg26dDRzZZl1AeGhFSLvY1kHaJW9JfgIUU6M0Xumz67mK89vTBI+HsUU54R71KDdOo
         drQHR0ACgbnKQRtYF5KNJK1CDfhNkI7UxVgYANEFjIFKqXzhOfudFviCVMj4yMQhtzpp
         SbjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=gjfBuMYF3R5rRZdLHF/eEEXrUZ6msA7utGpDOYPXVzw=;
        b=ntBVESAcdvwVVI2OT++96FSJcf9Q8D4PbcMwz0qOm6VpwuN1RBZv5IvA526v0MXCLo
         ehuNtRz/4TO7q90kHxhquL/TS0R0Wl8rFlX6ePtz3nPRT/lCjWWNgRDX4sVrmma9sh1a
         dwbO49FW4sr4eE9Ow5TCC1jyPCYIiN49PO0sQHmrAXe5/YvRClL+fyx887kfRDTGVWen
         6iKzYoOdEop2lX4oDoBGlA+diaCzglDmIFZDGzL/QrP58TBw7QzREmnXIlH4VyAooRrJ
         QQbSjTOZx6u3mj5jXqAC4Kbd0q8R7/cFeKt5A+vW9rSlRgOayh6llpQsspBc3I4RGJrb
         d31A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CvCmWldp;
       spf=pass (google.com: domain of 3ohebxwokcuedqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3ohebXwoKCUEdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id bd7si216985plb.0.2020.10.29.12.27.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:27:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ohebxwokcuedqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id l16so1265253qvt.17
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:27:31 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:59cf:: with SMTP id
 el15mr6150849qvb.17.1603999650465; Thu, 29 Oct 2020 12:27:30 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:55 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <5e8c8e6b6be30db1641239e9fd5858a87eee9a16.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 34/40] kasan, arm64: expand CONFIG_KASAN checks
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CvCmWldp;       spf=pass
 (google.com: domain of 3ohebxwokcuedqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3ohebXwoKCUEdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
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
index 9e5049ffa160..11dbd880e6c0 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -330,7 +330,7 @@ config BROKEN_GAS_INST
 
 config KASAN_SHADOW_OFFSET
 	hex
-	depends on KASAN
+	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	default 0xdfffa00000000000 if (ARM64_VA_BITS_48 || ARM64_VA_BITS_52) && !KASAN_SW_TAGS
 	default 0xdfffd00000000000 if ARM64_VA_BITS_47 && !KASAN_SW_TAGS
 	default 0xdffffe8000000000 if ARM64_VA_BITS_42 && !KASAN_SW_TAGS
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
index 580d6ef17079..507012ed24f4 100644
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
index 61684a500914..f1f2833e06d8 100644
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
index 8d3d3c21340d..0661f5be5706 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -235,7 +235,8 @@ static inline void kasan_release_vmalloc(unsigned long start,
 
 #endif /* CONFIG_KASAN_VMALLOC */
 
-#if defined(CONFIG_KASAN) && !defined(CONFIG_KASAN_VMALLOC)
+#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
+		!defined(CONFIG_KASAN_VMALLOC)
 
 /*
  * These functions provide a special case to support backing module
@@ -245,12 +246,12 @@ static inline void kasan_release_vmalloc(unsigned long start,
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5e8c8e6b6be30db1641239e9fd5858a87eee9a16.1603999489.git.andreyknvl%40google.com.
