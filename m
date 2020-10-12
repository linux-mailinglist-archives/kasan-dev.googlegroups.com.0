Return-Path: <kasan-dev+bncBDX4HWEMTEBRBF4BSP6AKGQEND7C5EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FCC428C314
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:46:15 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id x16sf9384737wrg.7
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:46:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535575; cv=pass;
        d=google.com; s=arc-20160816;
        b=TbIkLXclZmNzmuZpy069k2GorUIKSu9Nt9ER2Mp4ybHJgAOtQCOeHkjFiyQS6RAKbj
         p+eZDDYQuIK1XGXXMOSDkJaa/1+Wfc7hvXNSXc5PGEqaYHGQX8xa3L5tEN397Rrgn+Ee
         v+HpRPEyYi0sJNArMVQB7xk8UtTVUwL8dOvWjeb+zCqBxGTA4VVqeJ3YuRhIrvbNEnXb
         Th7tk5W3X+Qcno8AXpKy3ugJiWLSFJLWGgr+KtLu+0+p8ACQdrMGLI5+yyIua3BZeBhs
         a+HdyT32d44mm2/lMVRxFcosoNJYasg7wciFbVst14DrandeAPjsbKt0xboCtR0KzIBZ
         G9TA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=sKGNaHnqkAXazcGeHmVvcu/NxP8ulG0SkSKWnW9ZDIY=;
        b=Syfz0cwemDklnC+os2c3dvPL8MN2jzmklLpoluazrGfE7nDJQ5dLsPQ8rsign9K7hv
         2LuHOhsVmylDS8I8o0c7jSZcg5ztkBEGyqXStKT05GmtxuZF1JcdY41cgqVusEq3fC0L
         2ZTUF50pa0xVf+JWihudeTKH3XCjcMGXfasDwZ04Q6MTdBqrAKboIM6u5q2HJUXjMcnV
         snsiPBMShiMXGQ8XXkwmxc5Kwuidopu/A4e5j6das+F06JtY1kyGObHKLGdRF6YOjszt
         6e0WQ8C9K8zcHIS4gJS7+7hDfhzs8IWY0uAQf5qDAp8OmhvIWToLjPylw6pLc5QE+1fR
         bYJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Vt1udr7z;
       spf=pass (google.com: domain of 3lccexwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3lcCEXwoKCSwIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sKGNaHnqkAXazcGeHmVvcu/NxP8ulG0SkSKWnW9ZDIY=;
        b=JXwonqj2lAqVWngMkuP45gc78JaOPqNWdSDWM3JuapjCwubeaMfEyykZw4nplBP/E8
         YoSURBTWAsCn4YOwXYATg7dFvbB8edAarcNjhmm0a2N0A7o+ndEv2ooI16DIFuQeIySD
         355TxRzlY3V8HtX4WqxCYo3AIRmdkBhF0CGQgc1zHuJMzM4X3xeV1O0UwJx+FY5iu2mR
         ukt1otL5UrgR2KBN5nKrKMnfegXWgyhHI90hVVExKMsvDiqyAfqsI6/dHkDcld+t30f6
         QiiJ0Gauwm0+1jvEnw1AzZuysNihOtk7bxtZ1in+SpFm+J9ZHEIlz0MSxRKKuCVmbbx+
         cbtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sKGNaHnqkAXazcGeHmVvcu/NxP8ulG0SkSKWnW9ZDIY=;
        b=lmNkNgIdwTw6qR+qe9choTckTnZkUu4ZReKamSN09H3BCyHOF66mH3fJEtjO/QVobn
         gcLmrAPUrYgbMqeiUCP22x2PjxIGzlr1s4L6p1LUu2A6GmSpB0spP8OxcPkEqhIYRWqG
         vwMYviBQExBk1eYX6OCmrTDjJpR+jy43eXMvb3xzldeOI18KF7uRSDZqJdFNxOF1kxd/
         q2jIet9rsRlNbh6+rFeDk2nksGbhhwync9bI/bDRNwreW+gk3BT2TRmut37ZcntqbH+t
         ljTf/TJ0mmwleJ/6mQzyA/sN4MqKESTDORRS8GRoHj+OpiTavDQw1UyR00mOyBtYEzlV
         yGOA==
X-Gm-Message-State: AOAM530CPrpy7HKeRIH3xszT+LE+lTQ6SZAJqxjdxQk45e9oEByUNia7
	mWbfA4Z4S30Vk8n7FxEqgK4=
X-Google-Smtp-Source: ABdhPJwnHHnXfg3p88EqrffDhXOhV1SY+4wjgiSlrbjIp3mEv5leQK6rEeEpkU0yt/xb3OfNH8HtlA==
X-Received: by 2002:a7b:c112:: with SMTP id w18mr7857188wmi.66.1602535575316;
        Mon, 12 Oct 2020 13:46:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7d02:: with SMTP id y2ls3574124wmc.2.canary-gmail; Mon,
 12 Oct 2020 13:46:14 -0700 (PDT)
X-Received: by 2002:a1c:1f89:: with SMTP id f131mr12899951wmf.10.1602535574398;
        Mon, 12 Oct 2020 13:46:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535574; cv=none;
        d=google.com; s=arc-20160816;
        b=0gEiKY8uHjZZ1MV/F0lFS81K2JyNzuC1bASKm7QA8xkkOPnMhKPxQpZ46hpvrXFAAp
         fRj1KaHJvfaZclU2uOsy2qEEuvQn+tHeWXJXZDw1QVthF2EFTiM4D9Yh//XRVMURTGEF
         5L+s8LLFPQ+tGiqYOlOU80Ek8Wfvf+lduB6DzSdBhvaj9M9r/xcaRjw0kX6O4JklPxc6
         81MZszbIsh/S6FKOo02ckm/uWjqlU2Yo0+KVq+wh7aIUGBPbQ3EsVEwQogMqMn9xcJOc
         8cadqhRCatM7/TcEpDe4XnLrk2KLOWYl4FSlRKVVkbF6CA0IwZ5mLulKzib2RMFXZbBk
         7zIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=q8z1ysIvdQl2qwL1BTKtEUugZI6jtuboegiHEyTuaNM=;
        b=b3bdTVBumJde5E77HxThn6dq+Y/AeV3bQo623OsJKTSlmBoE+N+hlt0sjHF7R/RTdT
         2agMSIOUyA/BGsGwmsjn5cPeH5/QpDw0og5+2hU5NfhJOl12+9yfzIEXpuMjTIlyorcb
         1UYMtn7gZUSPqnzuXvmz/eC6/I+bOWzahHlwpKx572LHJQFlP1CV4/PrnfhJ2aOUvaT+
         EeZTREFnjitLCd1vlFYfcHvgMKh3MvOVUnbtogqS+Qdap9FZAPhlpjosBolKk6hrUvf0
         4434WTB9b9RnhnO4clxRnpfJlE9BJ/eA9M1S9BkKerhnEpx7oKsUTqrTDdm+zh2zNkie
         trEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Vt1udr7z;
       spf=pass (google.com: domain of 3lccexwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3lcCEXwoKCSwIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id w206si576978wmb.2.2020.10.12.13.46.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:46:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lccexwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id m20so3510696wrb.21
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:46:14 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:cc02:: with SMTP id
 f2mr11970819wmh.1.1602535573911; Mon, 12 Oct 2020 13:46:13 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:40 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <b8e5477062d147bfa7844260f416a3e27c8468b6.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 34/40] kasan, arm64: expand CONFIG_KASAN checks
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
 header.i=@google.com header.s=20161025 header.b=Vt1udr7z;       spf=pass
 (google.com: domain of 3lccexwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3lcCEXwoKCSwIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
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
 arch/arm64/mm/dump.c               |  6 +++---
 include/linux/kasan-checks.h       |  2 +-
 include/linux/kasan.h              |  7 ++++---
 include/linux/moduleloader.h       |  3 ++-
 include/linux/string.h             |  2 +-
 mm/ptdump.c                        | 13 ++++++++-----
 scripts/Makefile.lib               |  2 ++
 14 files changed, 30 insertions(+), 22 deletions(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 192544fcd1a5..e28d49cc1400 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -320,7 +320,7 @@ config BROKEN_GAS_INST
 
 config KASAN_SHADOW_OFFSET
 	hex
-	depends on KASAN
+	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	default 0xdfffa00000000000 if (ARM64_VA_BITS_48 || ARM64_VA_BITS_52) && !KASAN_SW_TAGS
 	default 0xdfffd00000000000 if ARM64_VA_BITS_47 && !KASAN_SW_TAGS
 	default 0xdffffe8000000000 if ARM64_VA_BITS_42 && !KASAN_SW_TAGS
diff --git a/arch/arm64/Makefile b/arch/arm64/Makefile
index afcd61f7d2b0..af556bfec5c3 100644
--- a/arch/arm64/Makefile
+++ b/arch/arm64/Makefile
@@ -142,7 +142,7 @@ TEXT_OFFSET := 0x0
 
 ifeq ($(CONFIG_KASAN_SW_TAGS), y)
 KASAN_SHADOW_SCALE_SHIFT := 4
-else
+else ifeq ($(CONFIG_KASAN_GENERIC), y)
 KASAN_SHADOW_SCALE_SHIFT := 3
 endif
 
diff --git a/arch/arm64/include/asm/assembler.h b/arch/arm64/include/asm/assembler.h
index 54d181177656..bc9ace1e5f3a 100644
--- a/arch/arm64/include/asm/assembler.h
+++ b/arch/arm64/include/asm/assembler.h
@@ -464,7 +464,7 @@ USER(\label, ic	ivau, \tmp2)			// invalidate I line PoU
 #define NOKPROBE(x)
 #endif
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define EXPORT_SYMBOL_NOKASAN(name)
 #else
 #define EXPORT_SYMBOL_NOKASAN(name)	EXPORT_SYMBOL(name)
diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 268a3b6cebd2..de9af7bea90d 100644
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
index 037421c66b14..427ded9e68e8 100644
--- a/arch/arm64/kernel/head.S
+++ b/arch/arm64/kernel/head.S
@@ -452,7 +452,7 @@ SYM_FUNC_START_LOCAL(__primary_switched)
 	bl	__pi_memset
 	dsb	ishst				// Make zero page visible to PTW
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	bl	kasan_early_init
 #endif
 #ifdef CONFIG_RANDOMIZE_BASE
diff --git a/arch/arm64/kernel/image-vars.h b/arch/arm64/kernel/image-vars.h
index 8982b68289b7..ed8d086d601c 100644
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
diff --git a/arch/arm64/mm/dump.c b/arch/arm64/mm/dump.c
index ba6d1d89f9b2..bf8ddeac5d8f 100644
--- a/arch/arm64/mm/dump.c
+++ b/arch/arm64/mm/dump.c
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
@@ -381,7 +381,7 @@ void ptdump_check_wx(void)
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
index 2dadaf2be6d2..894eddf42168 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -229,7 +229,8 @@ static inline void kasan_release_vmalloc(unsigned long start,
 
 #endif /* CONFIG_KASAN_VMALLOC */
 
-#if defined(CONFIG_KASAN) && !defined(CONFIG_KASAN_VMALLOC)
+#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
+		!defined(CONFIG_KASAN_VMALLOC)
 
 /*
  * These functions provide a special case to support backing module
@@ -239,12 +240,12 @@ static inline void kasan_release_vmalloc(unsigned long start,
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
index 9b7a0632e87a..607322616363 100644
--- a/include/linux/string.h
+++ b/include/linux/string.h
@@ -273,7 +273,7 @@ void __write_overflow(void) __compiletime_error("detected write beyond size of o
 
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
index 3d599716940c..dc2d13c4455a 100644
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b8e5477062d147bfa7844260f416a3e27c8468b6.1602535397.git.andreyknvl%40google.com.
