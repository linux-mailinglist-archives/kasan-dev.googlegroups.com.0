Return-Path: <kasan-dev+bncBDX4HWEMTEBRBH6GWT5QKGQEFSTZMYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FD8D277BF5
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:52:16 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id w3sf324862wmg.4
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:52:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987936; cv=pass;
        d=google.com; s=arc-20160816;
        b=gN/aqueAV3mvhLye59x97I7x6DCcfHI4HmrgXu5/XPAn7yTpPOT3xIPftVWz33cDgz
         9mFVuEZkDCyRoNArejVOzzI+/cU1TgY83+NE0FqcGt/9orY13Zm9aa4kkpRI8fimooVc
         /7mzdk9x8jaL5ENdsSxfXZkhxZLo1vuxzBc64q2gP5asaY3VfkoSctlDJiy+OQTkqnq1
         B+kNonLUS8k4YMRGlbtBzsVvd7OuJcnMXqk7Y8lpCWHu8687YmmtNiXfoJv/Vww38K77
         YcGj6/ubAb5W4idQQPSXoHYtFtfCKcronnxAvs/mDgTQRmr41o/5/Pm8PzwU/AXEV5Uh
         wpVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=XJ/ll5HchUlJJ7IVu1HniMrtPwty1h+wYqJXRMiCJKc=;
        b=J3ZXvf075PLsDrrASXOjf5NZyqClIwz2mpU1xHRVKe6m6r5B/vfH5kyH9qTTS7gAtk
         qqwgYKtM7BP1jZ9D9miqBBAAEcMhlMKEKfLlEGWyyVLbjoaXJO4H/b1KGSfgGux3L3jB
         zU3iKZrf4k7ICly/QGnwWyhXtZVK3aDV8RGVW8dEmP7qiUoeofVZQgncsETVJi6Dqf6j
         sKZPijg+d6Z7B50SBwg5yMvlSmiPe0PSqO36au2Tbotos/FcemmBKsysmupkHyB22eIK
         qatysJc6J7kQUBrupYuVuFUcZPGSOWGr20NkqWzDKQqwj4gDLfPyNVTpOjIKpAZsFshb
         h9Tw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EYltS+cB;
       spf=pass (google.com: domain of 3hintxwokcrs1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3HiNtXwoKCRs1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XJ/ll5HchUlJJ7IVu1HniMrtPwty1h+wYqJXRMiCJKc=;
        b=sIdU1bbsEgnZGpjKJijk34YHXc6XSurubgJFZaCbaf7ezShdfY55SiWCJUrmkjT7cA
         9tRPUT8P9P6Je4iHNYw2k8hE+b54a8OTJXm/++yLQfXO7m5gSSeXc5o3LyhRH9hgtIL2
         NIXSrsS3epfB4ZgnaDOLdv3N8MO3YeL1T6Z2B01/J+K84GB43w726Au2CHA21BiHcoYK
         TXPdSrDKMT0hjh9iHcsDpBL4E3CyV+o61iRJnPMXxAY8CIRI6plXn5dGUAPXRhTX/PY8
         OmX6ZKIZVxNdgGERybhDV76DyOvYnQm4xEjRZa0djz0mrTOiYlUo2+FtxBEUH2OOTGcY
         UqOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XJ/ll5HchUlJJ7IVu1HniMrtPwty1h+wYqJXRMiCJKc=;
        b=cOV8PF6jthn6WRZIPQoH9K1drdWZDWZbI7jeqBFkJU6rc00N3FX9trcCv5uLRJt1ua
         AbQzBnfIwi4wwD5BGIjd09txEcwAmS6Z/5eiXpiMS6L1exYxWHkXgWBLDipclMAH2173
         q/CUoPhZmXwbnybGRJU4AQyGenh4pR0o+hga8qW8H6mrO2kraujYqGaC2cdGJBaT7bnv
         b5hJ8Y35Ap+YsQnn7d4O6a8gWeO1cMm0KL3yFhMUiroYroBAWrM3JsgCDdyXKBQXA5f2
         Z62ZLjCrlZ8UjFeH+m/zoJnOQrQ8OIuqsLvqHzgxhVItSEp6KVB32H5zWYnIOMwQO/nv
         8utA==
X-Gm-Message-State: AOAM533sFK6Xvt/liqLn1kVbfVJxVeEyy0frkefBsOJXntZXDRJru7hA
	HL8D2iV1dlbOGk0T8ODDEdg=
X-Google-Smtp-Source: ABdhPJxxiCCmVPi8+SixALK6RXL4VzwK+p0o3le12Pg4qmer4gV+kslWZusxhNiutHmslPL+cCSaag==
X-Received: by 2002:a1c:bb45:: with SMTP id l66mr868725wmf.79.1600987935902;
        Thu, 24 Sep 2020 15:52:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:428e:: with SMTP id k14ls1056413wrq.0.gmail; Thu, 24 Sep
 2020 15:52:15 -0700 (PDT)
X-Received: by 2002:a05:6000:100c:: with SMTP id a12mr1244146wrx.115.1600987935169;
        Thu, 24 Sep 2020 15:52:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987935; cv=none;
        d=google.com; s=arc-20160816;
        b=L+j6mEO1rZ5yYNmG09fl/Ifo6UvxNVkxEcDESWdUVPcgamYligSGtHQO8ymNG1mNL2
         Why9COj1/s1w4Exqm7ahbAwacecucjpnfc/nCbXNAOXydR6GGEEK/qb+soJGMtYC8BN7
         IBV6IG6dOt2rzso+3ZUrEy8leWtJckSeJ9BiaJT7bBkSwWueMkK/Bckz+9n/JLYD3cwd
         KT1O0f1EfVX0eYtgOFvmn/6BnSnKyseGFZPDVAMxLpr4UdgNCl6PJw1SaHsoxdExp3iP
         6NAlTEcWlcsnmPNYFl0Re6XrE8tfLS//qKDQj78u0tFtUrghCSEX7HWw9/MRa58bP6xn
         TwtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=MF3mpW6+ani4vCGp0C8RUVdzsmyAVZcFGt+KBhP2Uwo=;
        b=R8UWT0RNmmRVNqeBTVaW7Blaa9HL63Kaaqd6wF9eSbw/2TNSpJsHXhAF/iNZ69+nIs
         B2Do/KXp3DpSAnSRxID9AR+5hYgLaJuXZ75yf+o/iWknWvbN5/thxN7B3pC+kujqVojk
         Y+V0V+9k/CiP5+L7FHr6cGp0RWP6edqF21Px9C3OWg/AtZxPVwk0md92Jwzq/DQN/oUy
         cEENG9l66iRfdu3x0Ox4hqPI14OruTU1LUTj2QmlQjxKm4vpY0k9z/oEQ9HL7Dzag2SC
         C9UoKJKBGmrsTIYaeZZSCD0w4cMeDQaQPa/2QdIz2TOPGhF4GvaxN5is47mC8GG5Isp3
         TJzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EYltS+cB;
       spf=pass (google.com: domain of 3hintxwokcrs1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3HiNtXwoKCRs1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id s192si20574wme.1.2020.09.24.15.52.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:52:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hintxwokcrs1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id m10so275456wmf.5
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:52:15 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:cd06:: with SMTP id
 f6mr913608wmj.66.1600987934763; Thu, 24 Sep 2020 15:52:14 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:41 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <3bdfabc3f5f908fe8db6e3e3113c3dbbb0c530e1.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 34/39] kasan, arm64: expand CONFIG_KASAN checks
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EYltS+cB;       spf=pass
 (google.com: domain of 3hintxwokcrs1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3HiNtXwoKCRs1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
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
index 4ca1b9970201..94b974f15892 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -226,7 +226,8 @@ static inline void kasan_release_vmalloc(unsigned long start,
 
 #endif /* CONFIG_KASAN_VMALLOC */
 
-#if defined(CONFIG_KASAN) && !defined(CONFIG_KASAN_VMALLOC)
+#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
+		!defined(CONFIG_KASAN_VMALLOC)
 
 /*
  * These functions provide a special case to support backing module
@@ -236,12 +237,12 @@ static inline void kasan_release_vmalloc(unsigned long start,
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
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3bdfabc3f5f908fe8db6e3e3113c3dbbb0c530e1.1600987622.git.andreyknvl%40google.com.
