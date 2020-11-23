Return-Path: <kasan-dev+bncBDX4HWEMTEBRBENO6D6QKGQEEAULXEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 696BC2C155E
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:54 +0100 (CET)
Received: by mail-vk1-xa3b.google.com with SMTP id b199sf8373770vkf.8
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162193; cv=pass;
        d=google.com; s=arc-20160816;
        b=as48oG+sedbEbvr/EPt7hdCrgPwyXoD0E+/+nZqSpzyYbr1dv2FEaquDzrDlgpOcCI
         J+SgNKvUqFPAF3mYuebJ1zXrC+fuH059RURGNRrtZPKCNiS1BO2v7VjddJ21gEewHuzj
         nqyWR9dI/Fk0cKLJiTFdTprSoN4aG209A+d1/4QFm23uxB348NK0vz/XRkGtjWXOT3iN
         cUL9FjYrGxWFLK8RPEXeJza8uSa7Tkyl0htjwoyjluP8ViTU0I2IqlHn1ZOLki5tBjqy
         enztOZez6QuXggX5LsqC8y43BUBZQw3+dqjxGWxDpCZIktbk9ODNpOWLi6BRnvqWt+WV
         p7lQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ez2tNbMgRUi8uwQCqnbswyjaeNbD0dEYXu59KV2qfyE=;
        b=FeIPj7rmSqXSmIg/3YnayYR6DO8Dz9hGpZ7yPGp/YCrzxLLxLgP+aLAW7E2KZ6zfpH
         J4N1+uSW2Jp1yZlG2VeKVcGRIytXQ2JcPPeC5p7Cg4Oad3CLKK74/cnJYWVgItRs2v9c
         A+76q7Pn9gx90KAlddEsPzHNnkrQlhKqetEmbYEB4RJatK2oG+UVzoLsnxDdmUB8+BNm
         RTN9JBvdY3FqoDKfVRN+E4Y24sDpHbspbPDiICg1+GIZblSA6TjLIFeUbFrHmP4WwnU2
         J1fO5BCnUM08gJaLS2i6TWnGfImJDkS1I+uHVjYnnKSiKlvC/iSU0OFsWVBDVXhBdy0c
         MI2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IAJMHT7t;
       spf=pass (google.com: domain of 3ebe8xwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3EBe8XwoKCTMPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ez2tNbMgRUi8uwQCqnbswyjaeNbD0dEYXu59KV2qfyE=;
        b=QHT428N8uUDA+AdMYfXW79O3E+RKh7mhH8K3cVQd0ZvJzt2DOmRr/MtO4ZZRW3Q0s0
         YyKW4phcMXfbiFQsoHu+nxau6cX1C8DyKggPfnAM6HKXO3vI3vPTdnX/Sxg3VB/Qpz/G
         GzSsxQfY6kQd6FdKo5GIl6l4l7uxb+8tNXXRrBOKHpIKc5nltiug/yuazUZVhVkwVFvV
         2jIUyeP0FWZ/Iwo9mcVTVxYAlrPC1QmbIAcrZZEYyEicPcaiDU5GvYowWYcba6Xe2XB3
         JItwVvpz7ENgXzU06XmmCVKriH0dGvEj4Q9l4yaduQITc+3etGR/jXm22zIt15KaVShQ
         KFTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ez2tNbMgRUi8uwQCqnbswyjaeNbD0dEYXu59KV2qfyE=;
        b=j72mRAQa75MXWFGs3VPNzt7pgW3sb46uc39UAalNhYoj5WMI3SGvQ3y4K+jnjj+9er
         zy4Fb7asELgagujuhoIp9BEPUEKfCzJMGZ1qevJF5iF13MzktzTliNbd6kl2tEPa7pyr
         OKru4mjaA7TWctsLRqtadrRXGOxAOcFalw4p/rXI9jK7i6RaVuI2O2APcf3EalP/XhUD
         Vja+vJv98IkySrgnhc0mN55RrczFEAgxM0jEgzIGOF6069DOMOUp/hzuqF9WKKIeVW59
         9lfyhENq/tSFyOvq43NfeAjmpGF+HlE7HCQpv80IRY9/CXWsv3oIxc+1Ril1JUb0hl0B
         DYLA==
X-Gm-Message-State: AOAM531WJx1RX4NDHsGQwTFBkaz5y/cfFIqET6T1D9OYOAbNB+501O8z
	/Vgb/OGpKaupDN2ZjOwoQGE=
X-Google-Smtp-Source: ABdhPJxh2cEzBuANlaUUHMIMBkek9CiD+bTWAPk+0j6PtNyn284/ZGQuQWTi/4EjiNsq5Fr27sYE/w==
X-Received: by 2002:a67:ff14:: with SMTP id v20mr1230514vsp.20.1606162193493;
        Mon, 23 Nov 2020 12:09:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:5387:: with SMTP id k7ls1073450uaa.0.gmail; Mon, 23 Nov
 2020 12:09:53 -0800 (PST)
X-Received: by 2002:ab0:2642:: with SMTP id q2mr1082144uao.96.1606162192989;
        Mon, 23 Nov 2020 12:09:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162192; cv=none;
        d=google.com; s=arc-20160816;
        b=hQeL9jQOP8T3HDWCNCdcDhEHYWeF+7xT8a/xG07uG8oX6TwcAOXy6VHt6sYXK3OHuW
         C/L4pPnDxArm8+5OgRgdBwUuz7zNlD72xTGGpblzT7CtgqHoquD4oocekcuEyTikplln
         hnemy5aTaOF9wYnjG9Fwl+X8Ej+j239ywDm21cIaoYua3hMG2G+PbKHAsA8FyMXZkGz0
         YyZs4gJh5PMLoZEuqEKNDGj3/skbWcnSd4fj6+tn24AsJgkaeOEjojvAU2t3jcQEc0kk
         D4fB01EuC8quddC4vPM6WZ5/9SwJiuXNzMNH+AlFYRtVQ4Yjj09mMWgpLN4Jgr06I3gC
         mysw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=HBuKneo0/sFiVmGMwaY+Y8/9f0Ckbfm6QyIKGmBARHo=;
        b=WiSnkbseRkxbPIfTEw5amQRWQr4b6NHbJ//6qeOFe2DbbGcXNhRrb+nVaGSAYM7mJf
         UczdIPfGnpXPe8Epds0w4zyAa+Q9gey22NPRo5SZttTiQrxmtbNiYZCPijVS20651mWH
         36XIDlsorHShsNSw8mn7V90pUprTHKbMJOhogvOtFp8npWSe+0Oi3x3z2VoDnyUacc7+
         R2rRG0wCZW562XDHRSjBcd0c0D9NOdi0NyLTNabGzLLPi6xm4Lyjw/6+f4HD3HJMpB+n
         zXh1hXXAiLnPwGHYDWcxBmyqASoxYH+2w1vvA/eFtM9kFChs7JepQIufVIqhEBSP7zwj
         zKnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IAJMHT7t;
       spf=pass (google.com: domain of 3ebe8xwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3EBe8XwoKCTMPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id n1si630068vsr.2.2020.11.23.12.09.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:52 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ebe8xwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id ca17so13761710qvb.1
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:52 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4807:: with SMTP id
 g7mr1096154qvy.26.1606162192496; Mon, 23 Nov 2020 12:09:52 -0800 (PST)
Date: Mon, 23 Nov 2020 21:08:00 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <e6971e432dbd72bb897ff14134ebb7e169bdcf0c.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 36/42] kasan, arm64: expand CONFIG_KASAN checks
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
 header.i=@google.com header.s=20161025 header.b=IAJMHT7t;       spf=pass
 (google.com: domain of 3ebe8xwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3EBe8XwoKCTMPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
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
index b641bb6cbc73..434247e14814 100644
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
index c1f8f2c5be47..54f6be3a3d65 100644
--- a/arch/arm64/kernel/head.S
+++ b/arch/arm64/kernel/head.S
@@ -433,7 +433,7 @@ SYM_FUNC_START_LOCAL(__primary_switched)
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e6971e432dbd72bb897ff14134ebb7e169bdcf0c.1606161801.git.andreyknvl%40google.com.
