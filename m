Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFFO6D6QKGQE3RXKKLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AAB82C155F
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:57 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id j66sf6517420lfj.9
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162196; cv=pass;
        d=google.com; s=arc-20160816;
        b=t8AsBqy5TQyIuYQl/F9mkA1Vylqlm+Pd/wC0mN/uBfLkZWML2gDXISoVeYBbi7JIHl
         EmIkRW/shgweyOpHfUm/W0kCvg2VOWEZOcBSkqtAdwo/MJf+5OXs4bAXUai/6uil6rRf
         v0LrthSlcGGzFe8SE//rZ0/hCMZzFenHv4l2uiwAPN6LkPKzQArG+zXuc3W98II9XeoS
         bS4SNDYPc5Y8O7xsvo1/L4NRrHUfFBY9hnN3UBrenTWDnSTXCr8E+08INWfWOsKOdZNC
         pHhGJb0VyyrUwqrIQlwJa2XGwbQIhFD9PKyiYmWxptChAuAnGCxmAWEb7/9pKJy8auF6
         hAEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=h/skPAcNt0y3j01DhvWG0VAcL6UIqPR9DWT+XrGXJ0A=;
        b=rJyU426mhhbPbY9ZnTyyx/PL1FtIs8eY8ZY5vpSYCXIN4a0OvaBud+2THfPPbBC+6L
         et4ZmPwelrLRapwbZy1KvnccRuzP35k7RyHa8498NQIEhWw3CGP1xWHmp01ffc9Nls5h
         69oTcWNk0Ds7gsKUUc7C+YcoCXkbvR/Mxv3mP++Jf8dAIKY+gmTC2iu4hADn3cYTdRC3
         kc6InldycGkK7bW/fvGyKSogKJUVsk8S/EBCTSADbJZSpDY1qgWrey/M0hCRPiO1xid/
         HX+x2W48PLDNt6kH6nhqU4v46+jygLOxck+cfogt4wAJbVrzgQPY90ZBnDjBnrPIRx9w
         jqPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="wDbwb9/i";
       spf=pass (google.com: domain of 3exe8xwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Exe8XwoKCTYSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=h/skPAcNt0y3j01DhvWG0VAcL6UIqPR9DWT+XrGXJ0A=;
        b=O3dySkuZoQPM/N2OXRWIKds2PEKvEFNS7tNKlhmn6AJdlbqdPu0wiw+ZIwa0BMVV3H
         g7HlKlpiNvRq3IzJGKfZMP4N4WpGfs0BM6nolzSRdXB26oYxLUALn2v/49lq0zobvi6y
         +6Q5XNVWEEJZj5aTI6ODOMPHjc1FcChS0NNvTcF396PyPrTEbr65yR5njjXN8b3n6ADX
         Iy9t0wlZkXll1gsh2dkId4GazZ/QQBCOPpOzfRD51i3GEvuB5jIfZ3DqxepH503jI803
         V5SeimVzUasIPB/6Kd1Um3Zn8QrPC62cmpO48+065HZySkmbIAwXnXYMnIVWy595CsCJ
         5QCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h/skPAcNt0y3j01DhvWG0VAcL6UIqPR9DWT+XrGXJ0A=;
        b=S2p8mD+e4rJli2bpkgoC3zlXbzrEQrMgL0sgK5m1wo4jgJTiv8JVUHxOrRdx8JOu3Y
         dKD0KRyvKfiAbofLcZNE88EZpiqU7TdVKNaNWWaYO0lm2++ew1hCNN4+NeE49FReVgrA
         GM4xhycvYyG11T9+hnQZIF6vs3TEKJbSnyg5Kg4OLqGifGbltTR6DqTp42p3UlJLCMjs
         xSMF80LD2BJR3UECsgSoV1ZVTObHcVJUpWLTVIu1f4+nLEz66z1j/3XU/WDaKaCe/wnC
         kkp4yw9G0noWIWIU0RSI7eL90ZQkiphZtJvCRI7b37sOzFEbiHovHQ8Y+oJVTSY5/RdF
         Sj6w==
X-Gm-Message-State: AOAM532pREmSP39tyZgmmQCd2XFp5GmBMsOejPSk7mrUcpW6WB1ELntn
	r9M2zSiqEYY4rDWNt6iF0eo=
X-Google-Smtp-Source: ABdhPJxJiYXCR7nIFjnbPJHLrUdIBUyzcMVTie39HOOZJVzYbEBsM6IsEdwYkp3UpwX/AFnQzt6mEQ==
X-Received: by 2002:a19:4941:: with SMTP id l1mr378784lfj.136.1606162196798;
        Mon, 23 Nov 2020 12:09:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6b0b:: with SMTP id d11ls5177286lfa.1.gmail; Mon, 23 Nov
 2020 12:09:55 -0800 (PST)
X-Received: by 2002:a19:913:: with SMTP id 19mr349554lfj.147.1606162195764;
        Mon, 23 Nov 2020 12:09:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162195; cv=none;
        d=google.com; s=arc-20160816;
        b=gR1djdfO4sBun2teMzhRfjjjD8sTsj9kNzsF/hLI6IxqkNh7T5GaEadDeeQhWGzFHE
         3UZElt6lPWwSz9JmwGouc2jDxZJ6t64wyGP3dHt9/YX8+HHwsF3t2aBbGV9ITNd0pb8z
         yKuP6FIL/+pahp4/DsiCa5iZyMmCSQWaet8/btORAwRT5H5MJgOZr1nRMo1GdF4tn+1j
         JuTDiblbBcFvdnercJuqjsWlme+DFIiREBc1j1IrA6dr29oNz0kJaYqth+Si8BB2g9Rz
         k49O2eZsGxxFLBswcSnjZ3ayIfzrYy/SnE9lqhG51bSITUwiBtdtFf1ejowEWygUlJGW
         sCCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=xeXowmp0tLGPzXy2xdy3MngnVwJCRdP+7Fkx+qliX9g=;
        b=KEeOT5NAU8HaoaZPEKBEhMXwsZ7t1DHBDloiwVHwOYaPLbwam3v52Vp3GgUbDq/QdE
         niQGMkgZKq/MQ27L8CeaKHqeispNETlPmkKhH7IstTCkJylBjbf6y7w4wPfpTYP/PF3f
         iT9wyUcL9tUZ5oDF2o0+oqVnR30Naw+BhoF4gZD7uf4rd9W0ni0nlYwnSEs4xwhJxKGG
         TUI9W956WaXMXMJFPSsR2cKlvT7NL492SRzhbCtmGps9ur1dBlBAxDoC+8B/c8aOsRPO
         BVaket7fIs3N5e7RMV6dGOXwCAwZ+UBsrCya4+XHxYgMxdTphF0irPpUkuJ02IjwSLMn
         e2UQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="wDbwb9/i";
       spf=pass (google.com: domain of 3exe8xwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Exe8XwoKCTYSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id y84si392848lfa.6.2020.11.23.12.09.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:55 -0800 (PST)
Received-SPF: pass (google.com: domain of 3exe8xwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id n19so314974wmc.1
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:55 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:6405:: with SMTP id
 y5mr603878wmb.150.1606162195064; Mon, 23 Nov 2020 12:09:55 -0800 (PST)
Date: Mon, 23 Nov 2020 21:08:01 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <cfd0fbede579a6b66755c98c88c108e54f9c56bf.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 37/42] kasan, arm64: implement HW_TAGS runtime
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
 header.i=@google.com header.s=20161025 header.b="wDbwb9/i";       spf=pass
 (google.com: domain of 3exe8xwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Exe8XwoKCTYSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
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

Provide implementation of KASAN functions required for the hardware
tag-based mode. Those include core functions for memory and pointer
tagging (tags_hw.c) and bug reporting (report_tags_hw.c). Also adapt
common KASAN code to support the new mode.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I8a8689ba098174a4d0ef3f1d008178387c80ee1c
---
 arch/arm64/include/asm/memory.h   |  4 +-
 arch/arm64/kernel/cpufeature.c    |  3 ++
 arch/arm64/kernel/smp.c           |  2 +
 include/linux/kasan.h             | 24 ++++++---
 include/linux/mm.h                |  2 +-
 include/linux/page-flags-layout.h |  2 +-
 mm/kasan/Makefile                 |  5 ++
 mm/kasan/common.c                 | 15 +++---
 mm/kasan/hw_tags.c                | 89 +++++++++++++++++++++++++++++++
 mm/kasan/kasan.h                  | 19 +++++--
 mm/kasan/report_hw_tags.c         | 42 +++++++++++++++
 mm/kasan/report_sw_tags.c         |  2 +-
 mm/kasan/shadow.c                 |  2 +-
 mm/kasan/sw_tags.c                |  2 +-
 14 files changed, 187 insertions(+), 26 deletions(-)
 create mode 100644 mm/kasan/hw_tags.c
 create mode 100644 mm/kasan/report_hw_tags.c

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index cd671fb6707c..18fce223b67b 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -214,7 +214,7 @@ static inline unsigned long kaslr_offset(void)
 	(__force __typeof__(addr))__addr;				\
 })
 
-#ifdef CONFIG_KASAN_SW_TAGS
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 #define __tag_shifted(tag)	((u64)(tag) << 56)
 #define __tag_reset(addr)	__untagged_addr(addr)
 #define __tag_get(addr)		(__u8)((u64)(addr) >> 56)
@@ -222,7 +222,7 @@ static inline unsigned long kaslr_offset(void)
 #define __tag_shifted(tag)	0UL
 #define __tag_reset(addr)	(addr)
 #define __tag_get(addr)		0
-#endif /* CONFIG_KASAN_SW_TAGS */
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline const void *__tag_set(const void *addr, u8 tag)
 {
diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
index a81df8b0e51e..aba31dcd77f2 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -70,6 +70,7 @@
 #include <linux/types.h>
 #include <linux/mm.h>
 #include <linux/cpu.h>
+#include <linux/kasan.h>
 #include <asm/cpu.h>
 #include <asm/cpufeature.h>
 #include <asm/cpu_ops.h>
@@ -1713,6 +1714,8 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
 		cleared_zero_page = true;
 		mte_clear_page_tags(lm_alias(empty_zero_page));
 	}
+
+	kasan_init_hw_tags_cpu();
 }
 #endif /* CONFIG_ARM64_MTE */
 
diff --git a/arch/arm64/kernel/smp.c b/arch/arm64/kernel/smp.c
index 2499b895efea..19b1705ae5cb 100644
--- a/arch/arm64/kernel/smp.c
+++ b/arch/arm64/kernel/smp.c
@@ -462,6 +462,8 @@ void __init smp_prepare_boot_cpu(void)
 	/* Conditionally switch to GIC PMR for interrupt masking */
 	if (system_uses_irq_prio_masking())
 		init_gic_priority_masking();
+
+	kasan_init_hw_tags();
 }
 
 static u64 __init of_get_cpu_mpidr(struct device_node *dn)
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 118a57517281..0c89e6fdd29e 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -189,25 +189,35 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #endif /* CONFIG_KASAN_GENERIC */
 
-#ifdef CONFIG_KASAN_SW_TAGS
-
-void __init kasan_init_sw_tags(void);
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 
 void *kasan_reset_tag(const void *addr);
 
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 
-#else /* CONFIG_KASAN_SW_TAGS */
-
-static inline void kasan_init_sw_tags(void) { }
+#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline void *kasan_reset_tag(const void *addr)
 {
 	return (void *)addr;
 }
 
-#endif /* CONFIG_KASAN_SW_TAGS */
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS*/
+
+#ifdef CONFIG_KASAN_SW_TAGS
+void __init kasan_init_sw_tags(void);
+#else
+static inline void kasan_init_sw_tags(void) { }
+#endif
+
+#ifdef CONFIG_KASAN_HW_TAGS
+void kasan_init_hw_tags_cpu(void);
+void __init kasan_init_hw_tags(void);
+#else
+static inline void kasan_init_hw_tags_cpu(void) { }
+static inline void kasan_init_hw_tags(void) { }
+#endif
 
 #ifdef CONFIG_KASAN_VMALLOC
 
diff --git a/include/linux/mm.h b/include/linux/mm.h
index a1c25da94663..035957363055 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -1421,7 +1421,7 @@ static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
 }
 #endif /* CONFIG_NUMA_BALANCING */
 
-#ifdef CONFIG_KASAN_SW_TAGS
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 static inline u8 page_kasan_tag(const struct page *page)
 {
 	return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
diff --git a/include/linux/page-flags-layout.h b/include/linux/page-flags-layout.h
index e200eef6a7fd..7d4ec26d8a3e 100644
--- a/include/linux/page-flags-layout.h
+++ b/include/linux/page-flags-layout.h
@@ -77,7 +77,7 @@
 #define LAST_CPUPID_SHIFT 0
 #endif
 
-#ifdef CONFIG_KASAN_SW_TAGS
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 #define KASAN_TAG_WIDTH 8
 #else
 #define KASAN_TAG_WIDTH 0
diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index f1d68a34f3c9..9fe39a66388a 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -10,8 +10,10 @@ CFLAGS_REMOVE_init.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_quarantine.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_report_generic.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_report_hw_tags.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_report_sw_tags.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_shadow.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_hw_tags.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_sw_tags.o = $(CC_FLAGS_FTRACE)
 
 # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
@@ -27,10 +29,13 @@ CFLAGS_init.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_quarantine.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_report_generic.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_report_hw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_report_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_hw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 
 obj-$(CONFIG_KASAN) := common.o report.o
 obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
+obj-$(CONFIG_KASAN_HW_TAGS) += hw_tags.o report_hw_tags.o
 obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 52fa763d2169..998aede4d172 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -119,7 +119,7 @@ void kasan_free_pages(struct page *page, unsigned int order)
  */
 static inline unsigned int optimal_redzone(unsigned int object_size)
 {
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC))
 		return 0;
 
 	return
@@ -184,14 +184,14 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
 struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
 					const void *object)
 {
-	return (void *)object + cache->kasan_info.alloc_meta_offset;
+	return (void *)reset_tag(object) + cache->kasan_info.alloc_meta_offset;
 }
 
 struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
 				      const void *object)
 {
 	BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
-	return (void *)object + cache->kasan_info.free_meta_offset;
+	return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
 }
 
 void kasan_poison_slab(struct page *page)
@@ -273,9 +273,8 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 	alloc_info = get_alloc_info(cache, object);
 	__memset(alloc_info, 0, sizeof(*alloc_info));
 
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
-		object = set_tag(object,
-				assign_tag(cache, object, true, false));
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
+		object = set_tag(object, assign_tag(cache, object, true, false));
 
 	return (void *)object;
 }
@@ -349,10 +348,10 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	redzone_end = round_up((unsigned long)object + cache->object_size,
 				KASAN_GRANULE_SIZE);
 
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
 		tag = assign_tag(cache, object, false, keep_tag);
 
-	/* Tag is ignored in set_tag without CONFIG_KASAN_SW_TAGS */
+	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
 	unpoison_range(set_tag(object, tag), size);
 	poison_range((void *)redzone_start, redzone_end - redzone_start,
 		     KASAN_KMALLOC_REDZONE);
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
new file mode 100644
index 000000000000..3f9232464ed4
--- /dev/null
+++ b/mm/kasan/hw_tags.c
@@ -0,0 +1,89 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains core hardware tag-based KASAN code.
+ *
+ * Copyright (c) 2020 Google, Inc.
+ * Author: Andrey Konovalov <andreyknvl@google.com>
+ */
+
+#define pr_fmt(fmt) "kasan: " fmt
+
+#include <linux/kasan.h>
+#include <linux/kernel.h>
+#include <linux/kfence.h>
+#include <linux/memory.h>
+#include <linux/mm.h>
+#include <linux/string.h>
+#include <linux/types.h>
+
+#include "kasan.h"
+
+/* kasan_init_hw_tags_cpu() is called for each CPU. */
+void kasan_init_hw_tags_cpu(void)
+{
+	hw_init_tags(KASAN_TAG_MAX);
+	hw_enable_tagging();
+}
+
+/* kasan_init_hw_tags() is called once on boot CPU. */
+void __init kasan_init_hw_tags(void)
+{
+	pr_info("KernelAddressSanitizer initialized\n");
+}
+
+void *kasan_reset_tag(const void *addr)
+{
+	return reset_tag(addr);
+}
+
+void poison_range(const void *address, size_t size, u8 value)
+{
+	/* Skip KFENCE memory if called explicitly outside of sl*b. */
+	if (is_kfence_address(address))
+		return;
+
+	hw_set_mem_tag_range(reset_tag(address),
+			round_up(size, KASAN_GRANULE_SIZE), value);
+}
+
+void unpoison_range(const void *address, size_t size)
+{
+	/* Skip KFENCE memory if called explicitly outside of sl*b. */
+	if (is_kfence_address(address))
+		return;
+
+	hw_set_mem_tag_range(reset_tag(address),
+			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
+}
+
+u8 random_tag(void)
+{
+	return hw_get_random_tag();
+}
+
+bool check_invalid_free(void *addr)
+{
+	u8 ptr_tag = get_tag(addr);
+	u8 mem_tag = hw_get_mem_tag(addr);
+
+	return (mem_tag == KASAN_TAG_INVALID) ||
+		(ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag);
+}
+
+void kasan_set_free_info(struct kmem_cache *cache,
+				void *object, u8 tag)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = get_alloc_info(cache, object);
+	kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
+}
+
+struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
+				void *object, u8 tag)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = get_alloc_info(cache, object);
+	return &alloc_meta->free_track[0];
+}
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 92cb2c16e314..64560cc71191 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -154,6 +154,11 @@ struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
 struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
 					const void *object);
 
+void poison_range(const void *address, size_t size, u8 value);
+void unpoison_range(const void *address, size_t size);
+
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
+
 static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 {
 	return (void *)(((unsigned long)shadow_addr - KASAN_SHADOW_OFFSET)
@@ -165,9 +170,6 @@ static inline bool addr_has_metadata(const void *addr)
 	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
 }
 
-void poison_range(const void *address, size_t size, u8 value);
-void unpoison_range(const void *address, size_t size);
-
 /**
  * check_memory_region - Check memory region, and report if invalid access.
  * @addr: the accessed address
@@ -179,6 +181,15 @@ void unpoison_range(const void *address, size_t size);
 bool check_memory_region(unsigned long addr, size_t size, bool write,
 				unsigned long ret_ip);
 
+#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+static inline bool addr_has_metadata(const void *addr)
+{
+	return true;
+}
+
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
 bool check_invalid_free(void *addr);
 
 void *find_first_bad_addr(void *addr, size_t size);
@@ -215,7 +226,7 @@ static inline void quarantine_reduce(void) { }
 static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
 #endif
 
-#ifdef CONFIG_KASAN_SW_TAGS
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 
 void print_tags(u8 addr_tag, const void *addr);
 
diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
new file mode 100644
index 000000000000..da543eb832cd
--- /dev/null
+++ b/mm/kasan/report_hw_tags.c
@@ -0,0 +1,42 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains hardware tag-based KASAN specific error reporting code.
+ *
+ * Copyright (c) 2020 Google, Inc.
+ * Author: Andrey Konovalov <andreyknvl@google.com>
+ */
+
+#include <linux/kasan.h>
+#include <linux/kernel.h>
+#include <linux/memory.h>
+#include <linux/mm.h>
+#include <linux/string.h>
+#include <linux/types.h>
+
+#include "kasan.h"
+
+const char *get_bug_type(struct kasan_access_info *info)
+{
+	return "invalid-access";
+}
+
+void *find_first_bad_addr(void *addr, size_t size)
+{
+	return reset_tag(addr);
+}
+
+void metadata_fetch_row(char *buffer, void *row)
+{
+	int i;
+
+	for (i = 0; i < META_BYTES_PER_ROW; i++)
+		buffer[i] = hw_get_mem_tag(row + i * KASAN_GRANULE_SIZE);
+}
+
+void print_tags(u8 addr_tag, const void *addr)
+{
+	u8 memory_tag = hw_get_mem_tag((void *)addr);
+
+	pr_err("Pointer tag: [%02x], memory tag: [%02x]\n",
+		addr_tag, memory_tag);
+}
diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
index add2dfe6169c..aebc44a29e83 100644
--- a/mm/kasan/report_sw_tags.c
+++ b/mm/kasan/report_sw_tags.c
@@ -1,6 +1,6 @@
 // SPDX-License-Identifier: GPL-2.0
 /*
- * This file contains tag-based KASAN specific error reporting code.
+ * This file contains software tag-based KASAN specific error reporting code.
  *
  * Copyright (c) 2014 Samsung Electronics Co., Ltd.
  * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 80522d2c447b..d8a122f887a0 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -120,7 +120,7 @@ void unpoison_range(const void *address, size_t size)
 
 		if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
 			*shadow = tag;
-		else
+		else /* CONFIG_KASAN_GENERIC */
 			*shadow = size & KASAN_GRANULE_MASK;
 	}
 }
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 7317d5229b2b..a518483f3965 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -1,6 +1,6 @@
 // SPDX-License-Identifier: GPL-2.0
 /*
- * This file contains core tag-based KASAN code.
+ * This file contains core software tag-based KASAN code.
  *
  * Copyright (c) 2018 Google, Inc.
  * Author: Andrey Konovalov <andreyknvl@google.com>
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cfd0fbede579a6b66755c98c88c108e54f9c56bf.1606161801.git.andreyknvl%40google.com.
