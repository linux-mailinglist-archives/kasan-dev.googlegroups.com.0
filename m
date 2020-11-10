Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWNAVT6QKGQEF5KPK2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id C82262AE2E6
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:41 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id z7sf1851329wme.8
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046361; cv=pass;
        d=google.com; s=arc-20160816;
        b=YSJgSnufEujYuP9kSrvGgzv7zjQVFdrpGBCaldwCxOvH3VWwVukE03YV4DWm9R8bST
         rUsIGAA6gS3T3nY05C8qzdp4/RgvyFat0176Pdzh9XfnemiOdV2BBiG9RllpnPKF0ijg
         4l/o2RFCCxIn/LyPv0AIo9sQAbl2ErWu8gZ3lN5w0phUpFZ/CNWeCPsgt/ewXeOQsjqA
         ZzIY8dBQ3Fk988guvpDsVwzrF650Lx6F+aXPWe+2xIdH1zOa1dUFAMai3+6YPJi+7qL7
         wHhrGksztBEMUaAqnKOUNHjJgfZNATYIJVBS96/tL4TzX9s+lQX2S7dJGaIEEA2OoDyx
         D1PQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=s8CcAFiHVvcI34WTAH6Be8/J76ya8iOTJ5L5fCKdqRE=;
        b=zTLtDgpS56EQtQqfODwyElMyQYiQY3hwP/cWpZxYzmnaMdihjH7Ivec9kV3dw1EvYC
         XnbstbdY/kpR7yMwJ6tACu0xj09RSkYwg6C/huegxbwbDhtuFlQpz2EXMv5CsWsl8x57
         rV+/Gc/VVZQ8t2a0yiqoJ9WaxEUdqrEppP4hTSJeOs1lGMehhqKbN+7oeIHCfa3y5vRt
         nB37tVrSw37oc70z9qj/KCBujpMClZt7d1F6lZoYrW572g8PlDaZJEuEhAzECSZ9DZIX
         OubM2vTT7B7lwotiRwZcoTZW5b1ox3Fn6rXA5/gZ0c6mCg5z/MTwr5VUZBEaSLmvRAWR
         U/LQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=R5JpD9aZ;
       spf=pass (google.com: domain of 3wbcrxwokcskfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3WBCrXwoKCSkFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=s8CcAFiHVvcI34WTAH6Be8/J76ya8iOTJ5L5fCKdqRE=;
        b=CiFfGHtfkmXxXN+0hW6TGaFE3Fzv35PdlnbFVdTC8bbkRwXd7bso18yT6kqzAk0JLX
         xtuiBVGqZLFjjOU6JovPbjw9fMGY3fR5dpTfATxNCIzinT6oUHbLTcHLOOAZP5GSuZRM
         xm5Ek78XDPZ6jcO64CP08/Zc3Zagy69ou3CJQhIY9ZC6gPqNfbbyJYwfe1dsLf2YUMFY
         tiPWjNjvfzeMwk7p//qqxmcdnsL0GB21DS67QmZIFsGDznNOC+F56Wv/I7/Bcbyogvee
         jWPi9AJ4DyaTy+l75wf6pnRzFYscfi2i3R0C+oGL+VkosPIG6R3w+LrbbdnPLDrEC+LM
         Pjcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s8CcAFiHVvcI34WTAH6Be8/J76ya8iOTJ5L5fCKdqRE=;
        b=JoTrb7Q0lnOpKPzGDgiJ4pfhJ9kGX/8dy29ZXs1nyYKVmgtP0jSPkOjNHS9Sxz97uK
         jDTcSDoUlP82FzvySUauHWdM5LFiXkXLYes+3k/t7dzF6sPlwWtBQy9ixV/lhp84P2kS
         2hY3CnrrhNNFOpR/VNJpNNTGNaGuRIPWHySCp4mtg+5RIFOUIRp61gQIp3DN+5qz3rUR
         p7rVdQbKDJxbvPdlPXFRvt77nHE8y4HzI6mMixnF60bTFYP6HdnWk/EK37VHqhcar2EA
         7qSP9ngBTpFu/VDfwF+6W03bW1ZUKDyk3m1iWEkCXppQGEjV1bYuvlR3ylm43Qyo8ABp
         JdXQ==
X-Gm-Message-State: AOAM532H/nQ0dK6ujO+dCSP3qMuPl02HS2ThR2ZW+d9S4TDzvMfsmOEM
	qHHasc12aAgRbeNunrdZ5Mk=
X-Google-Smtp-Source: ABdhPJzCpPMr6AxCNogM3TwntyzTHQD0VGTagmjsZKW2igBH2jvVIsG+85TnddYMkhl2pEr79Q1cVw==
X-Received: by 2002:adf:f881:: with SMTP id u1mr27973465wrp.103.1605046361539;
        Tue, 10 Nov 2020 14:12:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a544:: with SMTP id j4ls463076wrb.3.gmail; Tue, 10 Nov
 2020 14:12:40 -0800 (PST)
X-Received: by 2002:adf:9cc6:: with SMTP id h6mr26562709wre.341.1605046360813;
        Tue, 10 Nov 2020 14:12:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046360; cv=none;
        d=google.com; s=arc-20160816;
        b=horHNkTcBiX4HGnjLi+Hydfqu7u0/CnTN9UtJmm0GUdoGSrDIhsjF54EiTpVaViYua
         3aw6e5yaOlOV7HmPWTRVWuDqT/C8ttqfIRG3534RK7CANRH1mCVTIK/LNrM7PvOdYvtA
         dpqyk8oAPMzRSxCfeH9ifIUckPfkVymyUGlphZ3HoQodtn+B6MtlNEIGESohvk3pnag7
         5m0CB9kblPkQmCrsZTNv/DADjupxF8HS77gZo6MjUXV2/5KSs9hE4/J1oO60sSIlXCOm
         LNKkCilv2wqhxttcmxw8UHG/ZTtve6qA4sTV24hTM5JzVB00OEpqkpj+KHRXJqnCR8qM
         LmBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=mrYrPbtFlwFDOBHjKpMO5h+zp2zY7teN7SdhYVzLhQg=;
        b=xrzpfj/t/uxEcN+1kEdFkGGhd/xhZAWIzcNlSSVskoRlpZnIaWGzYisUR+UDarhK4z
         lS2u765o5BffPWB89Mj7Pt8AHdbKStR/0oCn0mdv971EaLPfCrXFAy13Q+JxtFwUDQ03
         hfWaAOlrOCWDGFMUgKSt81WLV2lCQ70vE+KYd/MtpwkcrGX+tqwcAp6YVQBLR3jqOy5e
         di0faerR7mpvFg9n7+JvllvQxpJ3HNM5doM6sWvnIhUGz1ugSgt01jyGjWRAifJHneeO
         SqZomRU1LT75FFw+3aImBkZ/Jaro7VWWvbfH+FapeFrcOEnCWLgxu4SXkfvxW0GfmHxL
         VURQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=R5JpD9aZ;
       spf=pass (google.com: domain of 3wbcrxwokcskfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3WBCrXwoKCSkFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x149.google.com (mail-lf1-x149.google.com. [2a00:1450:4864:20::149])
        by gmr-mx.google.com with ESMTPS id t9si128687wmt.4.2020.11.10.14.12.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:40 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wbcrxwokcskfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) client-ip=2a00:1450:4864:20::149;
Received: by mail-lf1-x149.google.com with SMTP id h24so78558lfm.6
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:40 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a2e:9807:: with SMTP id
 a7mr6284930ljj.449.1605046360068; Tue, 10 Nov 2020 14:12:40 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:36 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <9f8119934070b7ffa8d129b64c9d05644ce7d20a.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 39/44] kasan, arm64: implement HW_TAGS runtime
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=R5JpD9aZ;       spf=pass
 (google.com: domain of 3wbcrxwokcskfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3WBCrXwoKCSkFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I8a8689ba098174a4d0ef3f1d008178387c80ee1c
---
 arch/arm64/include/asm/memory.h   |  4 +-
 arch/arm64/kernel/cpufeature.c    |  3 ++
 arch/arm64/kernel/smp.c           |  2 +
 include/linux/kasan.h             | 24 +++++++---
 include/linux/mm.h                |  2 +-
 include/linux/page-flags-layout.h |  2 +-
 mm/kasan/Makefile                 |  5 ++
 mm/kasan/common.c                 | 15 +++---
 mm/kasan/hw_tags.c                | 80 +++++++++++++++++++++++++++++++
 mm/kasan/kasan.h                  | 17 +++++--
 mm/kasan/report_hw_tags.c         | 42 ++++++++++++++++
 mm/kasan/report_sw_tags.c         |  2 +-
 mm/kasan/shadow.c                 |  2 +-
 mm/kasan/sw_tags.c                |  2 +-
 14 files changed, 177 insertions(+), 25 deletions(-)
 create mode 100644 mm/kasan/hw_tags.c
 create mode 100644 mm/kasan/report_hw_tags.c

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 656aaddb7014..5042eef5b111 100644
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
index dcc165b3fc04..6a1f2e3558c5 100644
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
@@ -1704,6 +1705,8 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
 		cleared_zero_page = true;
 		mte_clear_page_tags(lm_alias(empty_zero_page));
 	}
+
+	kasan_init_hw_tags_cpu();
 }
 #endif /* CONFIG_ARM64_MTE */
 
diff --git a/arch/arm64/kernel/smp.c b/arch/arm64/kernel/smp.c
index 09c96f57818c..7235b9478413 100644
--- a/arch/arm64/kernel/smp.c
+++ b/arch/arm64/kernel/smp.c
@@ -461,6 +461,8 @@ void __init smp_prepare_boot_cpu(void)
 	/* Conditionally switch to GIC PMR for interrupt masking */
 	if (system_uses_irq_prio_masking())
 		init_gic_priority_masking();
+
+	kasan_init_hw_tags();
 }
 
 static u64 __init of_get_cpu_mpidr(struct device_node *dn)
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b6fc14b3da53..f22bdef82111 100644
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
+void kasan_init_hw_tags(void);
+#else
+static inline void kasan_init_hw_tags_cpu(void) { }
+static inline void kasan_init_hw_tags(void) { }
+#endif
 
 #ifdef CONFIG_KASAN_VMALLOC
 
diff --git a/include/linux/mm.h b/include/linux/mm.h
index db6ae4d3fb4e..0793d03a4183 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -1413,7 +1413,7 @@ static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
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
index d0b3ff410b0c..2bb0ef6da6bd 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -113,7 +113,7 @@ void kasan_free_pages(struct page *page, unsigned int order)
  */
 static inline unsigned int optimal_redzone(unsigned int object_size)
 {
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC))
 		return 0;
 
 	return
@@ -178,14 +178,14 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
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
@@ -267,9 +267,8 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 	alloc_info = get_alloc_info(cache, object);
 	__memset(alloc_info, 0, sizeof(*alloc_info));
 
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
-		object = set_tag(object,
-				assign_tag(cache, object, true, false));
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
+		object = set_tag(object, assign_tag(cache, object, true, false));
 
 	return (void *)object;
 }
@@ -337,10 +336,10 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	redzone_end = round_up((unsigned long)object + cache->object_size,
 				KASAN_GRANULE_SIZE);
 
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
 		tag = assign_tag(cache, object, false, keep_tag);
 
-	/* Tag is ignored in set_tag without CONFIG_KASAN_SW_TAGS */
+	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
 	kasan_unpoison_memory(set_tag(object, tag), size);
 	kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
 		KASAN_KMALLOC_REDZONE);
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
new file mode 100644
index 000000000000..0080b78ec843
--- /dev/null
+++ b/mm/kasan/hw_tags.c
@@ -0,0 +1,80 @@
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
+void kasan_init_hw_tags(void)
+{
+	pr_info("KernelAddressSanitizer initialized\n");
+}
+
+void *kasan_reset_tag(const void *addr)
+{
+	return reset_tag(addr);
+}
+
+void kasan_poison_memory(const void *address, size_t size, u8 value)
+{
+	hw_set_mem_tag_range(reset_tag(address),
+			round_up(size, KASAN_GRANULE_SIZE), value);
+}
+
+void kasan_unpoison_memory(const void *address, size_t size)
+{
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
index d745a78745dd..21fe75c66f26 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -153,6 +153,10 @@ struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
 struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
 					const void *object);
 
+void kasan_poison_memory(const void *address, size_t size, u8 value);
+
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
+
 static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 {
 	return (void *)(((unsigned long)shadow_addr - KASAN_SHADOW_OFFSET)
@@ -164,8 +168,6 @@ static inline bool addr_has_metadata(const void *addr)
 	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
 }
 
-void kasan_poison_memory(const void *address, size_t size, u8 value);
-
 /**
  * check_memory_region - Check memory region, and report if invalid access.
  * @addr: the accessed address
@@ -177,6 +179,15 @@ void kasan_poison_memory(const void *address, size_t size, u8 value);
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
@@ -213,7 +224,7 @@ static inline void quarantine_reduce(void) { }
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
index 1fadd4930d54..616ac64c4a21 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -107,7 +107,7 @@ void kasan_unpoison_memory(const void *address, size_t size)
 
 		if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
 			*shadow = tag;
-		else
+		else /* CONFIG_KASAN_GENERIC */
 			*shadow = size & KASAN_GRANULE_MASK;
 	}
 }
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index b09a2c06abad..dfe707dd8d0d 100644
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9f8119934070b7ffa8d129b64c9d05644ce7d20a.1605046192.git.andreyknvl%40google.com.
