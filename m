Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCMMXT6QKGQEPWWN5SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id EB3832B282F
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:46 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id w15sf6871239plq.17
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305865; cv=pass;
        d=google.com; s=arc-20160816;
        b=B0xM1zMvpL5RveTsCo/GebjwZLK1nnum6/BhEljlJ8XXnEK48opwaC8tdjDJKhbiav
         6OrFdNqQQXgBEIl/4aIFYJw6pp418ifTq9EvZWOVl4E8oMBM3u90XElg2ZOdiv0ibPpW
         lAYdm9zPrYaQPB/PzPejZhByFp9uz0PsH5y7qHNZDnSzSpQTzhtVtNG75NVsKF3ap5FU
         i0mB4qzvVW8cN92t5mu77s7dV2YiT1OszuHuWy2gibUNIfSESkIu1N0/6DwAhI2d98Qu
         PeSe5yNCVfBmzuYESa8t8LbA/a4lZ4slRQ75bm/3h0EIkrQlYlNwJNImuVqUbw57iBkL
         ze6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=jzRcnHPtTyKKu6FC3Pba9t5AQ7XxYcf1wZSaQ/rvtWg=;
        b=lnFtMoM5VC3mki/e3yJ3DOt9l+yncsAg827U9ZuwRPpv8fskqaYyTW3NjE7Nw4QaZs
         ijFcUbRAqZnndIQL+3VnS///zOyl3JA6C5K8IzN8QuoiCGlmOXO3UF0JecsQOJTxQ5IR
         lUeYxKhoWFPB+wkylmHjB4A82+K9ae71mQcr8t5UJpH0yAVYrxPfqCWD/bE0kWYGUA1j
         6MTUhZqWZuQZHxEYcJ1JkXCIbuSo92ZJmGDqQ21et+Zk+YJ5LtAg7D0mWWnUd4uN1s2z
         7jdkSXAP+TlzKgz40STu5jU3BULeB9VMvIu2rEQvXhbdSeIE+MO8pFRNGe1CI27VaKhJ
         LZXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lZ7e9QzA;
       spf=pass (google.com: domain of 3caavxwokcdmzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3CAavXwoKCdMzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jzRcnHPtTyKKu6FC3Pba9t5AQ7XxYcf1wZSaQ/rvtWg=;
        b=Lgnkrr2qKDVyViaoboHWBet/XMsDNMu4o6w0TVICFfQEgpNZ3l1ahY6zy4IroAjEbw
         9DRra6k5Wdlhv9gbYaYOst0awcpaSRWqFVDL+6IzqsD+lQfdb4a9VJm1whJ3ecr8JgRC
         H4ri4PqD8Gii+wW355MteaGTce1Y2tOXF7hkZC81dAeKahLT1BD0wP+M/DPX0LjoX6KU
         76b5Hqb+pcwW6o7wQHi/5ZHF53kPu7CpJ4LLATwEYlQPudbur2YezQkgychjLvzLX4iS
         27NuKZlfF4vQ2Oas1nfb+rnbxfxk1MdCY8yAdhemkiknIIliL5u8nH5WmFszNsz1GvVP
         pWzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jzRcnHPtTyKKu6FC3Pba9t5AQ7XxYcf1wZSaQ/rvtWg=;
        b=DyG+Oy4ptQ53nJtAB6ezXkWtmfedLq1w5Sh5BJU2kxfiklS2zJcpwL17MfS6fdPQ9A
         4z/M0+DjLrFM/pednseXxryKSJQdsrqQaGGYOHi3/vSxcPGmbj7wn+InGMmouwkVSYM9
         9aD3yCBKW6nwATYM5c7fc58ifqeTt0XWXjrBFw/bGlucVlRgEzIcRjT7ngS/bdP2BZfq
         0mWfsDDjd/60ZE2WtzWaziaYPe+6CMSP3FJgQkqzTvgNY3WhB4BLPx9WXBd58cwpCr0p
         ueqGWgSMtpR059CDXPiprX70O3lWI64kdtQfw8hZO+fQJX1KoKc61oBkhOiY6zWAOOk3
         lt8g==
X-Gm-Message-State: AOAM533ztdTqn/meRYyD4Is+7pECVG+MdqncJ8FF4nSv9rKuU9TjrxVE
	Nf5hy7SLNDdP7CEZYuS6av0=
X-Google-Smtp-Source: ABdhPJx+rvxrtRFUGeE5yT1xwanSWR4vsirPWZ95Zw7jg+7EjLIjWDG0c3k3NZw21/6Bkaa5zKQsqg==
X-Received: by 2002:a17:902:bd8c:b029:d8:db1d:2a35 with SMTP id q12-20020a170902bd8cb02900d8db1d2a35mr1954269pls.66.1605305865686;
        Fri, 13 Nov 2020 14:17:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3712:: with SMTP id mg18ls4394486pjb.2.gmail; Fri,
 13 Nov 2020 14:17:45 -0800 (PST)
X-Received: by 2002:a17:90b:14c:: with SMTP id em12mr5411548pjb.170.1605305865157;
        Fri, 13 Nov 2020 14:17:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305865; cv=none;
        d=google.com; s=arc-20160816;
        b=z+JOvizPL/zWIeA0RIklLgWdlBIihb95CxTc4zdGRrc2Y6WJn8HlCgTHAgs8rDM7g5
         RPfaT9AEGDQ9OO7M0rNWdaw+PqTJ+2PxQyyhZwWBBNxaaA3dUsMzDffQF6kfwoR7FNX1
         ys03JVeLPIIVc+G1ia1L9TKINkQRHBItzC3TaQUe3WPdLJipxgJyn2N/atu6mo5I1asa
         U4hagWHoMOvNfnKUPlOsYgmEo+CTzvf1zUdJQUoJ8liYnwF5AU1cJx3EJOFzbgIQTaj8
         Ak+7W52gO9wP+0d7hsSF4SI3xCI0qFzWPYt8re5dlHn1tgw8OtLVbmy70j8NcAt2rfzz
         lKWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=l8FhY8iLnm1UC3omxkrqQyTkWrd2zZI5cE2lswEOwd0=;
        b=MjefuYklCQTw30AlSlt/ceY/ZTOxIerSgSsDW3h/5aE6Fs4srxJnfO6dAPw0bq+csW
         9zdKfNBZNL5EWoGv7x38W8bNW/fZsGvusTnn0ovKvbEF/42ytyD9WayY5LX9uEnUKNva
         K5Abh0WV5hvWCPCjQLVjY435Z2TkUux9m88VgxxUVNxCZTuGr8RYt8DECWb2y7GUhZjs
         aNvQS/Zi718PSLO/qATDmvZHVJJ2oiKNej8RtnCl+8L2zSL5hRBni6NFOJZTdzpu5EsY
         OGp3kdI4ekPeoMFdMwG9rntIdorwaR6H9roUthoC/fE4B1QKScUDjDSxiNRv+O2d/4T+
         d/zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lZ7e9QzA;
       spf=pass (google.com: domain of 3caavxwokcdmzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3CAavXwoKCdMzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id v8si672533pgj.1.2020.11.13.14.17.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3caavxwokcdmzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id s8so2714604qvr.20
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:45 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:9e2c:: with SMTP id
 p44mr4583776qve.55.1605305864212; Fri, 13 Nov 2020 14:17:44 -0800 (PST)
Date: Fri, 13 Nov 2020 23:16:05 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <962bce0035be5c0d5293ad93f077e110eb12e275.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 37/42] kasan, arm64: implement HW_TAGS runtime
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
 header.i=@google.com header.s=20161025 header.b=lZ7e9QzA;       spf=pass
 (google.com: domain of 3caavxwokcdmzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3CAavXwoKCdMzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
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
index bffcd55668c7..3f07af6d140c 100644
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
@@ -1711,6 +1712,8 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
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
index 1ed52bae5142..947f4f1a6536 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -1414,7 +1414,7 @@ static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
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
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/962bce0035be5c0d5293ad93f077e110eb12e275.1605305705.git.andreyknvl%40google.com.
