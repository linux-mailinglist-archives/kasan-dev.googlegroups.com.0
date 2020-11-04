Return-Path: <kasan-dev+bncBDX4HWEMTEBRBR7ORT6QKGQEWJCEKIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 063302A714C
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:40 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id n17sf107241lfi.11
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532039; cv=pass;
        d=google.com; s=arc-20160816;
        b=TmE7CD5AbWf30RppQIue4I9pJezK1UOFyu/tbOa7QJ6PxGE7Vzd8dhEay5FgFCVekj
         l12/e5FLyyTRCoNFCKUlTraqoF0eN8mVHTSEGkdQCgWk2jVJGxmtE4sQqqeakST3rkvC
         gEkvkgjurziI4ApIjNhJ6EhC17+tItFcbN8WdGylQ7hJzRxXlK/1sL8EJIiZvnErvHrz
         AOe2MfN6vy80JD4xy/VI1Jpg46JmfF34rqJafVojnkgS9pxCWLD26fLORXfr+QJFxjuo
         TCN36Z13780TCtbcm6Zv3UA455kmxQpx0mVkPrLZ/aooUs9Vj+N+m2Rmnw577LoSwpbq
         IyWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=5q1IBkQkaJfH4HLqPrNOV/4w4NDEk2iVjvGEYtw6SKc=;
        b=pr+vdGrCZ2XpHcG9ke57vT7eTT6P7YvSyIb0ZEhzpJkcLyZbgL00h9HJzmV3ejNQfY
         PSQfGEUzTPUr2IQMf3AIiuGxJD8nwRhjvagwX6wArkZAtpxeFIrSITJbYqzhPKkHUd0u
         1PMAyWUlIrLjilLURO4NAdBOjmTFBazO9cKQZxUFENMpBEr3xjhS38QvXg4i09S4fQSZ
         JXbiOTsRKfBkohFK4IH8B4nF4BeFKBnlKohvRjMjfi+pJAwVDxqOXb+F9R35N+c0Xxot
         tajOg4BKQksDLy3gj9EOKCvRSbraSJt7TAFZ/JP+ueiuPEYBJTNZqOlqYC1nT3UxQAZy
         j5iQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rqy67E2U;
       spf=pass (google.com: domain of 3rjejxwokcuuhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3RjejXwoKCUUhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5q1IBkQkaJfH4HLqPrNOV/4w4NDEk2iVjvGEYtw6SKc=;
        b=R/tHfKTSDlrz8yDXIXQIJOv3Xc7Acxw8ESqSEqe6CYsiIilrDux2wfqqKZxLUZLWKS
         oUVKM6dWkyzpsH5BfChSq16SKe82NEpSRZ1PO/Ifu0dvwmC7VNkqQrO8TsjsoxBhWZ/I
         j0bj5bQMssFjOteIDLV0IfCxx6pClb0icepJPMAWhg5pqOy4+eKYWV1xS+bP34c3ljJn
         GZ75AIDm8SubxYNSLdzapzv87/yjYz9UvYbfPIjPmGZG8/rGLjwqNtF6tP95EqYq8GN+
         5JFWIu8ZklKomQsOYBKeKY9Tv5wbq3Mtwouh9rQbQqBHR11zvCl+KPLjRe4XyUtvzioS
         qfgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5q1IBkQkaJfH4HLqPrNOV/4w4NDEk2iVjvGEYtw6SKc=;
        b=KRVQb72GJJdg+LKdniaLAMIGt77Gw+C1nlo1vQcqkM1fnBL8k776SBZMKNEBeFZ9+8
         0/z6TFNfHr2T9ibv8eR5glw1MLYPC3Of5t3od78PSL1myQ3Hx7k0FcT9t7x6kmMl+Uor
         dtAUVC7EfiNyDBBpRikLkIWJFcGEzOJOYYR4krJB6DTAbSR92jK3ZB6foajwMXgY8Ljd
         RioENglFVL4tQB3i7O5UbYJqPuSQ8WP3qg4h+8iUV7yVQkeaZra77luWIl1f0XogJPy9
         kcxAFz/jpydFMGD+mhD0/Q3Yy20Ydx+ZgXH9L03Vgz3dpeT/AR36K4+ouyBLLBhvY0Ma
         3H3w==
X-Gm-Message-State: AOAM533SNuyyq9Si0W5vq5ZvCTlwkzuZzr4QxDDa5CWIwn3n5wT1Vfj6
	qtOX3t2x/TotabWXc/qDUXc=
X-Google-Smtp-Source: ABdhPJzQZto588kwUMYtZOCla9s78Y0TIvmYhlSgdt974iTztR3/oKrAAhgUdkbyxilLHQSMPllmJw==
X-Received: by 2002:a19:4815:: with SMTP id v21mr11437lfa.603.1604532039576;
        Wed, 04 Nov 2020 15:20:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b5b7:: with SMTP id f23ls673618ljn.2.gmail; Wed, 04 Nov
 2020 15:20:38 -0800 (PST)
X-Received: by 2002:a2e:9702:: with SMTP id r2mr118282lji.360.1604532038666;
        Wed, 04 Nov 2020 15:20:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532038; cv=none;
        d=google.com; s=arc-20160816;
        b=A6ABp13uyZo2zaH7TMoo+l2XfpqZSVSEjO3tZWJCVTRIPW4h/PG1uH1S5+CoL4ggSq
         1+qo1RdTwIjtRdN2k1kHJdwgPwksKraESDYbxL1p4XTx+moxr8wUwhXOzk1a8ncPfmFJ
         Q8gWKFQzKAJ2xwGtxconSDclKJ54q+BeBdeb/BhvEA7ta5mdA6U9dzyy6cE4ccNzg+sp
         WBCy3qw8C0du9Fo5ycazNp9D3OceH1Hn55lH4bHgaki0gICibcdC/vzdtWpZ85ftYDip
         dmx+N2TzsWoiHjIf1kLMsyqwIbpX7ioj8bVRCjJ5LFe03/8pK5YC9xiXIdogoS+aQY0H
         tI3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=lPY7PJCK16UmR8RN2RBmgmWrbvOdJWJ4hhQCD1C5stE=;
        b=F2IQdMxysxr6/IMYO11FpBn7jqeK6CMhHbI1dWE8p2IGGhPVTljXFBkbxwlL2ob+Q9
         PO3GXUDWdclMNHL8xeehxTqTv85jJauUYe/q9abc7VT1gUifq7ckZFJxqMNNL2th5GJO
         f2Jr+0W+Gk0N2mPBH59EInnvzsIVxMstM+BbsKWZVQOL+o7T9r0AaW/i1MRVI/0aKwzl
         qdWJ6O/BVyxP4HKLYloaAJ9hPyWDwLBdQASl12hG/ioaY7pnZ4oIDd3PNlD/l1NFdJMM
         DuNstvwLK5M3HENeBAIk4ioEu4BrGF+YHlMKZjxXS9IxqeJD5wk196mKlSu4+qha2Qe4
         ktzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rqy67E2U;
       spf=pass (google.com: domain of 3rjejxwokcuuhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3RjejXwoKCUUhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id v24si116686lfo.5.2020.11.04.15.20.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:38 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rjejxwokcuuhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id h8so45179wrt.9
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:38 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c3d5:: with SMTP id
 t21mr63924wmj.37.1604532038336; Wed, 04 Nov 2020 15:20:38 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:53 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <9b0c00ddb76e15cdcd86e12f85ce4f8a5e946299.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 38/43] kasan, arm64: implement HW_TAGS runtime
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
 header.i=@google.com header.s=20161025 header.b=rqy67E2U;       spf=pass
 (google.com: domain of 3rjejxwokcuuhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3RjejXwoKCUUhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
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
 include/linux/kasan.h             | 22 ++++++---
 include/linux/mm.h                |  2 +-
 include/linux/page-flags-layout.h |  2 +-
 mm/kasan/Makefile                 |  5 ++
 mm/kasan/common.c                 | 15 +++---
 mm/kasan/hw_tags.c                | 76 +++++++++++++++++++++++++++++++
 mm/kasan/kasan.h                  | 17 +++++--
 mm/kasan/report_hw_tags.c         | 42 +++++++++++++++++
 mm/kasan/report_sw_tags.c         |  2 +-
 mm/kasan/shadow.c                 |  2 +-
 mm/kasan/sw_tags.c                |  2 +-
 13 files changed, 169 insertions(+), 25 deletions(-)
 create mode 100644 mm/kasan/hw_tags.c
 create mode 100644 mm/kasan/report_hw_tags.c

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 507012ed24f4..b245554984a2 100644
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
index dcc165b3fc04..b66a96525a3e 100644
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
+	kasan_init_hw_tags();
 }
 #endif /* CONFIG_ARM64_MTE */
 
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index beb699e90e55..c6bf762eb88c 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -187,25 +187,33 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
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
+void __init kasan_init_hw_tags(void);
+#else
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
index 000000000000..bdb684c65561
--- /dev/null
+++ b/mm/kasan/hw_tags.c
@@ -0,0 +1,76 @@
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
+/* kasan_init_hw_tags() is called for each CPU. */
+void __init kasan_init_hw_tags(void)
+{
+	hw_init_tags(KASAN_TAG_MAX);
+
+	if (smp_processor_id() == 0)
+		pr_info("KernelAddressSanitizer initialized\n");
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
index 618e69d12f61..b0a57d8f9803 100644
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
+	return PageSlab(virt_to_head_page(addr));
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9b0c00ddb76e15cdcd86e12f85ce4f8a5e946299.1604531793.git.andreyknvl%40google.com.
