Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGMBSP6AKGQE52RZEZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C24828C315
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:46:18 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id a73sf4324522edf.16
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:46:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535578; cv=pass;
        d=google.com; s=arc-20160816;
        b=1ILC5xhuvC/5vKNILErY4lxCWO51Ts0rGdAaJYkoxuDF1lUwAHT+RL9WRqeSu47CpM
         fpxuTSpgBElYjZmDXPovLWJ+4gDWE7bf6jikmbeHQ9f/Tp7O7FRic/w3xL1OIyzFUvZw
         wq+wskeN1rSfeyMcrgxWEpcubIlln2pqv2BtA588/3nwhRfG3n9gTsjA4ymnIBSyvo49
         gpPjAm7mzwsm5jpFULET03naON4zL4PwZIijxjiPydnygWQ1xewzrhGOqJ2igTI2EsoQ
         TZ/NLg6y0uGRy+fyyf4m0Cb4jr8v9QL+xLUKhXJqJH/O2u4owKUD2S/f2ZqMrIOWqRTN
         zMJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=bhpi/pQ1ywUY5B1chvtzq+hYjsC7EGa7RCCmO4G0ZdM=;
        b=bD7maql9d4i9172MQVgVuc08hZrvBcRgsTzWR21KSVcn5nRZVbaYBaM1LCSSvYzEJT
         BkQXJ+6dOm35xu1DEnNm03TfL0O5GEnp/d6algYqX+UZIDOEQrQ5ZvFDosQZFDKrSG64
         PxQmalsGTx3zNawI60u1Bhv8LNQlrfSdDq5aS6gt/z4q08x2gTcY0gzJ97JwRcYWO0LC
         wgr/y1tIgnGzMVPO1j+qP2Rr7wzoMD+YKoDVow2cKamz0n9VnhqbrtbSziRwNnZrQ6aT
         wy4ERSjNP/HSVN1g5zrIv/XpxM3o2VZN+d33yVEjZ7mZcUhN+n18+xCYQpjGIAzNuFp7
         ADqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kwNK0uiI;
       spf=pass (google.com: domain of 3mmcexwokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3mMCEXwoKCS8LYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bhpi/pQ1ywUY5B1chvtzq+hYjsC7EGa7RCCmO4G0ZdM=;
        b=tQeZIvshwTGbi0mzYhWhX5uz4d6lrO81i7mSriB/5ulJy07RrImx19emevbCKUi3HH
         7xdzDP3MRUAKHdFJriLAVS9ypfjx0IEVtcpSX3m/p624lGghDHLiaE6T6E5IxVFb6lLN
         AXvWsGPsNwIkDZsc7jD/UUQ0SrsyNFWm3V3Gwuv8/pXgkgLsbIDDe0hhk1+9B5PsU4qf
         vYiBl2FDVHqLk0qlZ3cfS/D8oZWfca5mnATzwbwvidp7Pp/OJlyL5rXZeJGYerJuJprD
         M23dAfuaVI7lVXbz3tf3Ih6kozdnGlt7yhMu/JTVg8tiraPT6InGWvNEE4FZJyLDlwzq
         tzPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bhpi/pQ1ywUY5B1chvtzq+hYjsC7EGa7RCCmO4G0ZdM=;
        b=lkA/+y0Mv6BXolfLePj31l4bc/GBbDDLSzlmTVc0YTgzmneU5HisPGehbsiqp1cuSv
         O+xNn9aD6SrVa8d7YgLP6Nnjw0dbwATcq4T9t6j4MaSjBQhLB8P8ZZne2A5j3t0aXv4c
         iHQ5+cBxhVn7UrY3lUc21EO3Lbv+QxqSOOcmWFYRUWyw9de6GEe1LF7rudw3UVhUDrEM
         qxHAfivwvyXUrJ2Q6RuB4I4xErvg8dDRcC2nQy924spXwzsPTQXtrJAxd+qT4nmxJeqn
         1yuH7ygaNHzvr1mHdFGUelAW9T5giMa5ULNcRWKxElHY98w7MtiIotL//jVo3yZVhtyh
         MyZw==
X-Gm-Message-State: AOAM530ivh+yUrfgZZYz+ZdU9g2xkkhTDzF5hjGlK97DJncWdC8ct5+D
	J4ygnJW2kzFdaouuaTM+42o=
X-Google-Smtp-Source: ABdhPJxM8KLUCWAv1f439FHvaFt0VWTzr8CvwNixw0bEJN/kcMkKw8J9cg8y4gm70DJ4z9NUBeS/rQ==
X-Received: by 2002:a17:906:a211:: with SMTP id r17mr30772836ejy.444.1602535577907;
        Mon, 12 Oct 2020 13:46:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:160e:: with SMTP id f14ls68033edv.2.gmail; Mon, 12
 Oct 2020 13:46:17 -0700 (PDT)
X-Received: by 2002:a50:bc01:: with SMTP id j1mr16805178edh.66.1602535577011;
        Mon, 12 Oct 2020 13:46:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535577; cv=none;
        d=google.com; s=arc-20160816;
        b=HlCSe3Z4UbCVBr7WJ+WUTjYguYnuDoeOPD2a33BrRaefG4w5hDjuinoBpCY7h5/wmj
         I1myy6r6oSP3Bf7ZWp5xXx6fmmQNapYcjaoaej602yzE57oCapf8GnPXa/ckaHaiMWnp
         ke6xjE8TuLf9Rkyt4v/wD8bQIiMp9XWAHDIjo3H4oUTSDV54ywpgZcJk1hHq92XLGuAv
         dsqxYvSClIwDaBg+JqwZiZiWmU36lyoyC9uMn51krsbBmmuufCOfxEg3UOi4eIrJC4yX
         f9KfLr6ofV3JNdXVwWYRxM81Czh114CPD1OFKFkd8F84aC+jav9ljF1jaV85zw7/7v31
         vwdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=uIpusHXl35Xv9DgfcZtbVlzgB9Ejy/BOtVqKPNQSwjE=;
        b=ORGsjfy8w8Aw24frJxvLzRMlRag2q+OPqvxtAzEnZf/0aZCoKqQalgk20+fgj6bM6H
         qgG8eRlm9Z0X32ORIwkOd7lW3O8IDTFHbcVfI/MI7InYZRrzDgr7ueTunc7JPYgMrAZF
         sUlOQwBjV5FwHtmGl6vfSzhKjITfBij1wCrgy6v8KKb8t7V3HoBS/frN87svjiGqOcej
         tJ8sOVLaAJUBgmce7dzzh2L6JgV0jLBnn0LRcVqRkd3f9tAkV6yZHjdgUPif/wpAAdjo
         nEK0OFX7fzlPp5Ia30A+9XCv8wTkZB7vpLUPpZwd2pNVbdlwSLslckY8GtBfUeLFwj9l
         I7Bw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kwNK0uiI;
       spf=pass (google.com: domain of 3mmcexwokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3mMCEXwoKCS8LYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id g25si431019eds.3.2020.10.12.13.46.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:46:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mmcexwokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id f11so9783301wro.15
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:46:16 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:791a:: with SMTP id
 l26mr12931602wme.163.1602535576628; Mon, 12 Oct 2020 13:46:16 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:41 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <d55051a16e6c32761ccf32caa1a6f6fe889bbec8.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 35/40] kasan, arm64: implement HW_TAGS runtime
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
 header.i=@google.com header.s=20161025 header.b=kwNK0uiI;       spf=pass
 (google.com: domain of 3mmcexwokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3mMCEXwoKCS8LYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I8a8689ba098174a4d0ef3f1d008178387c80ee1c
---
 arch/arm64/include/asm/memory.h   |  4 +-
 arch/arm64/kernel/setup.c         |  5 ++-
 include/linux/kasan.h             |  6 +--
 include/linux/mm.h                |  2 +-
 include/linux/page-flags-layout.h |  2 +-
 mm/kasan/Makefile                 |  5 +++
 mm/kasan/common.c                 | 15 ++++---
 mm/kasan/hw_tags.c                | 70 +++++++++++++++++++++++++++++++
 mm/kasan/kasan.h                  | 17 ++++++--
 mm/kasan/report_hw_tags.c         | 42 +++++++++++++++++++
 mm/kasan/report_sw_tags.c         |  2 +-
 mm/kasan/shadow.c                 |  2 +-
 mm/kasan/sw_tags.c                |  2 +-
 13 files changed, 152 insertions(+), 22 deletions(-)
 create mode 100644 mm/kasan/hw_tags.c
 create mode 100644 mm/kasan/report_hw_tags.c

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index de9af7bea90d..b5d6b824c21c 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -215,7 +215,7 @@ static inline unsigned long kaslr_offset(void)
 	(__force __typeof__(addr))__addr;				\
 })
 
-#ifdef CONFIG_KASAN_SW_TAGS
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 #define __tag_shifted(tag)	((u64)(tag) << 56)
 #define __tag_reset(addr)	__untagged_addr(addr)
 #define __tag_get(addr)		(__u8)((u64)(addr) >> 56)
@@ -223,7 +223,7 @@ static inline unsigned long kaslr_offset(void)
 #define __tag_shifted(tag)	0UL
 #define __tag_reset(addr)	(addr)
 #define __tag_get(addr)		0
-#endif /* CONFIG_KASAN_SW_TAGS */
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline const void *__tag_set(const void *addr, u8 tag)
 {
diff --git a/arch/arm64/kernel/setup.c b/arch/arm64/kernel/setup.c
index 77c4c9bad1b8..b07d9fbfa8b6 100644
--- a/arch/arm64/kernel/setup.c
+++ b/arch/arm64/kernel/setup.c
@@ -358,7 +358,10 @@ void __init __no_sanitize_address setup_arch(char **cmdline_p)
 	smp_init_cpus();
 	smp_build_mpidr_hash();
 
-	/* Init percpu seeds for random tags after cpus are set up. */
+	/*
+	 * For CONFIG_KASAN_SW_TAGS this initializes percpu seeds and must
+	 * come after cpus are set up.
+	 */
 	kasan_init_tags();
 
 #ifdef CONFIG_ARM64_SW_TTBR0_PAN
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 894eddf42168..3f3f541e5d5f 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -181,7 +181,7 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #endif /* CONFIG_KASAN_GENERIC */
 
-#ifdef CONFIG_KASAN_SW_TAGS
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 
 void kasan_init_tags(void);
 
@@ -190,7 +190,7 @@ void *kasan_reset_tag(const void *addr);
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 
-#else /* CONFIG_KASAN_SW_TAGS */
+#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline void kasan_init_tags(void) { }
 
@@ -199,7 +199,7 @@ static inline void *kasan_reset_tag(const void *addr)
 	return (void *)addr;
 }
 
-#endif /* CONFIG_KASAN_SW_TAGS */
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS*/
 
 #ifdef CONFIG_KASAN_VMALLOC
 
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 4312c6c808e9..a3cac68c737c 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -1411,7 +1411,7 @@ static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
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
index 000000000000..7f0568df2a93
--- /dev/null
+++ b/mm/kasan/hw_tags.c
@@ -0,0 +1,70 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains core hardware tag-based KASAN code.
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
+void kasan_init_tags(void)
+{
+	init_tags(KASAN_TAG_MAX);
+}
+
+void *kasan_reset_tag(const void *addr)
+{
+	return reset_tag(addr);
+}
+
+void kasan_poison_memory(const void *address, size_t size, u8 value)
+{
+	set_mem_tag_range(reset_tag(address),
+			  round_up(size, KASAN_GRANULE_SIZE), value);
+}
+
+void kasan_unpoison_memory(const void *address, size_t size)
+{
+	set_mem_tag_range(reset_tag(address),
+			  round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
+}
+
+u8 random_tag(void)
+{
+	return get_random_tag();
+}
+
+bool check_invalid_free(void *addr)
+{
+	u8 ptr_tag = get_tag(addr);
+	u8 mem_tag = get_mem_tag(addr);
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
index cf03640c8874..f6363d1d6d26 100644
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
index 000000000000..d8423d1e3b6b
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
+		buffer[i] = mte_get_mem_tag(row + i * KASAN_GRANULE_SIZE);
+}
+
+void print_tags(u8 addr_tag, const void *addr)
+{
+	u8 memory_tag = mte_get_mem_tag((void *)addr);
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
index b2638c2cd58a..ccc35a311179 100644
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d55051a16e6c32761ccf32caa1a6f6fe889bbec8.1602535397.git.andreyknvl%40google.com.
