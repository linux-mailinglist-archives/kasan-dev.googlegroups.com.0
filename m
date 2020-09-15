Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6G6QT5QKGQESATT2YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 23DB026AF6C
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:46 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id e12sf2631426pfm.0
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204665; cv=pass;
        d=google.com; s=arc-20160816;
        b=dNgYsmX+qyMSjQJjbWvUSy+wLENxd7sZ+mVT9JsyPpit6ncStE7Tz2M7363qBxOIpp
         /cijquxkbeeaWnLiup1Vm6M+fgGUBXEAHSddQHPjGFodaYTLV9cU/z5GBkIMBtSGzi5w
         P146q0vVz9HmDX7Enfa4RbI0q+K561gcSF/SkcBVVGnTQ+6wnb6WzrSL5vkutl4O/pdQ
         oIRSI7eOpK1KVyjRa5eggEJ+ikSubkdIX3wfnVw+na6xu4fxp6DcBR68swJalTGsukEt
         nfwBeHknNNPT+ghtr7Lni6nHObgw+6dTfD2E4h16cEs3peb2JxtISRrHZN2LSFywH7jg
         tIYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=fYnvvOyxeNQHGpACzSkoKT/esUftsP4ewxItHBDGIJs=;
        b=qxMT8e0PoxSJsrHU+7WgKSqtbRcuEF2ODkAMQkMhJq+v3rBGPmkJ685AWGOYaqLot6
         Dmm3+tSMw61UlyV3uzxs0liaTEovLa7tb93PGISvVxu0oh0ZvR7Kqaky3yffhoWbN6eY
         TFfmjEgKvk/3FhMT9l+0oqk0l3mgS4yHT3gwcGObFF84puWjMyQAdmGdORmsFOleXxIu
         RFYJcswPcvy+FDGJ5V7qve8jkN0uS6jkAOt3s3hG1BlGHnsB1hBkY1ZOXQ7XFiEKdAto
         wSxMyfnrbxIf90BWu5Gm/7ynFJiLYQTai3QoqvqIuK/JX/8q/n7y/S8HAS1jd3iwkHsZ
         AGUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eGUywzkx;
       spf=pass (google.com: domain of 3dy9hxwokcvw4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3dy9hXwoKCVw4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fYnvvOyxeNQHGpACzSkoKT/esUftsP4ewxItHBDGIJs=;
        b=fUHayWc5FZF6v5s9VFgPmJhhrD6sU6fCvNV+by77K3Z9pc90MqLQObDTrsIOGUC78X
         OWWu4rhnRZ3Fw6YKWfkPKRHHfQ5rTJAFgXvsLWD3N5pqgEe8Y+/wi8ZH3dG6t9RJsVdo
         tbgRzJEoXjG7eaitTG/Latdm8p8vcYlPh2XfnFgRJdm5gt5d+xxkcb4sFdFOpjsMatu3
         zhwtjj1UtJmNX21kDTp8kqp7CxMRUXM/iqHnx82SQEHRRJv8cMCtaMILwtZT616DjjdX
         ZWRA+ZtyDvDP5y5XcC6RhjFZoreV8tc3lpVcIXI6qQGmno5aNNmeJkhbFYedmDcubhJV
         Gc7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fYnvvOyxeNQHGpACzSkoKT/esUftsP4ewxItHBDGIJs=;
        b=HqAf4qib3uNzYHBDhTmXObnkfxesQfVweStsimC0ld5VgtChqd5iVAdsD7atVcZevl
         3wL27/HqVHqbNxwYFz7BlhqZumKKiFra6H/fkyf3XkGolU5xwHp6Z2XPqEcG+OJ9CB1K
         U7X4jRR4JY7uI3FVnGVCvQykHfXDImJoZ0qc6efJoyQxcrtsOVlFrhpvkyHvLdkx3AQ7
         LIniWvZy9+kIFb9IVv81TODNHUw4QdP7XTxMFqm+RvLnjBsENZZp7LCSPGBczityZH0+
         lVAUClwe221DegzO5scAj2AAeA3maSvUbCi3Y/f1VLo+2sspfwAFijNGaCwiVVtXx44O
         mM2w==
X-Gm-Message-State: AOAM533kuQoO7vWN72y+xOj/h6qgW1sIlfCbdcpI7JGctheuvMzkdTu1
	3NPXSgUKfb3xFRgXwDZABQE=
X-Google-Smtp-Source: ABdhPJwlduaNDczX1RqnQONrTjLpHdj343IPeRZ1but2Q2pnelVWu0tHaASY/xn84WZdtUYM7gjcNQ==
X-Received: by 2002:a17:902:ba8a:b029:d1:e5e7:be70 with SMTP id k10-20020a170902ba8ab02900d1e5e7be70mr3393967pls.74.1600204664780;
        Tue, 15 Sep 2020 14:17:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8f92:: with SMTP id z18ls155372plo.11.gmail; Tue, 15
 Sep 2020 14:17:44 -0700 (PDT)
X-Received: by 2002:a17:90b:1256:: with SMTP id gx22mr1142524pjb.47.1600204664168;
        Tue, 15 Sep 2020 14:17:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204664; cv=none;
        d=google.com; s=arc-20160816;
        b=YRCt5AgCuYpK6YH9KqPrGHhm7flgLbzJCFOWlB0pQOwmR4pmRAWFjY+S2ue7TTckos
         8XPMfOX59wPSy11djs8YJipGoR4x8bgO6isT41Tfh89y3dLiyEJd2YvXxq8CR2zVdubQ
         Kb+elzOEJQ1+CZpZU14TNcP+0dY/zR/KnXXM1ux6vFGHTzA9O4UYXRG2Hc4rN5Ci/0rE
         VGonsbT4q8q5ieo/D0aRu6PXfDYYmBRFY3vPMVt1gLOTLCTG1WPOV43ODPj3Z78Uxi1T
         09IW70oe1ILgNZerHBw9DeauQqRH2/YOuEvHkF+R00nMlouZZjW46DPZExFPWjsg7Y3N
         bvAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=GS63ueuB4la1O7X0K9617yAQx4ln+SDXx/Ooc+f8eKM=;
        b=Z3LtZnbopx4EX7pKVltrw7jyuIEXzYrHv3ucBMb5DAnfhp3TwES9YCT9SiGJHZKsIC
         XFUdQjTGFH/DMlxZQlRcx12dlycjwFJtVPrYVIzGpw1paf4sTPKjaa0zZUM1iGruR32i
         GSQiyhbdSN78EACX3Pc5DfpDL8Jyr6via4k47Tfp31D3KSoBemWq6L3JTKK8Ijjn1nwY
         tT6BjesUhGViF3cqmCT7FLuXkPjj8E6xPSbbTdjhAr8E+2vCNukW8JQMp5Js4IN+IQi9
         Z7XCYSLK2y3/JcrDSf+P3SdCp3a+oCEPTf2QbpNC7J0xfjof3d3cL7dm/sKPYPIt4jtH
         K8Gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eGUywzkx;
       spf=pass (google.com: domain of 3dy9hxwokcvw4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3dy9hXwoKCVw4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id mm16si68974pjb.2.2020.09.15.14.17.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dy9hxwokcvw4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id w126so4119300qka.5
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:44 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:9d04:: with SMTP id
 m4mr3781463qvf.50.1600204663244; Tue, 15 Sep 2020 14:17:43 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:16:15 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <74133d1a57c47cb8fec791dd5d1e6417b0579fc3.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 33/37] kasan, arm64: implement HW_TAGS runtime
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
 header.i=@google.com header.s=20161025 header.b=eGUywzkx;       spf=pass
 (google.com: domain of 3dy9hxwokcvw4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3dy9hXwoKCVw4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I8a8689ba098174a4d0ef3f1d008178387c80ee1c
---
 arch/arm64/include/asm/memory.h   |  4 +-
 arch/arm64/kernel/setup.c         |  1 -
 include/linux/kasan.h             |  6 +--
 include/linux/mm.h                |  2 +-
 include/linux/page-flags-layout.h |  2 +-
 mm/kasan/Makefile                 |  5 ++
 mm/kasan/common.c                 | 14 +++---
 mm/kasan/kasan.h                  | 17 +++++--
 mm/kasan/report_tags_hw.c         | 47 +++++++++++++++++++
 mm/kasan/report_tags_sw.c         |  2 +-
 mm/kasan/shadow.c                 |  2 +-
 mm/kasan/tags_hw.c                | 78 +++++++++++++++++++++++++++++++
 mm/kasan/tags_sw.c                |  2 +-
 13 files changed, 162 insertions(+), 20 deletions(-)
 create mode 100644 mm/kasan/report_tags_hw.c
 create mode 100644 mm/kasan/tags_hw.c

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
index 77c4c9bad1b8..5985be8af2c6 100644
--- a/arch/arm64/kernel/setup.c
+++ b/arch/arm64/kernel/setup.c
@@ -358,7 +358,6 @@ void __init __no_sanitize_address setup_arch(char **cmdline_p)
 	smp_init_cpus();
 	smp_build_mpidr_hash();
 
-	/* Init percpu seeds for random tags after cpus are set up. */
 	kasan_init_tags();
 
 #ifdef CONFIG_ARM64_SW_TTBR0_PAN
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 875bbcedd994..613c9d38eee5 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -184,7 +184,7 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #endif /* CONFIG_KASAN_GENERIC */
 
-#ifdef CONFIG_KASAN_SW_TAGS
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 
 void kasan_init_tags(void);
 
@@ -193,7 +193,7 @@ void *kasan_reset_tag(const void *addr);
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 
-#else /* CONFIG_KASAN_SW_TAGS */
+#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline void kasan_init_tags(void) { }
 
@@ -202,7 +202,7 @@ static inline void *kasan_reset_tag(const void *addr)
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
index 0789f9023884..f8cf9ba674a1 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -10,9 +10,11 @@ CFLAGS_REMOVE_init.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_quarantine.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_report_generic.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_report_tags_hw.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_report_tags_sw.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_shadow.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_tags_sw.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_tags_hw.o = $(CC_FLAGS_FTRACE)
 
 # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
 # see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63533
@@ -27,10 +29,13 @@ CFLAGS_init.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_quarantine.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_report_generic.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_report_tags_hw.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_report_tags_sw.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_tags_hw.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_tags_sw.o := $(CC_FLAGS_KASAN_RUNTIME)
 
 obj-$(CONFIG_KASAN) := common.o report.o
 obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
 obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_tags_sw.o shadow.o tags_sw.o
+obj-$(CONFIG_KASAN_HW_TAGS) += tags_hw.o report_tags_hw.o
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 41c7f1105eaa..412a23d1546b 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -118,7 +118,7 @@ void kasan_free_pages(struct page *page, unsigned int order)
  */
 static inline unsigned int optimal_redzone(unsigned int object_size)
 {
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC))
 		return 0;
 
 	return
@@ -183,14 +183,14 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
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
@@ -272,7 +272,8 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 	alloc_info = get_alloc_info(cache, object);
 	__memset(alloc_info, 0, sizeof(*alloc_info));
 
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) ||
+			IS_ENABLED(CONFIG_KASAN_HW_TAGS))
 		object = set_tag(object,
 				assign_tag(cache, object, true, false));
 
@@ -342,10 +343,11 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	redzone_end = round_up((unsigned long)object + cache->object_size,
 				KASAN_GRANULE_SIZE);
 
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) ||
+			IS_ENABLED(CONFIG_KASAN_HW_TAGS))
 		tag = assign_tag(cache, object, false, keep_tag);
 
-	/* Tag is ignored in set_tag without CONFIG_KASAN_SW_TAGS */
+	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
 	kasan_unpoison_memory(set_tag(object, tag), size);
 	kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
 		KASAN_KMALLOC_REDZONE);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index ba63d8a62968..1e9eda217be7 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -152,6 +152,10 @@ struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
 struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
 					const void *object);
 
+void kasan_poison_memory(const void *address, size_t size, u8 value);
+
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
+
 static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 {
 	return (void *)(((unsigned long)shadow_addr - KASAN_SHADOW_OFFSET)
@@ -163,8 +167,6 @@ static inline bool addr_has_metadata(const void *addr)
 	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
 }
 
-void kasan_poison_memory(const void *address, size_t size, u8 value);
-
 /**
  * check_memory_region - Check memory region, and report if invalid access.
  * @addr: the accessed address
@@ -176,6 +178,15 @@ void kasan_poison_memory(const void *address, size_t size, u8 value);
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
@@ -212,7 +223,7 @@ static inline void quarantine_reduce(void) { }
 static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
 #endif
 
-#ifdef CONFIG_KASAN_SW_TAGS
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 
 void print_tags(u8 addr_tag, const void *addr);
 
diff --git a/mm/kasan/report_tags_hw.c b/mm/kasan/report_tags_hw.c
new file mode 100644
index 000000000000..c2f73c46279a
--- /dev/null
+++ b/mm/kasan/report_tags_hw.c
@@ -0,0 +1,47 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains hardware tag-based KASAN specific error reporting code.
+ *
+ * Copyright (c) 2020 Google, Inc.
+ * Author: Andrey Konovalov <andreyknvl@google.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License version 2 as
+ * published by the Free Software Foundation.
+ *
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
diff --git a/mm/kasan/report_tags_sw.c b/mm/kasan/report_tags_sw.c
index 4060d0503462..b2894902bc47 100644
--- a/mm/kasan/report_tags_sw.c
+++ b/mm/kasan/report_tags_sw.c
@@ -1,6 +1,6 @@
 // SPDX-License-Identifier: GPL-2.0
 /*
- * This file contains tag-based KASAN specific error reporting code.
+ * This file contains software tag-based KASAN specific error reporting code.
  *
  * Copyright (c) 2014 Samsung Electronics Co., Ltd.
  * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 4888084ecdfc..ca69726adf8f 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -111,7 +111,7 @@ void kasan_unpoison_memory(const void *address, size_t size)
 
 		if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
 			*shadow = tag;
-		else
+		else /* CONFIG_KASAN_GENERIC */
 			*shadow = size & KASAN_GRANULE_MASK;
 	}
 }
diff --git a/mm/kasan/tags_hw.c b/mm/kasan/tags_hw.c
new file mode 100644
index 000000000000..c93d43379e39
--- /dev/null
+++ b/mm/kasan/tags_hw.c
@@ -0,0 +1,78 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains core hardware tag-based KASAN code.
+ *
+ * Copyright (c) 2020 Google, Inc.
+ * Author: Andrey Konovalov <andreyknvl@google.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License version 2 as
+ * published by the Free Software Foundation.
+ *
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
+		round_up(size, KASAN_GRANULE_SIZE), value);
+}
+
+void kasan_unpoison_memory(const void *address, size_t size)
+{
+	set_mem_tag_range(reset_tag(address),
+		round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
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
+	if (mem_tag == KASAN_TAG_INVALID)
+		return true;
+	if (ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag)
+		return true;
+	return false;
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
diff --git a/mm/kasan/tags_sw.c b/mm/kasan/tags_sw.c
index feb42c1763b8..3df978b8d1d9 100644
--- a/mm/kasan/tags_sw.c
+++ b/mm/kasan/tags_sw.c
@@ -1,6 +1,6 @@
 // SPDX-License-Identifier: GPL-2.0
 /*
- * This file contains core tag-based KASAN code.
+ * This file contains core software tag-based KASAN code.
  *
  * Copyright (c) 2018 Google, Inc.
  * Author: Andrey Konovalov <andreyknvl@google.com>
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/74133d1a57c47cb8fec791dd5d1e6417b0579fc3.1600204505.git.andreyknvl%40google.com.
