Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYW4QD6QKGQE6MDBYMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id E6C102A2F2A
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:55 +0100 (CET)
Received: by mail-vs1-xe38.google.com with SMTP id h5sf1185832vsq.16
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333155; cv=pass;
        d=google.com; s=arc-20160816;
        b=YYPJJuINATqEwEVsorTEDQjcpMOoSkGxp3IrGy+rBcXKbR8IDdpdiGbLDKKXIhMIpq
         PpfrQ+oKrGwcQB5tVJmgJc924LsILdOp7qCym5L7ED1MyXGEXEG1g8I2z4q3h2q30MZE
         JZO0WCh1wCvfVz7JSY5V39XlsyCLyErRfWJ+DQgxfEuS895gF6prLyY2UbiOV5HmxKHV
         LCadXy/eEPLaRxa+CiHHK8Gdlh0bK+Mj2CDF8v48jZ8gfEz2RkhJWKKJL66miuQv1xLJ
         zxRkPaJnn/Ti/YBajB0tsy/PBxS6cP1ZX8JR67OVE+OsvAmlBv4ndEBLaexz7LLbpiSS
         /4qQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=1Eg/t1ZkDavVtwtJJ8Ri5VTCFKuFkqY41NwyPCtW690=;
        b=e52dpMtC3Dv8JrKufkdwseiUyCC46a80A1Ys+ttsuWurKNY2y0+wKJl9wodghRvbjR
         ddhn0QeKPc2xT2cGHcPHptXWhHV/eRR7FL6+AKi1otNUYl8NKi3+347WaDY9Keoero7B
         bTriYpwYwmHiLGAJI9kONRS0ZsB4/WhZ69CnDD+WNw7ask2rlnkPDKu6AMEz5/S0cK1p
         gmIaNnsiwK9o73aLhHk/U6qCTXwOrSPTqA245ToYg4cJCpxijdDSAxmC23iDSeFrBPGa
         PMB0CPKLfqJbmvN7HRYS1/qK5SW1s8onPsfleaQnLUMpzJqtqT6nyQ/QiizE2qpZCQgW
         txeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uyvLjiFK;
       spf=pass (google.com: domain of 3ys6gxwokcuierhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3YS6gXwoKCUIerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1Eg/t1ZkDavVtwtJJ8Ri5VTCFKuFkqY41NwyPCtW690=;
        b=ekNbmLeMYtJ0XPrWFFp/U40P0KRZb/vmZUo/HISOUwA4QdkN32c3I7N4r5iCUB336c
         KJCY82ylu0TB5EBA3DS5AvCng9xG6/JF1TLWM0ScVdSXTtmGAqB6YenMEdO2BgYK10Dz
         E1REqeiv5LpO7i6ekMU5N6UzRNPBnWwpX1pR7l8p1uq/SjweGDAOOq7KJowpmzfN4KwG
         qTmw8UXjc1dZcj+dvmRvLcjx3dGtKCM2IB51uLu2rsWmYTqI5+htHKSpxLh1zJvczFQH
         122HREebSNcAqoBX+zXZVzuxKCNTGTBkJIUCdv4xiWDBeAPHCSqzOU8PQpAER+zRtR0O
         mXtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1Eg/t1ZkDavVtwtJJ8Ri5VTCFKuFkqY41NwyPCtW690=;
        b=ay14Vy8bwZkvKUGzBp931j2AkctOA20Ku4i4noU9Nni4ROlSB5mRrD5LjSdXg9XZT0
         1Qlg47jtSF/tzbLrTxbxd2wpMN4ojxDWUWEJD9KtCExLjQt4q5M8rYi+YShXnj0nvjav
         zSpn+9ysSQtJ4fW7zYeNruArZV6C47zj4NBEeWdV54pfwO+bS91tpa83vR9Tghai6+0f
         C0k14WwxDbKyqhXKMYg/xg/QKV9fzQdW36T9SWmbBKdwAyd3krUxRDZDHsMppgrgxAL/
         UqAquW5Ou9l3lJkgMv48yTkc/H3q6fZbX/EBmaNRes/NrZuefn/kGlAk8WsyEvfkv7VK
         gM9w==
X-Gm-Message-State: AOAM532JbBLIyXXn/PgyKmNE4snPGnAEmAq4r5S1WoXmfKX+WXm1Ewsp
	LMxDI95NOjESjYz0ME6lcAI=
X-Google-Smtp-Source: ABdhPJxuJGJxJOFkAfOiV6hyf1MuoYS9q4hqYZb3jzZEJ35/q+i29yKVKeOoxhzFor8bcvhiGw5RZw==
X-Received: by 2002:a67:f857:: with SMTP id b23mr15217368vsp.10.1604333155005;
        Mon, 02 Nov 2020 08:05:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:874b:: with SMTP id j72ls1864105vsd.9.gmail; Mon, 02 Nov
 2020 08:05:54 -0800 (PST)
X-Received: by 2002:a67:80d7:: with SMTP id b206mr15110961vsd.30.1604333154194;
        Mon, 02 Nov 2020 08:05:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333154; cv=none;
        d=google.com; s=arc-20160816;
        b=S7YaxQW7mOu7e/Orn8O4PfsQlGjXPgoSDQpWEfT4oMkXMGBUpwpCKWV2xUQZLqm3QN
         C3v8RRhN44XWqobe0AiYXy203oYLio7XiipR3e5zeN6wII1hR3VdK1I9lkNJrjz49YDR
         6/Cu/cPFkSGYxExXo6njehSSSBy96clg8obmYNAvrqfduRspZrfa9rQbEtJ4jXNCRJ0P
         gbLP/66YuLB/Z0Zh8fYnXiqCAvM1OWfqqT0U/WMG28ZoGFLEADfKU8wYArS8i6kiWtTS
         J8VPGMQQPQ9OY1dzvVXjAS4M8jqehiBUAcE4SfKN9XPnRJz1pXfX9gs3nCvszIFq5y53
         mhgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=n9laSblWPVqU0a9v35znGWY0n0QUnfpyV3X/kSlN+mQ=;
        b=mI5efBUjKlCDW/EohAJJV1VpTo/kfyIr9N0+3z1a6/lza2kX1RCNKRD2a/FHnYb4gH
         DIwnlKTikM6WNwvJZkuPMc9gU2lHefFC863EuM+LirCxmlzNT2wi6tRut3plxUN/RWkv
         /9ppE6BP2s5WsuIWZieYqW7of8R9i2ugwCyHM5XVfeaGHZBdUxBJ1MhOzAnZFpeuzG7Y
         Hv6Ht2oq6MQoNasJMAqKYgVETOtFZadieNRnNVdTTzEf2guk6tGNsqFVSz8odqJJbIYY
         C9ukn/I2oFNiwb4aQs082vMFrkmX2Z54GrygEToVmK/AL/flcT9DGvT1ZCVTvnOxJ5pS
         LahA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uyvLjiFK;
       spf=pass (google.com: domain of 3ys6gxwokcuierhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3YS6gXwoKCUIerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id s4si521055vsm.1.2020.11.02.08.05.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:54 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ys6gxwokcuierhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id h16so8266253qtr.8
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:54 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:45d2:: with SMTP id
 v18mr21925266qvt.45.1604333153678; Mon, 02 Nov 2020 08:05:53 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:16 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <d34476bf236b01641aaba0f499a519180c6f4671.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 36/41] kasan, arm64: implement HW_TAGS runtime
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
 header.i=@google.com header.s=20161025 header.b=uyvLjiFK;       spf=pass
 (google.com: domain of 3ys6gxwokcuierhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3YS6gXwoKCUIerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
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
diff --git a/arch/arm64/kernel/setup.c b/arch/arm64/kernel/setup.c
index 133257ffd859..5271b9f4fb78 100644
--- a/arch/arm64/kernel/setup.c
+++ b/arch/arm64/kernel/setup.c
@@ -357,7 +357,10 @@ void __init __no_sanitize_address setup_arch(char **cmdline_p)
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
index 0661f5be5706..79655ceee042 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -187,7 +187,7 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #endif /* CONFIG_KASAN_GENERIC */
 
-#ifdef CONFIG_KASAN_SW_TAGS
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 
 void kasan_init_tags(void);
 
@@ -196,7 +196,7 @@ void *kasan_reset_tag(const void *addr);
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 
-#else /* CONFIG_KASAN_SW_TAGS */
+#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline void kasan_init_tags(void) { }
 
@@ -205,7 +205,7 @@ static inline void *kasan_reset_tag(const void *addr)
 	return (void *)addr;
 }
 
-#endif /* CONFIG_KASAN_SW_TAGS */
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS*/
 
 #ifdef CONFIG_KASAN_VMALLOC
 
diff --git a/include/linux/mm.h b/include/linux/mm.h
index ef360fe70aaf..777d8b4be35a 100644
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
index 000000000000..be89fbca0f45
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
+	hw_init_tags(KASAN_TAG_MAX);
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d34476bf236b01641aaba0f499a519180c6f4671.1604333009.git.andreyknvl%40google.com.
