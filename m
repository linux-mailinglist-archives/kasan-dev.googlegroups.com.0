Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPNN6D6QKGQECMQQ53Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 400522C153A
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:08:30 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id n13sf1515418wrs.10
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:08:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162110; cv=pass;
        d=google.com; s=arc-20160816;
        b=hXXej53kVWE0q74GOdphK2PHzxKe2ZzsG1eNXGoETDLnW1f1/0u+xaH8Hg07D0mBm1
         yo37YkNME9rgWVmWfpsNmDfvrP1t1hWkJvs9a1dirItBx98pu+jLbsBpAIMH5NSXEuc6
         rIA7tzqgAM4tmzv0VtX+2XNoO8aOQBNp6xwnQ0FFYn80lIzE/LGBbQEoa8uvCc+LPtqS
         /4UW26aoWhD4pa3fkRiRJsxvUCtoLoma59GIZ4RIrbsElS4YxBg9pKfQDwNfWeJuwMPw
         27YGTyybykPVn2oRlMBO/kYSKmeyoDhiqIy/2PR1HKFGTRp6tmSytig8btljA88aSh5O
         LB4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=s4HQ1yFn9Ij8JgIOv7nJbT1TgPA4DMS98v6uStss16A=;
        b=Bi8OcQ8fCsBpMe5IfE+kTh2FtDgDq5oYz2/OBj7NnYxrAZ/+AWwenC4V7Th4wHV66o
         +UPZkSWoNodKZlT+dK9lAF128UptAfJ6Ip6NQxVene1FAZ07hzusisfzthnsvGHVa5OL
         4KOu8JClMm+iv84T81ZOJb/ufB5F7DdKFFNPl0w4KUDG/p94YLh+41K5uBvanU85Zh7F
         fJKfSFjr4er2QRM4VMk/DD8/s5X7YUTKZHAh269XzWZlYyzHCsGqdbWkPMyOZ4Yz9KQx
         bMN4G5MUsEnrvCgauDz5jDNDHpKNh2kwHwl7DH5QXun5W0pXLaZemHB8EtjWXyD287Xm
         OAUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W0DqXgU7;
       spf=pass (google.com: domain of 3vba8xwokcd09mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3vBa8XwoKCd09MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=s4HQ1yFn9Ij8JgIOv7nJbT1TgPA4DMS98v6uStss16A=;
        b=d7ABCGQMnQhGdLFO3VFI04AA9BMDbh3u/YEJHZ8uvN9YbfoQFxHNQY54cOTh8G7BLN
         gWhS2rbZ4+tsDWWcPYOSqSsbXpDm8OB/6awna8U1GFPL7bFvvdjDRSMJLRIRMl1VX8wL
         YDgljAXyFuIbqvA9vm7f+5sKeet0inFPTZBPPsUtKdeqVJCtB8V7BIWH+x2g70YrIywP
         9/FSm6erp4eXLmB7hyEXaqZsOHbbkWusUYza7agzIDOuS56LeSmax9hMgGRPn7dEVRL5
         rJB3SR6FT7R47NGjKRjDVyKoVBZJfnQan5bQREVroGaSsapCo0D0rwBj2xIU+gM5LH4h
         xugQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s4HQ1yFn9Ij8JgIOv7nJbT1TgPA4DMS98v6uStss16A=;
        b=C9YCtqzF+9Rh/gnOH6Iaw7TqLMbEMhUVk3Zqd09anGk+TmUZU2qkgJ5ov7ZSzbF1q0
         XZfL6YB1H//TrqD9fe1BWZpZCb45MjDpU9kx4FZvCvu4BFt6/fJvKHdTpVYIulR5gSKP
         eRY7/d6y4NtUPurUUfCOBjg9m8ZG5MYtb9PtH0kEs9EUnqfYp58f4i/nlFw/WThdFR16
         I3GKEfBarQ9XeYV2JW/gVjK7a1qwxHVkXE4+VRNFPSfqEr9bycJf2c2Z5Mb9j6a49LgN
         GnEVXKAbLTuHwd3dSyrJ6IKKwnhTmPMup18B8P2zAQsHjA3fQv3pr6oyfas7Y/GI4gdm
         /sDQ==
X-Gm-Message-State: AOAM532WDsaehOly4M9WFQL2NsXbAYog8T6KNXZceY6tKl1St96FUTa/
	m5Dx4MI9QSr2S6JZh72ez7M=
X-Google-Smtp-Source: ABdhPJyjYE2M/wDel7UBmYnutXBIMoFp8HhSxiGzWpaB76CHilukRQuFb4Ti0kWApavv0b2257MkJQ==
X-Received: by 2002:a1c:bdc4:: with SMTP id n187mr568681wmf.147.1606162110009;
        Mon, 23 Nov 2020 12:08:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f70d:: with SMTP id r13ls8963552wrp.1.gmail; Mon, 23 Nov
 2020 12:08:29 -0800 (PST)
X-Received: by 2002:a5d:50d1:: with SMTP id f17mr1445067wrt.264.1606162109110;
        Mon, 23 Nov 2020 12:08:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162109; cv=none;
        d=google.com; s=arc-20160816;
        b=kF3Wt9Z1bu6le049cEJhrriqPonBANC4RgnTSjN7HXJtKLa/PvHm5vELiQujsWeWWH
         PmiNej0cNTGNgrm2X3j92zKYWnCRAdQRMJYU+NhNVHcDD2BvdcbHIiytc4yYTXLOIi14
         DhBg0BAvO7Gtm1fw22byUSVGwOoC3PmJGzVfk8TUnV04mHO2Gb/++91/kg3nxOl7hlmk
         JUdifKBMiy58No2RhcVj9m4Ymffz7cva5nWMDTBSs+Ggg0VwbStDX+Kfw1TaOIrUmgd3
         biIddmQzPVZ8OXyyDyWcvZs07JI/8K+7cpSxB7JuJJNvE8jiMVUci8N3dvc1NIgQuMQR
         O6xA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=rY7yMii3gaWV4vY+mOJjHDhvV20XyRJBFdhOjQqTKLM=;
        b=eBU9o5DD3NQm6D5669fXrWSRe/D6mjuCLg/khEdNR3QH0qb+VJUy3KOV+kS1kf0nx7
         pJQ+LJQDqjDHNr5Akbcj0s/WcfIj47vfBhURw3hgVwUFS4nPFGVDrP7zY+kwBH+HGx4t
         D4H00P3Z2/4C4FP8sZ3ymZD9ID4aSQAWoOgg+jM1H3d7ubeMViY0U7dSCMdkUerTPPH4
         S1hXN2/dQSHH3u35HerFDc5HB0v0b2YbrJ6frghP8wrseRKGHB79f1NyF6XtSNsY88Ik
         9kGrOMf32u8qZ23+4XIhv4nB78X8Al3IHi+/XYmpnpxq1Fr6clUv/trqroRCi1kpMReL
         Q1ww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W0DqXgU7;
       spf=pass (google.com: domain of 3vba8xwokcd09mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3vBa8XwoKCd09MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id r21si577912wra.4.2020.11.23.12.08.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:08:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vba8xwokcd09mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id v5so6288189wrr.0
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:08:29 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:dd8b:: with SMTP id
 u133mr558600wmg.107.1606162108611; Mon, 23 Nov 2020 12:08:28 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:28 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <e88d94eff94db883a65dca52e1736d80d28dd9bc.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 04/42] kasan: shadow declarations only for software modes
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
 header.i=@google.com header.s=20161025 header.b=W0DqXgU7;       spf=pass
 (google.com: domain of 3vba8xwokcd09mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3vBa8XwoKCd09MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Group shadow-related KASAN function declarations and only define them
for the two existing software modes.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I864be75a88b91b443c55e9c2042865e15703e164
---
 include/linux/kasan.h | 47 ++++++++++++++++++++++++++++---------------
 1 file changed, 31 insertions(+), 16 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 59538e795df4..26f2ab92e7ca 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -11,7 +11,6 @@ struct task_struct;
 
 #ifdef CONFIG_KASAN
 
-#include <linux/pgtable.h>
 #include <asm/kasan.h>
 
 /* kasan_data struct is used in KUnit tests for KASAN expected failures */
@@ -20,6 +19,20 @@ struct kunit_kasan_expectation {
 	bool report_found;
 };
 
+#endif
+
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
+
+#include <linux/pgtable.h>
+
+/* Software KASAN implementations use shadow memory. */
+
+#ifdef CONFIG_KASAN_SW_TAGS
+#define KASAN_SHADOW_INIT 0xFF
+#else
+#define KASAN_SHADOW_INIT 0
+#endif
+
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
 extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
 extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
@@ -35,6 +48,23 @@ static inline void *kasan_mem_to_shadow(const void *addr)
 		+ KASAN_SHADOW_OFFSET;
 }
 
+int kasan_add_zero_shadow(void *start, unsigned long size);
+void kasan_remove_zero_shadow(void *start, unsigned long size);
+
+#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+static inline int kasan_add_zero_shadow(void *start, unsigned long size)
+{
+	return 0;
+}
+static inline void kasan_remove_zero_shadow(void *start,
+					unsigned long size)
+{}
+
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+#ifdef CONFIG_KASAN
+
 /* Enable reporting bugs after kasan_disable_current() */
 extern void kasan_enable_current(void);
 
@@ -75,9 +105,6 @@ struct kasan_cache {
 	int free_meta_offset;
 };
 
-int kasan_add_zero_shadow(void *start, unsigned long size);
-void kasan_remove_zero_shadow(void *start, unsigned long size);
-
 size_t __ksize(const void *);
 static inline void kasan_unpoison_slab(const void *ptr)
 {
@@ -143,14 +170,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 	return false;
 }
 
-static inline int kasan_add_zero_shadow(void *start, unsigned long size)
-{
-	return 0;
-}
-static inline void kasan_remove_zero_shadow(void *start,
-					unsigned long size)
-{}
-
 static inline void kasan_unpoison_slab(const void *ptr) { }
 static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
@@ -158,8 +177,6 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
 #ifdef CONFIG_KASAN_GENERIC
 
-#define KASAN_SHADOW_INIT 0
-
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
@@ -174,8 +191,6 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #ifdef CONFIG_KASAN_SW_TAGS
 
-#define KASAN_SHADOW_INIT 0xFF
-
 void kasan_init_tags(void);
 
 void *kasan_reset_tag(const void *addr);
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e88d94eff94db883a65dca52e1736d80d28dd9bc.1606161801.git.andreyknvl%40google.com.
