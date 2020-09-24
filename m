Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4GFWT5QKGQE7DXNVYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 38864277BD3
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:29 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id e9sf336381oos.3
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987888; cv=pass;
        d=google.com; s=arc-20160816;
        b=JT1n1Q+49He3OQEBq7W6KOlQJtef4PlqM1v0WhRD5/RM19Y2o3MX76hGkSwFUlq4Cu
         aWJNEO9vI327eC8glY6SHNmqARfHHF2eQI2ytAA1k8g8Jg2Mwo5FtiOFbjL/74uU+gZQ
         J9gDiMXlp4pliuuy5mVejaWWRcA0BMKI/GsbbeKntgXqkfThRJqZU3wJJS3ZstvDGc1A
         vRxvmZZQPITWsBbNa0HGkuCg9hKCqzXODjR5TMWt+IdZFEnZfFVOlyhUeGGe7k+rvPAl
         D3z141gVM+p70epHXw+dSq4YsVQNHzo5QHz5B92wQ51GcUFY2l12PPi2u1fmBQ8TjNv3
         RiKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=gnU5Bo0Maid5sSyQaZOVeMrqPCreiNHIvy1LbrYoQ60=;
        b=HpGe48fz+ey54hZxliWlRl6alrgCogoH1RSTSgY6UiB6gJsyq0mzmXLSlXPVpwSwsU
         AqoqStkTmzQEcKNPFCqtQJ8aCSGr50MC6SwmqlxaHN4poagPLXYTXWfNH9JXOnOIQ8Qx
         SUX90kVKll6bTstUoeqbEBmbmPhXcLD8JRrrFgULNAQ4Xfl3GbYnHojb1kVnej/3UcoX
         nVHU03Eh+jlPlOkdBdbanYBWXImhV07jAULniBhfIo7YB8hPlwdP+9YpUMUh46WQlCf+
         5+KwJwSnFX3sB0hMDQEZYWyNDqlWJRbB5JRNEQ3ldyEgy904FEecVJp1h+l51wU6Rav+
         m6VA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qMHMZkbS;
       spf=pass (google.com: domain of 37yjtxwokceomzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=37yJtXwoKCeoMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gnU5Bo0Maid5sSyQaZOVeMrqPCreiNHIvy1LbrYoQ60=;
        b=nwZGJYCsLl9ljNAvuLSaM5VdMtPU1PyN5cGrc2R/F3skz5qWB+TUzyPviOvG0IYVkH
         xvWxP7t6Qf/asHmC1c/irar4wTgFEpDPV6CAvGoan6G25L7mMEb9/ST5HXtZuxtLdnRt
         KTlN2ZZ8+AUHo3epUpYiOuy5q8RMEacbT3YEoSHCQwAZ3SxVtfb2oZDntiKem3ehIx5a
         ph5yqSeuWvYP+ai1pLuGJ2GrSuhRnd7hbokcZmaMSL3sGUeJMdp2HvDi8HSf3upQqnLV
         FaHM7zMDxMlWLWYwzcCNPn+dVFnLJ+sa1HYXQo4GrNeL/1ePz9K1zwKWoHbblEmd8Mnf
         DYPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gnU5Bo0Maid5sSyQaZOVeMrqPCreiNHIvy1LbrYoQ60=;
        b=RSBHhjNV6sBamdAiiTTWzYWyKX4w3YG81KTk4Of5v7yDWSxKspCJDvhK/MiyjL93Cj
         PzS2GnNvGI2O559YJsLiifUNiV2XNoMKI8SZqCzLgJXpcf4zsFuyzIRWrEVkdy2CSXAH
         dVu4KRKNv+p9eKnqzi0sQfLlff3jbCn6FT2Vi6YPDAlK7gng/G+LaxwZR/furWkp+bDh
         MCyojyZGH7IQtOAYqkhx28Jpm3Pc83ePsms0Z8kosyg5nlBfEtBLN/sw4toY76XZZBIu
         up0XRLFQ8xIvpaPhqgibVFBI/dCcpxwu8yMppTQurUKPxN5eDyXeOglT5MrgMDAcnl58
         7Tdg==
X-Gm-Message-State: AOAM530KxXPoZeOlcH9htuPsnjBuHmiYQ/9Y3GUPGNzN7hlCVkc70vmB
	3qRBf6tAUubRTu8X4WUPhqM=
X-Google-Smtp-Source: ABdhPJzBVX/zjhxS9xF2NKqtKsQqnQ5xQpdzmQjENggrthj0jFd3AYypnsumpGWUJTxxijA2xFSbDg==
X-Received: by 2002:a9d:2942:: with SMTP id d60mr946321otb.20.1600987888180;
        Thu, 24 Sep 2020 15:51:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:8c48:: with SMTP id v8ls34565ooj.7.gmail; Thu, 24 Sep
 2020 15:51:27 -0700 (PDT)
X-Received: by 2002:a4a:1dc3:: with SMTP id 186mr1039677oog.88.1600987887797;
        Thu, 24 Sep 2020 15:51:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987887; cv=none;
        d=google.com; s=arc-20160816;
        b=PBOeElMTRp4M2jA/Wdq24Km0W4112OPuUxXGOIoUR/z9hMQteV3R8mOXeeZYkzYhHG
         o4zn8EEwTpUoba4lY8OMBtYbHdyOjmYf8UguwU3MJH8GREL+YrcTHlGGg2TxBHHfPVv8
         YNQuWV0jEj6SJyz9FSnt9/ABcBxEOUDtFW/TEjs53tq4KElWaHwL80corgGFtpQRBj3W
         mmzSQIIopTuc9xG/KvlMkFqFDQGTpAEN2lG6sgc0C1Q/0h3ZcyN4IGi07zaujqTCwjIj
         EjkI4nvDuT7DY927F4lF/+YtleHIXpyv5gTlHlsg7D/AVvGH9/MCrW7fk97w6n5q3eqU
         Fn7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ZYBZQ28rYl/uYPDoQ+ete7cs1v1ZYV++yqEN/4Z93+s=;
        b=Haipao5Whm4SwuD1yIFbrBSOWPWEzbuQhz7rNtTgTZhclnB17Atf0stS5WPRZqSqA5
         Utq1bQZTRradYcfegUqNuPIk/9SNMZBx4ipfBhej8e0UV0Hl3DNLFw+jZUZLQ7PIvi8j
         enQCR2NsHaz/cgin/zg+2tw4GwCjQ17F/jSVhAdSyKjB7piyGGGkL1LPo8nGG1S9t4fc
         gpyFJJOABsIxh1JHgMPRQDRywdTlUdaYPbcsvCyl8mOqQxgd4Ka1v8det161fX0FdPAT
         XPRkOJTreBnhFfzWMBQB5DQWnM5qSn4wvqgwGFMFDaC+FzY80tyqcRJZ/4Cs/Eu+YlTC
         HTyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qMHMZkbS;
       spf=pass (google.com: domain of 37yjtxwokceomzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=37yJtXwoKCeoMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id l15si153011otb.0.2020.09.24.15.51.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37yjtxwokceomzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id t56so490219qtt.19
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:27 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:cb11:: with SMTP id
 o17mr1470066qvk.44.1600987887139; Thu, 24 Sep 2020 15:51:27 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:22 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <3f395efd4f415a41ea72f18e181c0bf551a21094.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 15/39] kasan, arm64: only use kasan_depth for software modes
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
 header.i=@google.com header.s=20161025 header.b=qMHMZkbS;       spf=pass
 (google.com: domain of 37yjtxwokceomzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=37yJtXwoKCeoMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN won't use kasan_depth. Only define and use it
when one of the software KASAN modes are enabled.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I6109ea96c8df41ef6d75ad71bf22c1c8fa234a9a
---
 arch/arm64/mm/kasan_init.c | 11 ++++++++---
 include/linux/kasan.h      | 18 +++++++++---------
 include/linux/sched.h      |  2 +-
 init/init_task.c           |  2 +-
 mm/kasan/common.c          |  2 ++
 mm/kasan/report.c          |  2 ++
 6 files changed, 23 insertions(+), 14 deletions(-)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index 4d35eaf3ec97..b6b9d55bb72e 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -273,17 +273,22 @@ static void __init kasan_init_shadow(void)
 	cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
 }
 
+void __init kasan_init_depth(void)
+{
+	init_task.kasan_depth = 0;
+}
+
 #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) */
 
 static inline void __init kasan_init_shadow(void) { }
 
+static inline void __init kasan_init_depth(void) { }
+
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 void __init kasan_init(void)
 {
 	kasan_init_shadow();
-
-	/* At this point kasan is fully initialized. Enable error messages */
-	init_task.kasan_depth = 0;
+	kasan_init_depth();
 	pr_info("KernelAddressSanitizer initialized\n");
 }
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 18617d5c4cd7..4ca1b9970201 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -40,6 +40,12 @@ static inline void *kasan_mem_to_shadow(const void *addr)
 int kasan_add_zero_shadow(void *start, unsigned long size);
 void kasan_remove_zero_shadow(void *start, unsigned long size);
 
+/* Enable reporting bugs after kasan_disable_current() */
+extern void kasan_enable_current(void);
+
+/* Disable reporting bugs for current task */
+extern void kasan_disable_current(void);
+
 #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 static inline int kasan_add_zero_shadow(void *start, unsigned long size)
@@ -50,16 +56,13 @@ static inline void kasan_remove_zero_shadow(void *start,
 					unsigned long size)
 {}
 
+static inline void kasan_enable_current(void) {}
+static inline void kasan_disable_current(void) {}
+
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 #ifdef CONFIG_KASAN
 
-/* Enable reporting bugs after kasan_disable_current() */
-extern void kasan_enable_current(void);
-
-/* Disable reporting bugs for current task */
-extern void kasan_disable_current(void);
-
 void kasan_unpoison_memory(const void *address, size_t size);
 
 void kasan_unpoison_task_stack(struct task_struct *task);
@@ -110,9 +113,6 @@ static inline void kasan_unpoison_memory(const void *address, size_t size) {}
 
 static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
-static inline void kasan_enable_current(void) {}
-static inline void kasan_disable_current(void) {}
-
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
 
diff --git a/include/linux/sched.h b/include/linux/sched.h
index afe01e232935..db38b7ecf46d 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1192,7 +1192,7 @@ struct task_struct {
 	u64				timer_slack_ns;
 	u64				default_timer_slack_ns;
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	unsigned int			kasan_depth;
 #endif
 
diff --git a/init/init_task.c b/init/init_task.c
index f6889fce64af..b93078f1708b 100644
--- a/init/init_task.c
+++ b/init/init_task.c
@@ -173,7 +173,7 @@ struct task_struct init_task
 	.numa_group	= NULL,
 	.numa_faults	= NULL,
 #endif
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	.kasan_depth	= 1,
 #endif
 #ifdef CONFIG_KCSAN
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 543e6bf2168f..d0b3ff410b0c 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -46,6 +46,7 @@ void kasan_set_track(struct kasan_track *track, gfp_t flags)
 	track->stack = kasan_save_stack(flags);
 }
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 void kasan_enable_current(void)
 {
 	current->kasan_depth++;
@@ -55,6 +56,7 @@ void kasan_disable_current(void)
 {
 	current->kasan_depth--;
 }
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
 {
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index f28eec5acdf6..91b869673148 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -290,8 +290,10 @@ static void print_shadow_for_address(const void *addr)
 
 static bool report_enabled(void)
 {
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	if (current->kasan_depth)
 		return false;
+#endif
 	if (test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
 		return true;
 	return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3f395efd4f415a41ea72f18e181c0bf551a21094.1600987622.git.andreyknvl%40google.com.
