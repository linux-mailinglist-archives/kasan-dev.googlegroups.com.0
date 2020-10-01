Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGOE3H5QKGQEDEOW3KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AE71280B01
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:24 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id n25sf175369edr.13
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593884; cv=pass;
        d=google.com; s=arc-20160816;
        b=HA3y8T4MTuoxWeH226UacEHABnorMmfYFMecpy8em7zPN9BpqPvggn2U81PhoO07g5
         Uwk46qDoWvSgvCsqiQeZ/NnjO8KPxFubGbj5DswKG9W6r2EwuIry7D9r5soiYGd9e9WJ
         KggcPygSyet6UO1A9xp/EHIZDLpG2ozJUUjL85wYDV60eRU8tNYElPxWy4RX9ime+KWC
         /4cMwKz9HG9Yl22qouzXjwtPNLzJu29JpD+6jyicKTNU8anDjbeGLKeqYmXUY8Gfc4l9
         DZv6fQLTJUYuo8xRvhj/YGEov3eV0f3RRsAHRqMEHpRN4u1JWQLZKWR/WZkgUdlm0C0T
         hM0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=70bUuqubZB/qeIde4w3OWl0Vc/TPLNWUhc1gHr7XSjE=;
        b=POJjpZ3dREyU9e593HbXlpK2db+jm3HGoYcABrlCzy9R+Ai1mNgyHzJZ0uTvbTFwAt
         xzx/UhCXuZSFaARUD1gmkC9Z0w+RMMYXqUHCo75P5AIQoEAWeJ/dCq4oQhF3Q8K8Q0EL
         AoxS3jvXtLcrY5+lmqbh6Owj0khAO3zhaI+SnhcZDhTYSm8duykHjBP+3+sB4PfI1XWE
         Oqt7GVXzC23hBIpAz/H8xitwntePgHSCzLecXihBQTDhzGK+lMXbu4sO70a0iPgInhbI
         QInsFbU4rlQcO6UpdfT0j2vIrKev4We0dZVRbnJYfMi0Mk+eSPb5iI2xQHeePSAbAtLz
         oYnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=roiIrwI2;
       spf=pass (google.com: domain of 3ggj2xwokcbcxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3GGJ2XwoKCbcXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=70bUuqubZB/qeIde4w3OWl0Vc/TPLNWUhc1gHr7XSjE=;
        b=EaTrmKsfcW2SaoMS3nkipjF3XmFeCndWu+iIDkn61BqYFTPrTsPqHdz5Xvm3IeQDyn
         esqO/haZN65X+JGdRX/SaZ/PQ1G6ogxQlynyQwSBCmdEfGbTXWDKr1NQhzsSeQqmCmU0
         L7XQT+yImNK2d9rqT81lyEeFQo98opOH9/8D7VnV7BFr5T4RWtFzO0Mts37SNMWqe7BD
         2u43GtOpP39nV848Emrm4iDjEk//7QnVIFbahcKkEm9BSjWnnesXNC72UT7XEDswGk+9
         eGiK+9xL/u+4koGtbfBYOf3c8wbmYo2Lnwv6j09mHth//8XPiX4BOMJGfH2X1qnRUr8R
         BQPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=70bUuqubZB/qeIde4w3OWl0Vc/TPLNWUhc1gHr7XSjE=;
        b=LHHlWVGsLim49tZQ+yLvV3N5zjz4xQFAb3d8MOgEVyWuPl9FZwwqziMFxv9KIW+8jX
         Pe0KIN2LE6hI03BJHIHkLnucK9785OyOVl7ST+PDUSd15793HrBtEk+nchKTyLzvQwzn
         9/S1jbWa9njQhma+BpmXiRgvYk4RNtYrKN3XEu2vcOpViQHIZs4tXvRSoPZbgmL3Xmb3
         tIGfZwTsBkO+7QbvONeuNC57st3rVTmV8F101+3ur/FAokkGbUFBNeb/GyVfmz/KWZ3l
         SB1cqBrMH9SIiYPKO+BWDZpYsIwBwfm9XBD4HztldgBfIt9J4fh8yK/JHK0it69qBIoa
         Vhcg==
X-Gm-Message-State: AOAM533hXVWnQNvBGdkcgKYKnBUxzHYja9ejQg12WUH6f7Wjl7yrd9G5
	TZNV5p4pDUuUSqIKrrqsXVA=
X-Google-Smtp-Source: ABdhPJwgYEbzcgS3Zt7sg4BYP11gaho/bMx947hGzTg4ks4B/yqefibHi16hKGunadNZG4G6f4LjlA==
X-Received: by 2002:a05:6402:1656:: with SMTP id s22mr11183716edx.160.1601593882163;
        Thu, 01 Oct 2020 16:11:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c545:: with SMTP id s5ls3074077edr.3.gmail; Thu, 01 Oct
 2020 16:11:21 -0700 (PDT)
X-Received: by 2002:a05:6402:142a:: with SMTP id c10mr5067864edx.261.1601593881268;
        Thu, 01 Oct 2020 16:11:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593881; cv=none;
        d=google.com; s=arc-20160816;
        b=oO2Z4UrpRODd19aJcWSN+QlecRFTcGS6Rtvf1WiTYDTI+XZTBhwswXdB1vQWMf7iFG
         8i99r/4Z5Vec2TkNG+ZrzspqjHS3pSLVIp2MHgEZgqiRZL38hKumVLKKO6yrhqDlH1Oo
         OVMI4L8bnB6j+9CK3t84BGAXkOeDUhj1eJVZYPOeZNt4HJAwFGsY1qUatrSTqX6MAMGa
         ju5ocV5lraOaSYT1UIU8nIzCcvJ8rhm+Qo0uQHoOKPZIph4zT/dNB/UjZGna60ktn9go
         RH2uQ9aDE9Qw/RrxcwXDKsflsojJf/W8prOOqWeSNJLORB+MuU3dXP5tPUKh+e2zE/h6
         yoog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=92IUkL/SNCDmD7qK6l96e97eKQ8ygsmQO8JGCSzDuVY=;
        b=Np+Z+1gHNfwEHbhucX1rllvjI/IRrpsqvwO+Irrt896P1NaoOV7ShE/2sjplGmRaLb
         dICNdKXBk1mFAfTNjPQU9xhW73Nq+zIJqvdZAuHa5x1TwhL9lur2NrGlqiSIzzc2io1b
         W/2uD5AVvqpFhl7kXD5nZom4bH5rwsiXjdGwbX2oRI+ayBbM6zMsDdF01Eig+9273Zlv
         lRCs1LeuPV/q8t/EAIyj+BBMae/w/bgwIkU9N4yAv6mG9faaj4XQynMEkTI0vNXoYsvy
         8vVQMWUmQIWNT2tZ3TsVY0s6tQGkpcnhM65RaEWtp+0qc4fgYc7Nh1FIohcIlJwrDlR/
         PvqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=roiIrwI2;
       spf=pass (google.com: domain of 3ggj2xwokcbcxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3GGJ2XwoKCbcXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id a16si299033ejk.1.2020.10.01.16.11.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ggj2xwokcbcxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id m88so187853ede.0
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:21 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:aa7:cb8f:: with SMTP id
 r15mr11051920edt.356.1601593880984; Thu, 01 Oct 2020 16:11:20 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:16 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <6998b1dc79eb19f6d95dee449319865bf396199d.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 15/39] kasan, arm64: only use kasan_depth for software modes
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
 header.i=@google.com header.s=20161025 header.b=roiIrwI2;       spf=pass
 (google.com: domain of 3ggj2xwokcbcxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3GGJ2XwoKCbcXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
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
index c07175e6ad76..2dadaf2be6d2 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -43,6 +43,12 @@ static inline void *kasan_mem_to_shadow(const void *addr)
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
@@ -53,16 +59,13 @@ static inline void kasan_remove_zero_shadow(void *start,
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
@@ -113,9 +116,6 @@ static inline void kasan_unpoison_memory(const void *address, size_t size) {}
 
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
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6998b1dc79eb19f6d95dee449319865bf396199d.1601593784.git.andreyknvl%40google.com.
