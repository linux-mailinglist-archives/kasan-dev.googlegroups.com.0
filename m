Return-Path: <kasan-dev+bncBDX4HWEMTEBRBR64QD6QKGQECBNS3JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 871CF2A2F0E
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:28 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id h6sf14766472ybk.4
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333127; cv=pass;
        d=google.com; s=arc-20160816;
        b=rng0LeayozvboA+qXrHn44FcrKV/o9IUrbehgM6fA39GwMCdBY0+Aysi7connDtXjK
         3ZeBDguzndJALma7dnX9NLwCwM93s6AOVZaUSk6gCq7SYPotrC7uTH0i7VUQTKIhPI8Q
         33JbRn2kB+mtp6dZSeJ9WucteDGnx1v2WQAGfL7HXldpsOMG1Taxc1NWCeJayb8B8+k5
         F00Qvk64QirSvphiexxEHGr9cyJ1PTpkH6L4qP4YbdowGtzoO1u0ZWotTPHKI10944go
         WWgUDJIy6ynTvzfOz/VkZqIP7UsK6+EubNZ0JUBDmYtRreC9Q3oPIWxw9O9xMWhX3x/+
         B48Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=6+n3Ib2E41SSBOCNVZBD3fFhi/y70lDJu3DLmI2b3rY=;
        b=Urd4hlXF3dwhxWDBFi6rd5+9tY6vo81jyyIpXYaxC6rXGyM6kvRvK94ASaVCdxs9qx
         vX/2QpmLfIOjbdrBCHjyMnOFrQ9YbWXiIcfBXUYTFUvwna+YC07il4Dy4WApsvj+k+JE
         VXA3U+aGiwalWaFC185Ac4pOWW+0LXhTIMcIMbQ19vaLSflFekqv5DLIU5GBB9KFlQB5
         vrTiZlLBgGZ87Dkd5k4q91RXEyvTzjqJT5hP9uRiwpxSBgaeYuI6FPlo9ak0HIU59oeT
         pF+qP/zyFYMyDA/kiixDN66RJbyM9wo5wN6auEsx8eeEBusxApow1+cdKTWo4jX7HDei
         fgGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hNaPwQG3;
       spf=pass (google.com: domain of 3ri6gxwokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3Ri6gXwoKCScDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6+n3Ib2E41SSBOCNVZBD3fFhi/y70lDJu3DLmI2b3rY=;
        b=aSSaRLMeVQ/sXiRUvVlEe6e/L9ouI8s0KkBHch/lXuh9zXeS2Dx20yWf373Dzsmcna
         BPPKSCP+gUbioJvKdUhpftEQljeaWMq4MzCdLJQGYxYkuuTgJy0dqP1iLx53bopDko49
         heqxHVLKDNSB3/N1QWARmhdVe1RTb+K3j0kTFCKKLACrTwZENMAGgnf5xcn2r58eKwxd
         pym48/i6iZZzgtN7JaHVjE2Wm2rKz6c7eGsY31M6TJ/xouCxWp8gjvZz8rLqW6mFuZ2Q
         OvCwvKdivnQAA2HwDzatRgU1FMnCzAflidCa0e2FUTywPvY3xdkc83vdxGZ8o1yNmQKK
         ADSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6+n3Ib2E41SSBOCNVZBD3fFhi/y70lDJu3DLmI2b3rY=;
        b=CBarl+jUGuiTfZbV6qZxLfIUSBmHt9wWsrMqBbjHXtYLQeVY/waBqK/1W0ChHhixwH
         k2HjP1LomcoWTx71fIHx3pl1fEsYPQVfzeHty01Em64zSfm+W44weU/42seJbcopQovo
         bLLsy5VuMlHnw2w7xw+xisbmoUKxGDSbIkCQdVz5wrT53xw8PITZ6yM2JQeiLDyXgXyi
         35l5JlvqF1ib5iJ8c2Rh6u0bgGgd7oIgYeGQVGSgbPfR9xd1/HnS8Ffq5x7y6ObwljHo
         ybrvi3+3TXNcttQ80jt/mbS1kk9D+XVAKEOxgxrlyMP+0xoWxudC0UgaTTRbiYM4A8Qa
         TT9w==
X-Gm-Message-State: AOAM532smpAK/BElSMRV6L0MV1lsBguzbnVFqLYUlNz9g11WffeUZdRP
	e1zZUpK1fWImOYknoJLU77M=
X-Google-Smtp-Source: ABdhPJytM0VNn4X4RruT8IO05gBgfcbr/KcC8CrUW+OeMZFmxuw41rOUeDnAv1Vxyg4/26DzHBRpWw==
X-Received: by 2002:a25:b792:: with SMTP id n18mr23526426ybh.93.1604333127594;
        Mon, 02 Nov 2020 08:05:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3f81:: with SMTP id m123ls6910504yba.1.gmail; Mon, 02
 Nov 2020 08:05:27 -0800 (PST)
X-Received: by 2002:a25:7b86:: with SMTP id w128mr22153729ybc.192.1604333127054;
        Mon, 02 Nov 2020 08:05:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333127; cv=none;
        d=google.com; s=arc-20160816;
        b=LQGq9Vx6CghWWdzSuAJ+1ggDICXV+yRbi49ZB7wpN2t/+/R+6ZookI8gOOpSpT8x7U
         jSWxQIViL0LL0LbgGPy9Bip3tdcNvmr4qMdCT4IHrHjv5aeMvMw7JLoLe/wWMvwviFhX
         YGmdL3puyoDiqx9rvBRg9wR3xpmf/jXJ05ZyUDmfz5xH735OptagKVXN6On2lqkxhVuS
         iwiG6uldFoFLNX6IFuk2owc21N5LuMNXzfxJz7uSEAhwRVeh2h71Bdm1XTYmCfyYSDRJ
         BmY46M1Ltk3pqazDrwBopcgGyEE7ydCyeRZMIch1xc7tyl4fazfRhxrOPDvy2fLhkWYf
         CtzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=tnERJLSQMkNYv5nCg28tzBY5cjIpAsRRs2aOHq8rTuk=;
        b=jxOMW1AAwJR2opkIyE/vorXEwlQ4HAniP26ct+VmL02ksK3+9Btj2WJmAhZyet+/KX
         mxF0rnC3FDdSyeZJT2hggc804FZDpRUyghqH7e8FV5IydSCj2UDp/TZLXMU2Bx8SDK/V
         ynJMRWQ3tLGoVl7PNp8lrV+NSkeoPGpQOck5nRMzischlOGXgINW/n1MaPNd0a0Xhkva
         ZpPZMAmw1WsE0OkSFonTnnXpdOXTlRZZiEm6gFMLnSCmmWdCT3hOmjrO5iYATWKR2d2n
         yvNiVvMiI2mwcC2BQVly3HEgNMl/LUDuJ9LvYxFCFATPhdJXUH55jyqJ1VT65TMpYyzC
         tlkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hNaPwQG3;
       spf=pass (google.com: domain of 3ri6gxwokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3Ri6gXwoKCScDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id e184si719444ybe.0.2020.11.02.08.05.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:27 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ri6gxwokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id k188so8993368qke.3
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:27 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:1192:: with SMTP id
 t18mr23029504qvv.49.1604333126656; Mon, 02 Nov 2020 08:05:26 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:05 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <778b0bd612b08a46d7be76801069751fb67dfe08.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 25/41] kasan, arm64: only use kasan_depth for software modes
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
 header.i=@google.com header.s=20161025 header.b=hNaPwQG3;       spf=pass
 (google.com: domain of 3ri6gxwokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3Ri6gXwoKCScDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
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
index ffeb80d5aa8d..5172799f831f 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -273,17 +273,22 @@ static void __init kasan_init_shadow(void)
 	cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
 }
 
+static void __init kasan_init_depth(void)
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
index bfb21d5fd279..8d3d3c21340d 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -49,6 +49,12 @@ static inline void *kasan_mem_to_shadow(const void *addr)
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
@@ -59,16 +65,13 @@ static inline void kasan_remove_zero_shadow(void *start,
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
@@ -119,9 +122,6 @@ static inline void kasan_unpoison_memory(const void *address, size_t size) {}
 
 static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
-static inline void kasan_enable_current(void) {}
-static inline void kasan_disable_current(void) {}
-
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
 
diff --git a/include/linux/sched.h b/include/linux/sched.h
index 063cd120b459..81b09bd31186 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1197,7 +1197,7 @@ struct task_struct {
 	u64				timer_slack_ns;
 	u64				default_timer_slack_ns;
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	unsigned int			kasan_depth;
 #endif
 
diff --git a/init/init_task.c b/init/init_task.c
index a56f0abb63e9..39703b4ef1f1 100644
--- a/init/init_task.c
+++ b/init/init_task.c
@@ -176,7 +176,7 @@ struct task_struct init_task
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
index b18d193f7f58..af9138ea54ad 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -292,8 +292,10 @@ static void print_shadow_for_address(const void *addr)
 
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/778b0bd612b08a46d7be76801069751fb67dfe08.1604333009.git.andreyknvl%40google.com.
