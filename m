Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEXORT6QKGQEVVB4BFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id EB8E32A7126
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:46 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id w1sf101746lfl.14
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531986; cv=pass;
        d=google.com; s=arc-20160816;
        b=eTpzzmUMqfNykYrztzjGkf64VjwJRy1D4HuLjCm2xe172wRbaF2DO9ToemEBkDW9yh
         qdNvSozJbjzyBfpYBNsF0eCvMnRSs3ou46HszH5fkWJU3EeYJ9hqFgAzMdfTQOEo7QAw
         I3HjLXheJ00SqQf40MA0zQN43p7NzWqm+srpeSRmZiaIfFxwmhjZbOvrpLYlOKBQklCP
         SyvVNYEfXyiPlCQKWgwa18sVUGaCzmBrZI0AaDMo6Murs/aGubkcfQlvyu6A0vgYI6jA
         EcGhn1haAXbEOKZPnSB7qFKALvQgS7Lnx2NFh2fB2Ufrqf76FgiXf95qsehZnk3yyx+P
         q6Sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=sBAV4x2MA5FwGCmtKYm2+8ERUxJK5LxWGtIlYQlMRTg=;
        b=kkWET3tB9XLp+DrlvDmaPAQ3Wl6QjKoZQ/qVKFUGb2s514012dVaQ3nMfJPx+KZzw5
         MjmkMskLucuhj1XWc9+c0oNVRiVCzPmkbnOOUFqmpzovuECzCUVnEcLIl+Tmdpag7PzK
         8oA88TOdCnCvDLAs7rRA6vrnblkWRQpYjkbxxLkvoYaNCIFRf/FPpEE+X8LG6Xdg4vWG
         EqcDSGu9Q2D3ZtVxkX5vpzktq3DqDHyeuFDlLuSMFs9lezjYBA1KenqvaLAep0FKntv8
         PgSL7ijd5u3xi/wrmh9D6O7YFfeQr8JcyDGLZaYSsICZqb4x6wZZIlKUgld8g6qe6QB6
         lRaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HyGuQZMp;
       spf=pass (google.com: domain of 3etejxwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3ETejXwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sBAV4x2MA5FwGCmtKYm2+8ERUxJK5LxWGtIlYQlMRTg=;
        b=MhB/xK/6pPLku6FmnMcnAFBKSeijRqr5Yk7TixMsEN4B+maekaL8+R+m+Bck9Keb5O
         D0FTFugGTcAwW2y8GnRn/Svh6SfhIxwc2V0yS4RpmR+9oToJGsj3olGGFByQfpKV3ogU
         mo1OZx7skwgxeM44tIzg7tUT6vIWCu4gk0g8PFkfjzENDWbXWLSQ+ehMHg7DnV8A1ncy
         QnID9/RvgtjN5M0DU5tgU+9u4YWkDENxkl50ESQQbF737nIWFnQj3SgQf+b4+aF1qgeV
         EyHKp+KJnlgdmikWhk/0mkz/qAmTg5vzAJNWe17DACksitE53IlqZIupnAcRFKLdMpQ9
         3W2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sBAV4x2MA5FwGCmtKYm2+8ERUxJK5LxWGtIlYQlMRTg=;
        b=WzFeYsLHt2Bg+rFOZVg5gh2RVsq0QxoJvw16S92/N5uCEVxV+sHFI705VnFys8FPar
         92gs+WXjsSegAdaJ71txVF5p4wGptdNkpa8wJQKm7g8OlzKbLSlXafOBYVyL885L6sBG
         nII4jXRR6Br/ElxvuEOJVUlizDx00sGnh2D2G47MTzAhkGbeCP4sc5wTRwov0tAv+o4c
         6bJvaS+PKpwoBkHx6O1U9f/e2VDjkoP7RiPX+Qgrx4oTPSD4aTxE0GQE9Wx7LdnlLoz1
         KcFOMK4eRQ/+LzCS1Y1KJFXnKgHVz24gdSx8d+CV4sRAaCOLppzf5OBvIAMM9LkBs0Mf
         uOMw==
X-Gm-Message-State: AOAM5320ho6EJH+4wMZw1XggLkC2R5bkgJ3jkF+tYeBHfGkaT9i3mtyO
	FSGgf3afFy6IlWWoXuu3AGY=
X-Google-Smtp-Source: ABdhPJweo1RWQUQQJpiArKOm/nmb5UGGojmw7BxjRhUQK/IcmVZNNl5y0pxVN/CjbA3iX+R95U+pVA==
X-Received: by 2002:a19:87c2:: with SMTP id j185mr24195lfd.570.1604531986513;
        Wed, 04 Nov 2020 15:19:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:480e:: with SMTP id v14ls644305lfa.2.gmail; Wed, 04 Nov
 2020 15:19:45 -0800 (PST)
X-Received: by 2002:a05:6512:41d:: with SMTP id u29mr12200lfk.517.1604531985489;
        Wed, 04 Nov 2020 15:19:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531985; cv=none;
        d=google.com; s=arc-20160816;
        b=dwNypkWT1pwx7lPHSnyucFvJ8i3s0ivIn3oDbipTJSJ3ufjWU3mUIuGYgisW3iBpQg
         HQISi3nWkwIzqWwNVKeLn5GqMR/Ob/L08N6kTUlX0tppsHZ/go0toG/JA4Qj4mWtb0Tz
         xsj23sI3QlGfxiLkmL901I/ogcKu+1Cx/OM/IJxxT49OyU6R51MkJvL4eufowL9chslO
         C3Ea0tAmmiml2A5DNteyxKk+AGGWFCDsPE8p7JUCirU3zl9n2ki2a8802IfjZ93DVxx4
         37ApWX6NhbQkKV1n7Bdhy5f5KCREl2CELdX3DIlx4X5COibQn8TzB7yoHMYedLqZcabP
         iQSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=tnERJLSQMkNYv5nCg28tzBY5cjIpAsRRs2aOHq8rTuk=;
        b=rQOoTSoX3MgvJRySDVnz3H31wpCTYYZqR+WHW1qt6t+WIEqrIhCotv6f509ge8Yu23
         onMqlnxlkRthLro4WmmbMRCLXeWm/W+gTaypA0BonWSZ+T3MbaotdMq5Kv3k141gy+NN
         WO6SZwsDS4vNGONYKgUrgNwzIrt3HnKKOfflY9hOh4lAHEHud4uHgDcs5g0YGTeEj29M
         IgLHY0SYdVQ4o9vrINRS17b+yndzlskYENawV7BDsF/pUBys6l3p7ci2AHg3M4mksHEn
         WW2ZsW3S4FODwgfjgeQTT7qfrAIk7/EjX02S3aJETo6YadSwg48V6eVwBdEH9Sg8+umE
         w8AA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HyGuQZMp;
       spf=pass (google.com: domain of 3etejxwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3ETejXwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id a1si130822lff.2.2020.11.04.15.19.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3etejxwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id 27so70780ejy.8
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:45 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:3acd:: with SMTP id
 z13mr472324ejd.118.1604531985052; Wed, 04 Nov 2020 15:19:45 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:31 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <b55775c898f1dad5c5e03f29fb19cfb3a70d50c7.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 16/43] kasan, arm64: only use kasan_depth for software modes
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
 header.i=@google.com header.s=20161025 header.b=HyGuQZMp;       spf=pass
 (google.com: domain of 3etejxwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3ETejXwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b55775c898f1dad5c5e03f29fb19cfb3a70d50c7.1604531793.git.andreyknvl%40google.com.
