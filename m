Return-Path: <kasan-dev+bncBDX4HWEMTEBRB74ASP6AKGQEXSMTGUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7602828C304
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:51 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id j15sf2149818wrd.16
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535551; cv=pass;
        d=google.com; s=arc-20160816;
        b=rJYAoySHGFkChUNggT+4mkG2S9jz7Cl+iU3tB6zy5Tz+OkfLRObJG9gDwKO/FFQO62
         L/2YMdeprWX8jFxbOAZUwkzOFggDguWU9DKEtC6Ye1rH7gMW1t3hAlzzChsMhtA0Gcsv
         u+nQxYvL8dBOUpRc+ij4T/zd8PaawtbKDa//kBhYAdHcnc/oH3cWNzDTE+iii21iTayo
         GPgqWykxHmLj6PFCBi+OPn3BqDhhA/9u0YfCNqz8w2hwYpo6l0N7edKY5dFpdB8jQeIC
         i5XCmaqy9WNEFcbwrsulwb0oygLUfqQBdLU0wL00gts83kiCFOE25Cn4oO/PZjG18c8E
         6sOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=cQCRYrcWyNP/AU0uLtcbr+ry19W9WF8toSyQsEgrfi8=;
        b=GAwgeYYw9wf41BiWf7LhbWi6D/DJY2xHz9S5veHU34tkit0uoy8tjAE3AiuiLnaFpF
         2V8lWGAL+r/EfpnkPbMgz674fVjEUuf54kTuP7gj2vz6v2glRXbhtjEbK0+kG489rjlh
         6c502qH/gfYJsIT2PnnKTsUq57mRYUFC1hw71S8I0yUeEi5X2XdwqVFQvQhC+NYOjfCJ
         kuI1DPRRUpo+O30mzMl/QADMJ0AadwzFq0PXAg3SBb8vq6z4nEsxxMHX6i7sg7ZXJTkv
         zTla2uFIoheUCWjywa46vZsOpRn1rd2vcrqgU2M2M+3easDdSCv+MD5qCbuMF/wtdfai
         TIew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kj1FTs8t;
       spf=pass (google.com: domain of 3fscexwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3fsCEXwoKCRUv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cQCRYrcWyNP/AU0uLtcbr+ry19W9WF8toSyQsEgrfi8=;
        b=nqJfFMbnEKr0y7tT2cleQf0OYOTZVOceu+AlfJui4s1C2cIQIB8TP4upNvclLTfvwm
         gGMRHA/si/x7BgUKpa4LWFG2ZmMahTlvieVT8YjVCrp+oob8/xMRGIL9BNnkYGgkvNl/
         FlPiy+Pj0vbC9Ktvr/jd3/I/7WZ59rz+zYmt2e7y5/cb8VuQ/IZQmudmCWAIrIrYzvDN
         Q7VcFurDt/pkChd/O1Imr4FSTZw7KP2+CFzE+BvsLToy3g0G/wXePjPjZGO8MUAGStjV
         RnzSOZyBSyfKK+4YbLpvaeqWWgX1zga45WnMl//1fR8JaNPXyzqePluEN9Q51kUPH7Fq
         dSdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cQCRYrcWyNP/AU0uLtcbr+ry19W9WF8toSyQsEgrfi8=;
        b=kP7zrvxVeb5W/6zRmhDD0xg10bu0ABLn2wt82NQYqc0UhN6+qxdNBY07c95NjxUBi1
         SlzB8DRYEHFq2Dx12e2VOTpieYlj82aoKqvXN8QTrQ//M/EGCbrLRZiEZSVjGqC+dR8a
         Z9z6cQzkkp57aJ2I34+ks93YIeIaNV5+qeN9LjddpgOVCS+fQ2XCQSX1TG6OJuoaGjPq
         WwszAgZQAxrCJO9/WMkAFkk1DEMkvoZx71//ht7iiOd2g//OoGjSc6SIF248+7I2KUKw
         vxq4HX1M/d+tuZ9iAxNH3EQqUisJBYopWYIjcmJ0cu4ZOEQXhP1no1Kl7i//ry7dQTbj
         dvyQ==
X-Gm-Message-State: AOAM533i1qih1W967Sj76SZk29jWAVTVpAZXDk9Q578ijMdvhv6O8QPJ
	BnPVyQnBZXekeqeNUTI2Y1k=
X-Google-Smtp-Source: ABdhPJxHPfQCaL0e0Xw5XWyX5nF7FrhwfFL09rYdvwFc9epamauqCINkylHYNbJwxjqn8aqAPmcG3A==
X-Received: by 2002:adf:c3c2:: with SMTP id d2mr32833701wrg.191.1602535551238;
        Mon, 12 Oct 2020 13:45:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2506:: with SMTP id l6ls5488709wml.3.canary-gmail; Mon,
 12 Oct 2020 13:45:50 -0700 (PDT)
X-Received: by 2002:a05:600c:210f:: with SMTP id u15mr13018997wml.53.1602535550402;
        Mon, 12 Oct 2020 13:45:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535550; cv=none;
        d=google.com; s=arc-20160816;
        b=G0Uvtxm3iH05wQTipQMVMBx8H48OTnwEfbbKPuI0WXjMTtdSKmDdwGlWzXeQbfR9Fg
         NZ+6uGJWju+9JcKew+jzCCtsj3VgmKfFTnykzLXJ8w4GilmUIihX306PjiUoAgT6ybBW
         K0XVfPiNgDqzRME24BnuIYmWbFoiWlf3l29X4VDrNNGln4inOiaKXODH3MTFfe2XPyte
         CFlpxmS2KRiUvssRujscyhUtEullEHxRX5mDwkOb7iyAeP2FSyN7q+g00GunppVIBLL7
         gCStsr87zSLrZ+VQWwB56HycF2RScNGg3VFT+bW0EOrszPzfTsBV5BhuQaCzlcMJnc8C
         kDDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=zuIa+KZerDCWvd36FwPuL/g3MG3w4jWBk5rucKd4CV4=;
        b=wBpbu4Dg/onaIZ9FG3snUgrCbbkJLIJ9XnH+xsDQ+SRwuPW+Tg4fgTtIvTH31X7mCd
         RSQ6y2mHizNitB489VOV5n98f3DP4QlbcpS4oJ8e8HDGcXyTWJM8z048hB0vWAEtLLyJ
         2bw7oL37R/3N5YTrtIHy8C5qP/6OY2vkkyypZMhNH2xfRUE4pXFYGKsNGAxRAAqxDuij
         XO5Ou+N+J2o+8Mg3cPYV8q4CSyhSqzitYhy5UMtNI2JlffLtuQb/NnG99tHO1GcPmVIO
         qOVxt45WPFzf1B4D+gDOFqptLS+GDEiXXhIP544SGP/aQu7wUN/Gfpwl5reuOb0moRhX
         1eYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kj1FTs8t;
       spf=pass (google.com: domain of 3fscexwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3fsCEXwoKCRUv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id n19si372694wmk.1.2020.10.12.13.45.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fscexwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id t4so1258362edv.7
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:50 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a50:950e:: with SMTP id
 u14mr16039841eda.260.1602535550027; Mon, 12 Oct 2020 13:45:50 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:30 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <2964fa49118c6f67467afb0fd2391a3f4d7d7389.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 24/40] kasan, arm64: only use kasan_depth for software modes
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
 header.i=@google.com header.s=20161025 header.b=Kj1FTs8t;       spf=pass
 (google.com: domain of 3fscexwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3fsCEXwoKCRUv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2964fa49118c6f67467afb0fd2391a3f4d7d7389.1602535397.git.andreyknvl%40google.com.
