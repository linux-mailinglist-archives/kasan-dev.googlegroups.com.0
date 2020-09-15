Return-Path: <kasan-dev+bncBDX4HWEMTEBRBR66QT5QKGQE4WMQJWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F88526AF57
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:16:56 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id o13sf1491100ljp.18
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:16:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204616; cv=pass;
        d=google.com; s=arc-20160816;
        b=nBPf5ofGIi0GxvIiWd/+HXeeI+edsLDLLoI4Sz6Af/P2F4r++qf2Cs1K5z3Bcr+hBd
         WEMYXYObEVug9P0I8RjsXdv2X+GUPdeZn4AqyLlnYXXlUhzDQYR4pP/bQ7HLjpS4p3m4
         8m5dJwIAiFm1dct9WseuPiuQCK6w6CNwGoO62TvHt3J7xZjW62wVMqRPEluND/RjO1be
         JbehbSHDE2OJZ5riyswI8L/Qj7jfvUgzMuv5yMpYlEecGi6fd5yPLCs6gkvBZUVAfLHj
         8J9sNXeKyaF0dcRCmQLb+tUCTrr6sxT8/mT8vh/hc7hJDT1gKM4ktxXSmsasQjul6Y6D
         cObg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=pBL5thRlkYj8+sgp0NXSJRcZQr1R7941ctBd0Voj89Y=;
        b=JfNFVw6JsHGB9vsfWFwiAJQsEjgrUHdDahXZRHJ2bxegqQ5vQcudJGFBa+P4f2BkNx
         UMQjEIEX5mtqAXBjpfpraUaIMYDBePwBFuCSWiWx+IZBiTR7kcZBL8XVN3PkZ4KWIMmE
         TP7EEMhYH8QViHrgkpTOCbOrYi6jQDKMNOHIfe12peQP44bkP38gBYJzsRgKPm3zjH5C
         74lBTosA04kQZKSsl8gpBRfYhjRNcN3Vl2R5IYxZ77IsVkpaHBQK7BDk23Vo2s8iu1yQ
         tXLYyhyhO7hIFgt490aeVB7RGGZPPpz1F4QKX/YdjyzD6Sk4D0S428a8K4gOAar+0TEW
         i/jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cyy2ohm5;
       spf=pass (google.com: domain of 3ri9hxwokcsshukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Ri9hXwoKCSsHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pBL5thRlkYj8+sgp0NXSJRcZQr1R7941ctBd0Voj89Y=;
        b=poF+tK29NyIh09yBH0MlL7je7MDGVE2a4LSbWJACyjnieU+0cb1rO7sbVxyn/FNi/N
         sw/Dzu0ufo5c5+5O8xikAQi3YydiwPAehvEjvlhisan9FHIMkIiyuzPD1TsBmD4tbI9B
         wrshAaDNdVUQ2Z5uwmKyzoaP5sdmhV4/BVwBySq+CNHHIIRL8cd9+Ur5J9uH5Dujv2mJ
         qu2+RWhrwQLor+Ykd6r5DhzgK9JvqXkjiG8OKDSmFmbYwfwgsGHHNJPDCyoU/CLy0PjX
         wFwPF6j/bn/Em6hD8R5SjDdyFm9XICSeulHuhi0mM6LE++B9MZjEBD28LT5hwxTFgYYA
         pVvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pBL5thRlkYj8+sgp0NXSJRcZQr1R7941ctBd0Voj89Y=;
        b=WDpslxoJAbome/X1nv03GUhvLDEvdX/9Kgm4B4umPfH9J2mjB/oyKFlA+kXwyAUDNQ
         psg2b354+E5bepLcWZNkwDZQTX9JitHyHCnVQgTwtI7T4j90Qjtqhbr4NAuo/F+OikL7
         MinkJ2W7uut1zIPrgwBWrTM7jIgQVcYfw437DVB5xyJAxtexxaFkP08hzEbRo7N71TrQ
         Myusij2DbqTcaPCIFm/H46S4FMmjwlgUyTXVBl9vinBFYETPSTCdOXC05zhfnbFYtoN5
         9oL3y9GLuk2I66f17MVnps+JYgQSZyzQ9EvxhvILscEO0znubr48I343Xo447ldL5iCp
         MF9w==
X-Gm-Message-State: AOAM532od1iEFBWrmQoJNix+eZyJkoev73Sr1H7C1YHFFjbU1Kn1gTnt
	SET4t2k/CZVqylhFedL7Pzg=
X-Google-Smtp-Source: ABdhPJz5VP0VFvE/4H6AM1WTa4DUJeuy15BfT1/ZkjvWCoiz2NJV7+QNS9TZXUjtMptjs7h/Vasx+A==
X-Received: by 2002:ac2:418c:: with SMTP id z12mr6991888lfh.231.1600204616018;
        Tue, 15 Sep 2020 14:16:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b1c5:: with SMTP id e5ls60287lja.0.gmail; Tue, 15 Sep
 2020 14:16:55 -0700 (PDT)
X-Received: by 2002:a2e:8046:: with SMTP id p6mr6889586ljg.372.1600204614965;
        Tue, 15 Sep 2020 14:16:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204614; cv=none;
        d=google.com; s=arc-20160816;
        b=prjCqE8mXKo0LupONRv+sql5KAm0MIV1KBTkF0HL/d/zO3jZKWJahKP7wPZif9veM4
         KBu8p8qOR+QY/uW5YImKLzF2fR+ljsklRs2RpyWTmUT089NBaAHN75IZTSF5tAPhjAKD
         ummx+mTHjjbnUbXi/HE/kHmDN090oit0+yvXeNtpXbQLGnq1t9Gjns28hZrlw/WZBpj/
         hP2BIbdp+MS9RsSRpn1T/pbi55xDqGA1hdpWe+MZBTOVOCzltEw2deNVOCiaRjL5BlEG
         3vhL4jjv85mNywqLgjiyTluLfV2taUuKIg7cl+Ko8mUymL/l9F3YgLkCDmH71KSfA3n+
         /uPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=7yDwng4+Hj3dGnoK2YA+rQbDNoxu46t3AMw9ie+3lv0=;
        b=0IQOGFT79qgONLL6Sr7/tGIqs+cElehq9RucsindL8KwfzoNFa/pk3pK/YSiXT+unB
         2cLsYDtH1LeAkepiqmSqq2Ja+t8EtaCK+o/U2oCGUfHylbX4hPOp/ck7hC3rBwq2VtMu
         q0ciutOmKW9pJxydjP2OlvuNFg/uljan1DLNXkxVRDQPKHlYGWczbW23ougmrrHLDcZQ
         CQSQrn9XdkGq5/D/SP5Pakjom3bhdohsTUjGVEk4Mt1/npMkruji8VazK6EgsCUeqnve
         fsSk98T2+XqjRpW1DuX+00tADQ9oSF7Xk8jBXU6oYcM6h/4cJri58jXkuSZkY3n6BjhF
         Pyaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cyy2ohm5;
       spf=pass (google.com: domain of 3ri9hxwokcsshukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Ri9hXwoKCSsHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id p25si80532lji.8.2020.09.15.14.16.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:16:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ri9hxwokcsshukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id b7so1711748wrn.6
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:16:54 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:e108:: with SMTP id
 y8mr1249357wmg.178.1600204614417; Tue, 15 Sep 2020 14:16:54 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:15:55 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <b83ab742bda81114249ef81870a6f30023192cf3.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 13/37] kasan, arm64: only use kasan_depth for software modes
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
 header.i=@google.com header.s=20161025 header.b=cyy2ohm5;       spf=pass
 (google.com: domain of 3ri9hxwokcsshukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Ri9hXwoKCSsHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I6109ea96c8df41ef6d75ad71bf22c1c8fa234a9a
---
 arch/arm64/mm/kasan_init.c | 11 ++++++++---
 include/linux/kasan.h      | 14 ++++++++++----
 include/linux/sched.h      |  2 +-
 init/init_task.c           |  2 +-
 mm/kasan/common.c          |  2 ++
 mm/kasan/report.c          |  2 ++
 6 files changed, 24 insertions(+), 9 deletions(-)

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
index 18617d5c4cd7..894f4d9163ee 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -52,7 +52,7 @@ static inline void kasan_remove_zero_shadow(void *start,
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 /* Enable reporting bugs after kasan_disable_current() */
 extern void kasan_enable_current(void);
@@ -60,6 +60,15 @@ extern void kasan_enable_current(void);
 /* Disable reporting bugs for current task */
 extern void kasan_disable_current(void);
 
+#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+static inline void kasan_enable_current(void) {}
+static inline void kasan_disable_current(void) {}
+
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+#ifdef CONFIG_KASAN
+
 void kasan_unpoison_memory(const void *address, size_t size);
 
 void kasan_unpoison_task_stack(struct task_struct *task);
@@ -110,9 +119,6 @@ static inline void kasan_unpoison_memory(const void *address, size_t size) {}
 
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
index a2321d35390e..41c7f1105eaa 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -51,6 +51,7 @@ void kasan_set_track(struct kasan_track *track, gfp_t flags)
 	track->stack = kasan_save_stack(flags);
 }
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 void kasan_enable_current(void)
 {
 	current->kasan_depth++;
@@ -60,6 +61,7 @@ void kasan_disable_current(void)
 {
 	current->kasan_depth--;
 }
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
 {
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index ddaf9d14ca81..8463e35b489f 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -295,8 +295,10 @@ static void print_shadow_for_address(const void *addr)
 
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
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b83ab742bda81114249ef81870a6f30023192cf3.1600204505.git.andreyknvl%40google.com.
