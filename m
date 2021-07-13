Return-Path: <kasan-dev+bncBDL5H3OYYEEBBWWOWODQMGQEXD3NLOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 013EF3C67D4
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jul 2021 03:07:40 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id 124-20020a6217820000b02902feebfd791esf14028566pfx.19
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jul 2021 18:07:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626138458; cv=pass;
        d=google.com; s=arc-20160816;
        b=u7Mx2mL0cwc9APdYOYeB3U1fKYWWip3lx+NusJXJLnFH4GH5bQFFW3xbd9YGVpjC8h
         zMg54okf+greWlo6zlzex/SsfXgcy738VJwhWnCBKNBoSHL+Xn1cpsUNjRupKW2vOwWO
         0F3wctLLMzYd/rwj0Q8pf4tNGbW4oFWMOuS9MK1ZcBkSVcK6lGdpKI0UaRml0gpk73ZA
         wFi6RJI4z9bNAopD5YVjuDxDC67azMccXkpEIh8CoS4U4YQ6KZy0ygTrWrYS14FqTsPl
         lLohEhQkXFPyL1KAKSuhOt6eZFeRFBPmbqJSG8fyaPEhfGipCuZ//rMFfNU0Zj4+izjo
         O6Fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=1Nf75Y6MZZQlM4n7F9qJ2tteJW335y0WsO/fuqQBlqM=;
        b=S/w363Sv2pDgCPUl1G0+dvB7NeVybExbtqJ01yoMamhDIuJD8rhGQzLtugm+/sttgt
         ENZ1vqAoq8OA8vFxwSWbCOlTWNH0UEM54EYpvm99RO7KHK3FBicCcG++ajR2ukFbb6Vy
         wPdVHt4xl6Qohb0hMQGGq1MNtmbvPlmBvnIGe0GOyNJL/g9WKmxYi9OQ4r43ImTq7sLK
         4YhSRVetKiU4hrXYm1lq4FO918wi1PK5njpjgVpfdTYFfecWJCMug5s2UxP1FKDqHmyX
         oAEOgFVZkK7ytq9Qdk89M8bNxs19lNW92qUY+8GfmbsviSsZEt9lqClL2BzfcxjfyBh1
         gkng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dTAoo+q0;
       spf=pass (google.com: domain of 3wefsyagkceggyynivsxqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--woodylin.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3WefsYAgKCeggYYNiVSXQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--woodylin.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=1Nf75Y6MZZQlM4n7F9qJ2tteJW335y0WsO/fuqQBlqM=;
        b=PXX7eayG7LcLspyN3WvZlzv/GNvs2e24FjpzK8e22W2+na8AhFseDZZ76Qbzhgx1Yf
         7vxAYZmk9pHFAyVfihaz6aIm1RIgCRBb+HgxYOqKKNWP7eR2p+c6rQKWpV6UUiD3aazz
         xgTGp9Sh/QgvHyuYQcZK1Z1ruKSrcz1ClAo9wu0UEdCxGzHeIja+dF64xChScT6Ta0w4
         K/TI6ggCBi4ChymSb6D/Qw33y6B9MDzfGClqXga5nOFEhwRQPWirA7Q381l5jofR+VTV
         F8sQgBj7Pb6lWznjQ81KR1F4hofOaPv3frGX5/QHq/1KLlc2CyeJ8z3GYL9TGORrOUKJ
         ZJmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1Nf75Y6MZZQlM4n7F9qJ2tteJW335y0WsO/fuqQBlqM=;
        b=JQTtsVW8/7LDjfojTZV+5WmA6Xv1BrBWgbjIw3yTOzFdQWr1IOhQBtqT9iuPMJt5zN
         hCRbAz13rusjDT7Z8k7Nx+U/GncjzxutI/u67oE7wrTz543nWgXuj/vSi65hO9l0dpSm
         0Nhn6tHl98sdApndqMrP95GWWv5amKTqe8Dbf/+UbbCMZbFUeP+CNPQjls2N+Orx/aMF
         0eswBn4Yce0aH4u36Pv0tWisqKI0nB8hNpw0hPyN8w29cvqzLz8Sru9vZi3qS4yDK+4K
         nGTHT7CSxjtVDH3fxvmZadJy8MnV/QqUAX6Vxbf0OZw9afqHd2yaCiQ46a/G2Rn8Qgoe
         VKWw==
X-Gm-Message-State: AOAM533pxm4FgI9SjZczuVJeNoXjpH6M0+L4WjXE3m+ckuokK/vL9R2K
	p4Hm434ZHcrDTQudAvUCbrY=
X-Google-Smtp-Source: ABdhPJxVoWD19mqQRmtCfZjuCDwE/GKZwRsvsogDIw84Mke0MswKwSNeZBQ7dspDm96BzWTGHPJ4Xg==
X-Received: by 2002:a63:170b:: with SMTP id x11mr1797053pgl.253.1626138458607;
        Mon, 12 Jul 2021 18:07:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:e643:: with SMTP id p3ls111264pgj.6.gmail; Mon, 12 Jul
 2021 18:07:38 -0700 (PDT)
X-Received: by 2002:a62:19c6:0:b029:319:4a01:407d with SMTP id 189-20020a6219c60000b02903194a01407dmr1966827pfz.1.1626138458051;
        Mon, 12 Jul 2021 18:07:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626138458; cv=none;
        d=google.com; s=arc-20160816;
        b=HHJbKlj4Xgo/CUYWy1SLkoBjlpGvFnKuZbGvTWu2AzKHGIMHzjLhjRuBO6iO0W/wrT
         /qIc2bU0tZeZk0XWglG1ADEJdFN7x3SShv6uPdK0ORzKti+k91VH7ISw24gOHZV2Bnlk
         BT+WzBnVz8c6SIZlBWEWYwkdrbQcaYA0PC+Rn6yicTudPt/JeTSw30zs4JkH6DHfq4+x
         Z3zP5SdFixLGddcgKlgAwWErMsvgiWBENl5f7pt7xJF5p7p2MR4oCmxhtekV/qW0Yi8m
         eMKNIJwdaDWTP1k4wsQyTlxDuYedpx9ugSlrDzaLqsXnqIwRWwYD5r2q5XXhMX4a3RQm
         bBAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=7H0LpH2GONNn9NZv/9WQ2DtXytau5fXoMsvDyHJxp/k=;
        b=JJCNcTZJ+e0wlPb4uABMxrAZmu8VEGMmSv1SCYgFCcazTql2WQB/rYSsDy1krzFBHE
         eXkGzDsWnaJV4tLKyV+JZYdbXEoWUBCjRjSeq7elMsxm/Y3zuDWoDpPPqgnsmt8O9Gs5
         faU3C/bdBa0mCjWAryfo0dIQJs3m4s/gXnzgEnNUi3QhiPQbQ3LHa92KQUDib9eXmdXS
         QIdYmuRRrJOyeaYpE/cJavxqu+NWBFAiCjVUE3QGBvY41z+v9AZVPKUxI5/xf1ZRKpDd
         Fqfa5mUdvObfoc8ETpQmvwnIwJjbr3zwI8J6x66ge9FW7UeAtrYTCykP+62Ca6Wyo02s
         98Tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dTAoo+q0;
       spf=pass (google.com: domain of 3wefsyagkceggyynivsxqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--woodylin.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3WefsYAgKCeggYYNiVSXQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--woodylin.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id y190si2111867pgy.2.2021.07.12.18.07.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jul 2021 18:07:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wefsyagkceggyynivsxqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--woodylin.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id a4-20020a25f5040000b029054df41d5cceso24808585ybe.18
        for <kasan-dev@googlegroups.com>; Mon, 12 Jul 2021 18:07:38 -0700 (PDT)
X-Received: from woodylin.ntc.corp.google.com ([2401:fa00:fc:202:e7ee:3440:9a37:23d8])
 (user=woodylin job=sendgmr) by 2002:a5b:b01:: with SMTP id
 z1mr2302389ybp.341.1626138457207; Mon, 12 Jul 2021 18:07:37 -0700 (PDT)
Date: Tue, 13 Jul 2021 09:05:36 +0800
Message-Id: <20210713010536.3161822-1-woodylin@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.32.0.93.g670b81a890-goog
Subject: [PATCH v2] mm/kasan: move kasan.fault to mm/kasan/report.c
From: "'Woody Lin' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Jonathan Corbet <corbet@lwn.net>, Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Woody Lin <woodylin@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: woodylin@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dTAoo+q0;       spf=pass
 (google.com: domain of 3wefsyagkceggyynivsxqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--woodylin.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3WefsYAgKCeggYYNiVSXQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--woodylin.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Woody Lin <woodylin@google.com>
Reply-To: Woody Lin <woodylin@google.com>
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

Move the boot parameter 'kasan.fault' from hw_tags.c to report.c, so it
can support all KASAN modes - generic, and both tag-based.

Signed-off-by: Woody Lin <woodylin@google.com>
---
 Documentation/dev-tools/kasan.rst | 13 ++++++----
 mm/kasan/hw_tags.c                | 43 -------------------------------
 mm/kasan/kasan.h                  |  1 -
 mm/kasan/report.c                 | 29 ++++++++++++++++++---
 4 files changed, 34 insertions(+), 52 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 83ec4a556c19..21dc03bc10a4 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -181,9 +181,16 @@ By default, KASAN prints a bug report only for the first invalid memory access.
 With ``kasan_multi_shot``, KASAN prints a report on every invalid access. This
 effectively disables ``panic_on_warn`` for KASAN reports.
 
+Alternatively, independent of ``panic_on_warn`` the ``kasan.fault=`` boot
+parameter can be used to control panic and reporting behaviour:
+
+- ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
+  report or also panic the kernel (default: ``report``). The panic happens even
+  if ``kasan_multi_shot`` is enabled.
+
 Hardware tag-based KASAN mode (see the section about various modes below) is
 intended for use in production as a security mitigation. Therefore, it supports
-boot parameters that allow disabling KASAN or controlling its features.
+additional boot parameters that allow disabling KASAN or controlling features:
 
 - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
 
@@ -199,10 +206,6 @@ boot parameters that allow disabling KASAN or controlling its features.
 - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
   traces collection (default: ``on``).
 
-- ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
-  report or also panic the kernel (default: ``report``). The panic happens even
-  if ``kasan_multi_shot`` is enabled.
-
 Implementation details
 ----------------------
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 4ea8c368b5b8..51903639e55f 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -37,16 +37,9 @@ enum kasan_arg_stacktrace {
 	KASAN_ARG_STACKTRACE_ON,
 };
 
-enum kasan_arg_fault {
-	KASAN_ARG_FAULT_DEFAULT,
-	KASAN_ARG_FAULT_REPORT,
-	KASAN_ARG_FAULT_PANIC,
-};
-
 static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
-static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
 
 /* Whether KASAN is enabled at all. */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
@@ -59,9 +52,6 @@ EXPORT_SYMBOL_GPL(kasan_flag_async);
 /* Whether to collect alloc/free stack traces. */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
 
-/* Whether to panic or print a report and disable tag checking on fault. */
-bool kasan_flag_panic __ro_after_init;
-
 /* kasan=off/on */
 static int __init early_kasan_flag(char *arg)
 {
@@ -113,23 +103,6 @@ static int __init early_kasan_flag_stacktrace(char *arg)
 }
 early_param("kasan.stacktrace", early_kasan_flag_stacktrace);
 
-/* kasan.fault=report/panic */
-static int __init early_kasan_fault(char *arg)
-{
-	if (!arg)
-		return -EINVAL;
-
-	if (!strcmp(arg, "report"))
-		kasan_arg_fault = KASAN_ARG_FAULT_REPORT;
-	else if (!strcmp(arg, "panic"))
-		kasan_arg_fault = KASAN_ARG_FAULT_PANIC;
-	else
-		return -EINVAL;
-
-	return 0;
-}
-early_param("kasan.fault", early_kasan_fault);
-
 /* kasan_init_hw_tags_cpu() is called for each CPU. */
 void kasan_init_hw_tags_cpu(void)
 {
@@ -197,22 +170,6 @@ void __init kasan_init_hw_tags(void)
 		break;
 	}
 
-	switch (kasan_arg_fault) {
-	case KASAN_ARG_FAULT_DEFAULT:
-		/*
-		 * Default to no panic on report.
-		 * Do nothing, kasan_flag_panic keeps its default value.
-		 */
-		break;
-	case KASAN_ARG_FAULT_REPORT:
-		/* Do nothing, kasan_flag_panic keeps its default value. */
-		break;
-	case KASAN_ARG_FAULT_PANIC:
-		/* Enable panic on report. */
-		kasan_flag_panic = true;
-		break;
-	}
-
 	pr_info("KernelAddressSanitizer initialized\n");
 }
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 98e3059bfea4..9d57383ce1fa 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -36,7 +36,6 @@ static inline bool kasan_async_mode_enabled(void)
 
 #endif
 
-extern bool kasan_flag_panic __ro_after_init;
 extern bool kasan_flag_async __ro_after_init;
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 8fff1825b22c..884a950c7026 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -39,6 +39,31 @@ static unsigned long kasan_flags;
 #define KASAN_BIT_REPORTED	0
 #define KASAN_BIT_MULTI_SHOT	1
 
+enum kasan_arg_fault {
+	KASAN_ARG_FAULT_DEFAULT,
+	KASAN_ARG_FAULT_REPORT,
+	KASAN_ARG_FAULT_PANIC,
+};
+
+static enum kasan_arg_fault kasan_arg_fault __ro_after_init = KASAN_ARG_FAULT_DEFAULT;
+
+/* kasan.fault=report/panic */
+static int __init early_kasan_fault(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "report"))
+		kasan_arg_fault = KASAN_ARG_FAULT_REPORT;
+	else if (!strcmp(arg, "panic"))
+		kasan_arg_fault = KASAN_ARG_FAULT_PANIC;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan.fault", early_kasan_fault);
+
 bool kasan_save_enable_multi_shot(void)
 {
 	return test_and_set_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags);
@@ -102,10 +127,8 @@ static void end_report(unsigned long *flags, unsigned long addr)
 		panic_on_warn = 0;
 		panic("panic_on_warn set ...\n");
 	}
-#ifdef CONFIG_KASAN_HW_TAGS
-	if (kasan_flag_panic)
+	if (kasan_arg_fault == KASAN_ARG_FAULT_PANIC)
 		panic("kasan.fault=panic set ...\n");
-#endif
 	kasan_enable_current();
 }
 
-- 
2.32.0.93.g670b81a890-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210713010536.3161822-1-woodylin%40google.com.
