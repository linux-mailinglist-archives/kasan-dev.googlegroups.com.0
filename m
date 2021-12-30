Return-Path: <kasan-dev+bncBAABBBMLXCHAMGQEBVZPT5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id CDE37481FBA
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:16:21 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id f13-20020adfe90d000000b001a15c110077sf6498928wrm.8
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:16:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891781; cv=pass;
        d=google.com; s=arc-20160816;
        b=jRxYSYrr3ANbUwdsbMwuyVeJKkpnSUeCef3rCJ8V25o17mRuOchTYFFDcp6lfIpG5v
         dKLcOCASNI7eLleKHAdepvnq2UMif1BelIhYR7JQolLYjIUgog0/yR9PR6+C1SLK7cNR
         BnzzpHarum8pU9yPoGKXo1sRi9jSD69YeiTJYZzSPMKNa3BqGufZMPrwa2LMEXaZv2tq
         rg9JbWRrPk9pX3rV6u1jLHrYhx7w6/T719LR7XmvvuTqO2Bq+Thm4b+cXTm9D6P0Wa02
         zvqRPSlOwicw0sCOSANBW7Gddh46CAQ0QCdSMwQ+L7KrBVPLjhmzTnyXItKD/l0jRjcb
         qxVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gPPnnhm9gqWLKK+KWku15rZUQ+q4AUZWjJ12VttUqrI=;
        b=At8P2MVsiXDP0rDSPsoayRkHO1iuqb+lW43sqkPdem13NiRBKLHobbu3kUCBCBpFl5
         XdVgTGXqFHAQYdzKEGd2wWNp0P8fRC6//i5M71LO+Z9vzvD/qOMneJZW2vYTmOB9Gp0t
         TGdmVYyk3XTm6eYt3n1nEBNgxEjksSajsdKC42OqpDtnjUPRr0lsXF7X/xkgm9qIGMja
         8sbzyK2692TqjD8aGYPQ3kG1F83Z0qtWou66HLMWhT2BmRYNntafUs8NpM5J+b9j3tsX
         V+MzzXd9S5qjs4fH4J69GhJVMhSLYFX3ofMY1n4hFN9HhI1ayMCNhPOwr9TsDzQip6Zc
         TguA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eyGshO82;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gPPnnhm9gqWLKK+KWku15rZUQ+q4AUZWjJ12VttUqrI=;
        b=FJI9UR7/cEdJ75draaOBOwzfW4chLPvpOKpyBhfJb9Tw8Vcjz+JVzxEQig8FW5yrPq
         O7zkoM0jNpyBqg6I3KU5+aQYdlhTG6DjtadxK+XNqjR9CiTgjyz9ZxTQmQ7nBZERughW
         E668RRbd9AxDr+i7btVQGH36t6gAiMbSaSW5VpDeHEhMpd+qzz3k9qHm+Qen2yCu20bE
         1FbLff+Ts4PWMZVtzQvzkxkoatpZmSarRXlDo8jaJNmv/78eiv6GY7OTjhF4Qdaf2NKU
         lTqJaQLweyZ/8CtGW4+sK7w+fhmQ6KaS07m467W+yS4CuHEXRtN7zAJP5pbQvH3s5yj+
         mcfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gPPnnhm9gqWLKK+KWku15rZUQ+q4AUZWjJ12VttUqrI=;
        b=H1oexce/OnfVIs5qtPWkpid2Q9jJcCSzn9fa5gxKZYOn1w+00jdwKYCRh1VwJdu8ca
         QwU7iNzqV1iBpLH1LP2rgBkfVZ8a+x/kNFnwu9FrbpVwpqANXoRlnh1/GvPri3INmDXF
         WyFlhEBIci3lC25U3VqjRMceslce6y3JVa56TWll9yYdEDK9aqPHm4ZPaHZVUhJfpN2t
         tS3V9p8zjXwvR+EaHYt+1ElwwRoDVv40+VoeOfdpKw711TlkOdIFeDxlnsPX5utXNlrb
         p4JE2hlo5GbHEKSlCfVDDFYy0Fqjm3c2wJT2kPJCStXeI3EhhG5z9AB4zb/NLI0Bz4Bf
         APRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53306SkxuyG25TM+ddBFdSANW1vM6zkzkb4AfOT7oDWiy445QjzM
	Dabkj6QAsNeuKHoYZjYkPAs=
X-Google-Smtp-Source: ABdhPJxgsuFOdAcIJkIUhvhumMslG18iwmmseWGnUt3rg+PJ87T3Y+4hgWt8DZPxoOyhiDfykkqwyg==
X-Received: by 2002:a5d:6c67:: with SMTP id r7mr27396829wrz.350.1640891781627;
        Thu, 30 Dec 2021 11:16:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a4cc:: with SMTP id h12ls305713wrb.2.gmail; Thu, 30 Dec
 2021 11:16:21 -0800 (PST)
X-Received: by 2002:adf:fe0f:: with SMTP id n15mr26104494wrr.705.1640891780994;
        Thu, 30 Dec 2021 11:16:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891780; cv=none;
        d=google.com; s=arc-20160816;
        b=f9ds6n6e2bp8JHUyOCYv40Pp3Hm2rh4s+yKsZzj8cfY/Q91S3s8DD/HkhlkdIGpSuH
         0xGmJ8iZ1eWkuR0n2S/B9uE93Cp7B+bcw6HuUzupP2hTLyWWC5J34BLIqc0MOwvGK+2y
         RVISlmuv0hLHxu6Su8uvapY8yE8faALRubixZ1XuZewEl/+Oq6fgQZy4cS8PPQ/+o2hU
         /exbLdWjG8HDaYiP8HEcUvJsa5lXXsnxcC7qN1FK1Pf30yU4aOrDoEKpx2R/ViwU0In2
         HeNfmkwg4mVAGordc73z2kdR0x9JOEcPqDsU9C/Yu6PsXlZjkBoc2mtTDxVWOf2QG/hW
         r1wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ypDUrRwpvHxVi9/0pzLPCyjGz64l2U6vLcrEu5OiSo8=;
        b=yAtpwCuLol5LYp/yqmCLJiCUqQ7VlPBCRxnfkZICmMc5xvcWCPHghFDGjEq2Gs8Uuc
         P+5VXyn0BLnWMCvrOkGDoUiGurqdEgA6nAVzNIBUBEaHvBUPmg7C5RLWd+Ui7FW4scT+
         P7tILB+LglsO7lsCGfB78vslI+syCHabqoiFjLOVfZqP7XiCaoXRSwVt/3x4feJ3hiPM
         0rEaDDy3/FVp1jqQxL/NBY1m17Nwkqc1CIeHzbayEsgDJlgmFjAB9cD0lZE8xMT1P8Xy
         xwGEI1HiWwonpcUpk2K5ZzcoVTemzSW77DxyRyDXzZQIvcpDR8oC7Gy859tHOXOTT13P
         Q3Gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eyGshO82;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id f14si1333382wmq.2.2021.12.30.11.16.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:16:20 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v5 34/39] kasan: clean up feature flags for HW_TAGS mode
Date: Thu, 30 Dec 2021 20:14:59 +0100
Message-Id: <9fefb5cb7639153e50446746fdd3427635bdcda7.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=eyGshO82;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

- Untie kasan_init_hw_tags() code from the default values of
  kasan_arg_mode and kasan_arg_stacktrace.

- Move static_branch_enable(&kasan_flag_enabled) to the end of
  kasan_init_hw_tags_cpu().

- Remove excessive comments in kasan_arg_mode switch.

- Add new comments.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v4->v5:
- Add this patch.
---
 mm/kasan/hw_tags.c | 38 +++++++++++++++++++++-----------------
 mm/kasan/kasan.h   |  2 +-
 2 files changed, 22 insertions(+), 18 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 6509809dd5d8..6a3146d1ccc5 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -42,16 +42,22 @@ static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_stacktrace kasan_arg_stacktrace __initdata;
 
-/* Whether KASAN is enabled at all. */
+/*
+ * Whether KASAN is enabled at all.
+ * The value remains false until KASAN is initialized by kasan_init_hw_tags().
+ */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
 EXPORT_SYMBOL(kasan_flag_enabled);
 
-/* Whether the selected mode is synchronous/asynchronous/asymmetric.*/
+/*
+ * Whether the selected mode is synchronous, asynchronous, or asymmetric.
+ * Defaults to KASAN_MODE_SYNC.
+ */
 enum kasan_mode kasan_mode __ro_after_init;
 EXPORT_SYMBOL_GPL(kasan_mode);
 
 /* Whether to collect alloc/free stack traces. */
-DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
+DEFINE_STATIC_KEY_TRUE(kasan_flag_stacktrace);
 
 /* kasan=off/on */
 static int __init early_kasan_flag(char *arg)
@@ -127,7 +133,11 @@ void kasan_init_hw_tags_cpu(void)
 	 * as this function is only called for MTE-capable hardware.
 	 */
 
-	/* If KASAN is disabled via command line, don't initialize it. */
+	/*
+	 * If KASAN is disabled via command line, don't initialize it.
+	 * When this function is called, kasan_flag_enabled is not yet
+	 * set by kasan_init_hw_tags(). Thus, check kasan_arg instead.
+	 */
 	if (kasan_arg == KASAN_ARG_OFF)
 		return;
 
@@ -154,42 +164,36 @@ void __init kasan_init_hw_tags(void)
 	if (kasan_arg == KASAN_ARG_OFF)
 		return;
 
-	/* Enable KASAN. */
-	static_branch_enable(&kasan_flag_enabled);
-
 	switch (kasan_arg_mode) {
 	case KASAN_ARG_MODE_DEFAULT:
-		/*
-		 * Default to sync mode.
-		 */
-		fallthrough;
+		/* Default is specified by kasan_mode definition. */
+		break;
 	case KASAN_ARG_MODE_SYNC:
-		/* Sync mode enabled. */
 		kasan_mode = KASAN_MODE_SYNC;
 		break;
 	case KASAN_ARG_MODE_ASYNC:
-		/* Async mode enabled. */
 		kasan_mode = KASAN_MODE_ASYNC;
 		break;
 	case KASAN_ARG_MODE_ASYMM:
-		/* Asymm mode enabled. */
 		kasan_mode = KASAN_MODE_ASYMM;
 		break;
 	}
 
 	switch (kasan_arg_stacktrace) {
 	case KASAN_ARG_STACKTRACE_DEFAULT:
-		/* Default to enabling stack trace collection. */
-		static_branch_enable(&kasan_flag_stacktrace);
+		/* Default is specified by kasan_flag_stacktrace definition. */
 		break;
 	case KASAN_ARG_STACKTRACE_OFF:
-		/* Do nothing, kasan_flag_stacktrace keeps its default value. */
+		static_branch_disable(&kasan_flag_stacktrace);
 		break;
 	case KASAN_ARG_STACKTRACE_ON:
 		static_branch_enable(&kasan_flag_stacktrace);
 		break;
 	}
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, stacktrace=%s)\n",
 		kasan_mode_info(),
 		kasan_stack_collection_enabled() ? "on" : "off");
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 020f3e57a03f..efda13a9ce6a 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -12,7 +12,7 @@
 #include <linux/static_key.h>
 #include "../slab.h"
 
-DECLARE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
+DECLARE_STATIC_KEY_TRUE(kasan_flag_stacktrace);
 
 enum kasan_mode {
 	KASAN_MODE_SYNC,
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9fefb5cb7639153e50446746fdd3427635bdcda7.1640891329.git.andreyknvl%40google.com.
