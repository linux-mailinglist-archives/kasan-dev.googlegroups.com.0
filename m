Return-Path: <kasan-dev+bncBDX4HWEMTEBRBR5EVT6QKGQEP6JGDLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id D8DD42AE330
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:20:56 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id m17sf78400qvg.5
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:20:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046856; cv=pass;
        d=google.com; s=arc-20160816;
        b=LbsWcoM38s2ptPCGbrQ2/tVo9RLoDIU76wUcd2xpm4woNtVX1R3uj4VL1l7QDJoH5j
         bTZR6f8HkdAtZxYCdd9mgFzsFZwK0sFSsiZRipDQJmS+G4gW2lo6CgW1SqBDoWpCTQY4
         QjFPFRGdlr9LpsVMHk/87Nd4DDCFxNLXQXyrmxH2dOScFJRm4xAzWHy1pZU3BZqR3+N2
         lya8mtFkAOPy9XDJbew1Q+x9SXMO/5bTvYTI2Kxkme4Je+RgiYcBDH7HXuAnY3BcfvFJ
         f32Ure4/dXlAxHTb2MNNgLQDWvCSd/xUpAOk81+6bfAB+l0sqgWZEeJv7XmlKobbQRez
         7Sfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=S3xqQ2WxTTln+E8lehUg1fvzD/oRiPlgQhoXzn47G8E=;
        b=E+bxXH1c9t5+B/MdBl79BK/jzutFwrX6jxtXgReLPw4K4S0WmsvSiBfZ05fyq1dPXs
         n2D8+alLILaqcZh6k6LoNYXfCbP8nAMWBtqT6KMBDJrVcgkafLr7he0GDYpeZsL8PT80
         wevsfXfMBEGH8l2Ui3yuKQd8GFR2EU1JhLA3OAtehCiseZx+k0Nvj31Sf57bJUeKXHE+
         nKbyvZUbsamvYBFFm1LRysTr+B3CGBxXQ8v14ic3Ap1fr4qVL3lqj0U1MsOXGbCS8WeX
         Wv6GPylveJ0sbetgUme+tdb58KpOxmKquWJMG570XXoIJiaBI+qVMOM+Se8tOm4yNcvt
         1/uA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gvbp41Wo;
       spf=pass (google.com: domain of 3rxkrxwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3RxKrXwoKCRw2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=S3xqQ2WxTTln+E8lehUg1fvzD/oRiPlgQhoXzn47G8E=;
        b=tWsMS8BsIoPHOgGK6bXqnofCLS23udQbhuhXcvF5wjC+xoIp9R8Sj5YP7N5PQpu9Hq
         j7KOqnw/EB/T7u78wvo4DaIin+buv8IkdjLg6njc0YCL/MlpmEdVMEkK3WkggPZuWQyq
         9FhXBIZPlBoC2Nj4H52OFhnEv0Dt8cd82pyC0YzyBVm5KS7GHSMBU4wlaNaNmpdwAlOZ
         pUe+I1nUXAzNQ7XowYIeBdtJ0SqIpxkytscouESarX2KPLZHlaVtXgwqhbRvkGWrhR80
         EGS3rFtjr1w/8MRdAhRJjkR7+jbsOkCFIF6q7iRUml8fyFtzEMIVD3tychY2EtX0COmK
         I7sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S3xqQ2WxTTln+E8lehUg1fvzD/oRiPlgQhoXzn47G8E=;
        b=DjeANRWd+1MR7mXmlqj5Ab/c9l1Jy60CXDR9UNMqal75t4HCgR+Yx+NDeny6qxD0cw
         yTTLrvjXVoKS1DpkmGq+4lkQCGuiAxqO7OZT//Uzg+NNZaMdx0gOkXriyJ9dVwndeIvp
         4he/EHcdmWE6qzeOLiK+qfGszFiuDSLtZ0/FmY+h0ndHvc9iXhh5qxY6KyIlrJU/g5Ib
         OLQb4bp9O6Bp28klGjoESNFooQzVMDeBN+dC06i/QaVg4a706W5fKkeIwFpZSNg8+2gQ
         RHblhwsj8ya3fDGBB7pWQW6MQvbN46DEbbvZm5A4EniK/IgBD0+K7dLU+a6jKW06C8mb
         t7uw==
X-Gm-Message-State: AOAM533iQ1knjr26Z+1ncCoHia2XyxINHhyV05Tg8QpxsMyQLZKbIw6C
	+o21xKpdSAvcsBr5EQERqQ0=
X-Google-Smtp-Source: ABdhPJwjDd7KV7cDZQHI/SDAqfbzSnFd9apIk+h8bd6UOcpqDPqpRjr3j6FJ9E4JiQQh1votr/39yw==
X-Received: by 2002:a0c:8e4f:: with SMTP id w15mr21201508qvb.42.1605046855903;
        Tue, 10 Nov 2020 14:20:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:8744:: with SMTP id j65ls6672927qkd.1.gmail; Tue, 10 Nov
 2020 14:20:55 -0800 (PST)
X-Received: by 2002:a37:9441:: with SMTP id w62mr21972617qkd.474.1605046855451;
        Tue, 10 Nov 2020 14:20:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046855; cv=none;
        d=google.com; s=arc-20160816;
        b=osK298NHEiiOcg66b11QcQOTPc05aGuyZEfzxyBOrXO2OnHudmEdDGNqEbfGI0oC6R
         oXbZgQCsU9wKM/lN64tQi7SAfNYeWGCdU2ezv/o49qOCwDTw7UCVCFMtWOFQsIWY+FPr
         oadqJeVqCdVTMcPtK4XjYq4Z7PcJ1wyTnFd738Bl3zub5VQ17dI0cfNNYIgJCWyFElIu
         cCVX3TKp2iqrroM8NPgTa2MTG1EmVUuXwjaA+3W04Q5tpZ7jd/e/1H3+LPeyTcUUm/bp
         gkpQKPD4BfJyEiWsZv5ScIpaRXY0ojvML5Mr+Xi+nbLRCqRroe/eLU7+a8OHuWBFMz3P
         tPrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=C1AHhA2JiIvkEyQnY3sopRuy3W9NzHQWsdv6OutYhlM=;
        b=uR/bs0jOwp4zfF05RZlMr+E561968ONPmxt7J7KDdhSEMA/szginAhQ4pegOk2z7bV
         0ZSubdlZa7+TK3yYXcX5PYAKX7pUrvWAfN4oB+Zz3mRNWOG4NKlLRlNoae356mqlGlNK
         ChmTBQJe75Y8ax+9G2MM94/eTGZAsEsE0TEoF7t8G94PCKogv6qX8xW/48zB8Fh/etli
         mhHEddInTAzXPwgjSYJ2CAxA/IbjhJF7bxX/aKWFVi6VcSWKBLuqGZHQQ69XA8jwIvTl
         MN6vCnsOb6gfZe54zheh5s8j1eAJyxjlcIMBP7vWp/WjoK2MhOyrTymE5PqZlFJIMxnp
         Ychw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gvbp41Wo;
       spf=pass (google.com: domain of 3rxkrxwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3RxKrXwoKCRw2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id z205si17766qkb.1.2020.11.10.14.20.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:20:55 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rxkrxwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id x20so7513697qts.19
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:20:55 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:1541:: with SMTP id
 t1mr21263869qvw.61.1605046855110; Tue, 10 Nov 2020 14:20:55 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:15 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <fdf9e3aec8f57ebb2795710195f8aaf79e3b45bd.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 11/20] kasan: add and integrate kasan boot parameters
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gvbp41Wo;       spf=pass
 (google.com: domain of 3rxkrxwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3RxKrXwoKCRw2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN mode is intended to eventually be used in
production as a security mitigation. Therefore there's a need for finer
control over KASAN features and for an existence of a kill switch.

This change adds a few boot parameters for hardware tag-based KASAN that
allow to disable or otherwise control particular KASAN features.

The features that can be controlled are:

1. Whether KASAN is enabled at all.
2. Whether KASAN collects and saves alloc/free stacks.
3. Whether KASAN panics on a detected bug or not.

With this change a new boot parameter kasan.mode allows to choose one of
three main modes:

- kasan.mode=off - KASAN is disabled, no tag checks are performed
- kasan.mode=prod - only essential production features are enabled
- kasan.mode=full - all KASAN features are enabled

The chosen mode provides default control values for the features mentioned
above. However it's also possible to override the default values by
providing:

- kasan.stacktrace=off/on - enable alloc/free stack collection
                            (default: on for mode=full, otherwise off)
- kasan.fault=report/panic - only report tag fault or also panic
                             (default: report)

If kasan.mode parameter is not provided, it defaults to full when
CONFIG_DEBUG_KERNEL is enabled, and to prod otherwise.

It is essential that switching between these modes doesn't require
rebuilding the kernel with different configs, as this is required by
the Android GKI (Generic Kernel Image) initiative [1].

[1] https://source.android.com/devices/architecture/kernel/generic-kernel-image

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/If7d37003875b2ed3e0935702c8015c223d6416a4
---
 mm/kasan/common.c  |  22 +++++--
 mm/kasan/hw_tags.c | 152 +++++++++++++++++++++++++++++++++++++++++++++
 mm/kasan/kasan.h   |  16 +++++
 mm/kasan/report.c  |  14 ++++-
 4 files changed, 197 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 4598c1364f19..efad5ed6a3bd 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -129,6 +129,11 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	unsigned int redzone_size;
 	int redzone_adjust;
 
+	if (!kasan_stack_collection_enabled()) {
+		*flags |= SLAB_KASAN;
+		return;
+	}
+
 	/* Add alloc meta. */
 	cache->kasan_info.alloc_meta_offset = *size;
 	*size += sizeof(struct kasan_alloc_meta);
@@ -165,6 +170,8 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 
 size_t kasan_metadata_size(struct kmem_cache *cache)
 {
+	if (!kasan_stack_collection_enabled())
+		return 0;
 	return (cache->kasan_info.alloc_meta_offset ?
 		sizeof(struct kasan_alloc_meta) : 0) +
 		(cache->kasan_info.free_meta_offset ?
@@ -267,11 +274,13 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 {
 	struct kasan_alloc_meta *alloc_meta;
 
-	if (!(cache->flags & SLAB_KASAN))
-		return (void *)object;
+	if (kasan_stack_collection_enabled()) {
+		if (!(cache->flags & SLAB_KASAN))
+			return (void *)object;
 
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	__memset(alloc_meta, 0, sizeof(*alloc_meta));
+		alloc_meta = kasan_get_alloc_meta(cache, object);
+		__memset(alloc_meta, 0, sizeof(*alloc_meta));
+	}
 
 	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
 		object = set_tag(object, assign_tag(cache, object, true, false));
@@ -308,6 +317,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	rounded_up_size = round_up(cache->object_size, KASAN_GRANULE_SIZE);
 	kasan_poison_memory(object, rounded_up_size, KASAN_KMALLOC_FREE);
 
+	if (!kasan_stack_collection_enabled())
+		return false;
+
 	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
 			unlikely(!(cache->flags & SLAB_KASAN)))
 		return false;
@@ -355,7 +367,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
 		KASAN_KMALLOC_REDZONE);
 
-	if (cache->flags & SLAB_KASAN)
+	if (kasan_stack_collection_enabled() && (cache->flags & SLAB_KASAN))
 		set_alloc_info(cache, (void *)object, flags);
 
 	return set_tag(object, tag);
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 838b29e44e32..2f6f0261af8c 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -8,6 +8,8 @@
 
 #define pr_fmt(fmt) "kasan: " fmt
 
+#include <linux/init.h>
+#include <linux/jump_label.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
 #include <linux/memory.h>
@@ -17,9 +19,104 @@
 
 #include "kasan.h"
 
+enum kasan_arg_mode {
+	KASAN_ARG_MODE_DEFAULT,
+	KASAN_ARG_MODE_OFF,
+	KASAN_ARG_MODE_PROD,
+	KASAN_ARG_MODE_FULL,
+};
+
+enum kasan_arg_stacktrace {
+	KASAN_ARG_STACKTRACE_DEFAULT,
+	KASAN_ARG_STACKTRACE_OFF,
+	KASAN_ARG_STACKTRACE_ON,
+};
+
+enum kasan_arg_fault {
+	KASAN_ARG_FAULT_DEFAULT,
+	KASAN_ARG_FAULT_REPORT,
+	KASAN_ARG_FAULT_PANIC,
+};
+
+static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
+static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
+static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
+
+/* Whether KASAN is enabled at all. */
+DEFINE_STATIC_KEY_FALSE_RO(kasan_flag_enabled);
+EXPORT_SYMBOL(kasan_flag_enabled);
+
+/* Whether to collect alloc/free stack traces. */
+DEFINE_STATIC_KEY_FALSE_RO(kasan_flag_stacktrace);
+
+/* Whether panic or disable tag checking on fault. */
+bool kasan_flag_panic __ro_after_init;
+
+/* kasan.mode=off/prod/full */
+static int __init early_kasan_mode(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "off"))
+		kasan_arg_mode = KASAN_ARG_MODE_OFF;
+	else if (!strcmp(arg, "prod"))
+		kasan_arg_mode = KASAN_ARG_MODE_PROD;
+	else if (!strcmp(arg, "full"))
+		kasan_arg_mode = KASAN_ARG_MODE_FULL;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan.mode", early_kasan_mode);
+
+/* kasan.stack=off/on */
+static int __init early_kasan_flag_stacktrace(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "off"))
+		kasan_arg_stacktrace = KASAN_ARG_STACKTRACE_OFF;
+	else if (!strcmp(arg, "on"))
+		kasan_arg_stacktrace = KASAN_ARG_STACKTRACE_ON;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan.stacktrace", early_kasan_flag_stacktrace);
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
 /* kasan_init_hw_tags_cpu() is called for each CPU. */
 void kasan_init_hw_tags_cpu(void)
 {
+	/*
+	 * There's no need to check that the hardware is MTE-capable here,
+	 * as this function is only called for MTE-capable hardware.
+	 */
+
+	/* If KASAN is disabled, do nothing. */
+	if (kasan_arg_mode == KASAN_ARG_MODE_OFF)
+		return;
+
 	hw_init_tags(KASAN_TAG_MAX);
 	hw_enable_tagging();
 }
@@ -27,6 +124,61 @@ void kasan_init_hw_tags_cpu(void)
 /* kasan_init_hw_tags() is called once on boot CPU. */
 void kasan_init_hw_tags(void)
 {
+	/* If hardware doesn't support MTE, do nothing. */
+	if (!system_supports_mte())
+		return;
+
+	/* If KASAN is disabled, do nothing. */
+	if (kasan_arg_mode == KASAN_ARG_MODE_OFF)
+		return;
+
+	/* Choose KASAN mode if kasan boot parameter is not provided. */
+	if (kasan_arg_mode == KASAN_ARG_MODE_DEFAULT) {
+		if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
+			kasan_arg_mode = KASAN_ARG_MODE_FULL;
+		else
+			kasan_arg_mode = KASAN_ARG_MODE_PROD;
+	}
+
+	/* Preset parameter values based on the mode. */
+	switch (kasan_arg_mode) {
+	case KASAN_ARG_MODE_OFF:
+		return;
+	case KASAN_ARG_MODE_PROD:
+		static_branch_enable(&kasan_flag_enabled);
+		break;
+	case KASAN_ARG_MODE_FULL:
+		static_branch_enable(&kasan_flag_enabled);
+		static_branch_enable(&kasan_flag_stacktrace);
+		break;
+	default:
+		break;
+	}
+
+	/* Now, optionally override the presets. */
+
+	switch (kasan_arg_stacktrace) {
+	case KASAN_ARG_STACKTRACE_OFF:
+		static_branch_disable(&kasan_flag_stacktrace);
+		break;
+	case KASAN_ARG_STACKTRACE_ON:
+		static_branch_enable(&kasan_flag_stacktrace);
+		break;
+	default:
+		break;
+	}
+
+	switch (kasan_arg_fault) {
+	case KASAN_ARG_FAULT_REPORT:
+		kasan_flag_panic = false;
+		break;
+	case KASAN_ARG_FAULT_PANIC:
+		kasan_flag_panic = true;
+		break;
+	default:
+		break;
+	}
+
 	pr_info("KernelAddressSanitizer initialized\n");
 }
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 2d3c99125996..5eff3d9f624e 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -5,6 +5,22 @@
 #include <linux/kasan.h>
 #include <linux/stackdepot.h>
 
+#ifdef CONFIG_KASAN_HW_TAGS
+#include <linux/jump_label.h>
+DECLARE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
+static inline bool kasan_stack_collection_enabled(void)
+{
+	return static_branch_unlikely(&kasan_flag_stacktrace);
+}
+#else
+static inline bool kasan_stack_collection_enabled(void)
+{
+	return true;
+}
+#endif
+
+extern bool kasan_flag_panic __ro_after_init;
+
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
 #else
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 25ca66c99e48..7d86af340148 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -99,6 +99,10 @@ static void end_report(unsigned long *flags)
 		panic_on_warn = 0;
 		panic("panic_on_warn set ...\n");
 	}
+#ifdef CONFIG_KASAN_HW_TAGS
+	if (kasan_flag_panic)
+		panic("kasan.fault=panic set ...\n");
+#endif
 	kasan_enable_current();
 }
 
@@ -161,8 +165,8 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
 		(void *)(object_addr + cache->object_size));
 }
 
-static void describe_object(struct kmem_cache *cache, void *object,
-				const void *addr, u8 tag)
+static void describe_object_stacks(struct kmem_cache *cache, void *object,
+					const void *addr, u8 tag)
 {
 	struct kasan_alloc_meta *alloc_meta = kasan_get_alloc_meta(cache, object);
 
@@ -190,7 +194,13 @@ static void describe_object(struct kmem_cache *cache, void *object,
 		}
 #endif
 	}
+}
 
+static void describe_object(struct kmem_cache *cache, void *object,
+				const void *addr, u8 tag)
+{
+	if (kasan_stack_collection_enabled())
+		describe_object_stacks(cache, object, addr, tag);
 	describe_object_addr(cache, object, addr);
 }
 
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fdf9e3aec8f57ebb2795710195f8aaf79e3b45bd.1605046662.git.andreyknvl%40google.com.
