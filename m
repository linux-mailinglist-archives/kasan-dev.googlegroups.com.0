Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNUCRX6QKGQEJUQWGXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A4FC2A737D
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 01:03:04 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id c9sf25814pgk.10
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 16:03:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604534583; cv=pass;
        d=google.com; s=arc-20160816;
        b=cs0S6kNT+QfRKbDm8gHa58sLBwwvNX+Njo2GrZp98kpr/D193V5rpj7u656Kz36nm1
         2ArFKeF2yLWKxcrvkLolN6CmiEKWGFFNzaQLg8Q583Fs4CxOkDS2s3uHQ3wpuqj6vekT
         BqEvlt5oO29fSGMmHn587t0KySRIuksi9Qzod+VDKwfNmyktBHIKz6cVEIdgbbR2zHOl
         V2v24faOrkKpCET5fgahCmdPRsfp89S4yL2xgRvV/oMou9KWbdYX0kqF6orsnyec8Ozv
         QfdZ5DdCkkYbNWYUZUdr4WCNjTLdLX6hIN7OwBre/g6jlBT4rqAcOabk/1bZuM7rbVok
         4yDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=MRcEsxiJ2WTe4AiHqWYsZQLk2NJW8j9KqsVCAwwHHNE=;
        b=hCbZG60qwawYvzIDBBxLeMVszwrj0IH0le7BcS3UObAwT/0SAsT+F+8zNIFDOcQW3/
         aYK9KrPbfZwOiX2reNSNC3Iolvspyb4sU3G3WWxllRjDsbmTWQSBcJzZFb/Jx+/nP9iC
         +OwP1BQHlEyJ06ASpwlUcnBNg0I3sjBdkP2RTmer5fOvywHKyI1SLNx+fbmtne9D9Zmy
         TT6y6p3J89l+tSCrxtf7nosYFmp2RxBtI4Q+/LtLDWC0uNypZOMvDhX1tNLdEFGklNsI
         J3okDVua/92Y+2DTDKSRKAp0nMt83mfpQUWzBYfcdtntvb19sI+ccsqog0JX6wLl7CpZ
         Vf0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MX4puu5v;
       spf=pass (google.com: domain of 3nugjxwokcugkxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3NUGjXwoKCUgkxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MRcEsxiJ2WTe4AiHqWYsZQLk2NJW8j9KqsVCAwwHHNE=;
        b=oi4YmnbZ53ZcR8Opl67+m6nA0jow0fBgaeseVoxzqkxGO8EtFK5i6vVQsIVGoOHcYa
         4QPkIsCu2wK6au7hkTT60b+oP1BkXzP2aOs7T+aRrTDRTglDcOMmQhGQaonFPNz3lNUB
         UqY7re0jYj2TyrKRSP3grd1TPjYRm7FdQyeflVr2e7LkYuwM2qMjFKX2AryenmLkqep0
         onaoXqffm8Y+c79oLd8vxIftfGaZ7Q7nOwDZRkg/aKb5vWru62+BpH38Z0RAZxfD4wKW
         PtPi00thJleIpA18VrCdeWjbjHNVHSjb2QoISLWrzVZzJ6wbDEfgmQQRYKNeK97s3SGJ
         wY8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MRcEsxiJ2WTe4AiHqWYsZQLk2NJW8j9KqsVCAwwHHNE=;
        b=bKxqsisVWnYkheybS1/tyfgGD9A72A5FN6qzBmx5Oh5U4MLUEP7HaA99kL9R6Vpvb4
         08Z4KseoM8QIEUss3ESsbK0BQGxZ344VNQaMExCD+B7F4tPhuYkW2kgwBmnNYMtgCkQB
         HMYLpU257NiyL1CqWZuLMRVcF80Y9eeGBHblWJGOGtMoEDBMGSnlfktsYRAgncr/EX6w
         pDQSlpe/+o98HYFKbHP2mNJRzAYm90kXWoWPN8AD/xwgTGt7a6FjH6lUeBZzEUEQzYUp
         HVo43qhFlFHreh3ILnRI6l0peEFkFvwbIJ6XNC9SBKmHw6USYWgTq79DWPRwpwlJxsba
         gG+w==
X-Gm-Message-State: AOAM533uBhSo4E2BnLpAevo7EIvbjgSB4a+Tn3ZLKW6Z+unLv/nbPKrJ
	UA47KrI0Q5QFCZ+eQBlTm1U=
X-Google-Smtp-Source: ABdhPJwBFMkVJ+eVKGgCj55Ox3+ynmVEiMunNtA55/Hanjsj9uZ9o3fJOzPyaWg5N5yFoAk47Yo04w==
X-Received: by 2002:a63:7f49:: with SMTP id p9mr398035pgn.185.1604534582865;
        Wed, 04 Nov 2020 16:03:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:f601:: with SMTP id m1ls377288pgh.4.gmail; Wed, 04 Nov
 2020 16:03:02 -0800 (PST)
X-Received: by 2002:a05:6a00:16c7:b029:163:ce86:1d5d with SMTP id l7-20020a056a0016c7b0290163ce861d5dmr406765pfc.80.1604534582328;
        Wed, 04 Nov 2020 16:03:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604534582; cv=none;
        d=google.com; s=arc-20160816;
        b=zXNpMRWF3FZJoNxWfr4GzYdF2ylEMHKQ2vfoLZKeyVDAr/ZWbAJU/DQCeuBjs+Onql
         wOLYLlhGbpb6UuLkwd1cUn3wpK1UdFOBP3JrdonGwabmyydY4jRVLqEgUfUe1yoNK2Sh
         Fgo+MWYzF81AwMQEJy0/jVHc4lCBuLkTJxOCXGOk1gLMeROhNt1LFkSeHyfVEvdMBVNt
         NNXnH1crkLgpIA88ZpugYJCLyBT9BmfhMTLLgNkNtXsOkOjdwABI5Q958oJI+OcqRRt8
         FFD1mECwPIU7axtvAc6ADTcyOlmzocY76NIuKSAnrmLWSnkm3OBaor4lUqEQtqx/cGOz
         EBzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=YHPz8JrRkO/XRi71L68uJnMTHNWIIJmflnYXoYMB1HU=;
        b=XeXVVI4TpIrlXSPBRbJwEjMcb1D5JnsRcX69gjeLpHN2yEl41PfqPPmR06VOyO0Fca
         7xRUSNJ5SaknAn/6ejDuY+hcS5xWJfpotsOo+tKILVNuzaKb2UVJ8RG5And4rAajl36v
         5jotzYeqgwKzooLl9I7iT2lKGhuuzsD/2G4ReQBFZAu+AL/VHbBhgle3naz4HGrl4xHN
         NMCXstFCw/HQYnLfCAqjYDawIyUoCf0YmIoMgvDhZdOh+xV/4KeLEphi8bOaJ36T1ohz
         MqxXwKAQlgDQ/SbMwmTKUf/DuY65OdlcPcXO8bIO23h8/4NicmXjvp9zMLGSAsrX9zgQ
         GTIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MX4puu5v;
       spf=pass (google.com: domain of 3nugjxwokcugkxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3NUGjXwoKCUgkxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id f2si236431pfj.5.2020.11.04.16.03.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 16:03:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 3nugjxwokcugkxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id y8so34368qki.12
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 16:03:02 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:560d:: with SMTP id
 ca13mr435510qvb.2.1604534581496; Wed, 04 Nov 2020 16:03:01 -0800 (PST)
Date: Thu,  5 Nov 2020 01:02:21 +0100
In-Reply-To: <cover.1604534322.git.andreyknvl@google.com>
Message-Id: <050977b6a6e0baee4afb4e701b600af32ee85ee6.1604534322.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH 11/20] kasan: add and integrate kasan boot parameters
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MX4puu5v;       spf=pass
 (google.com: domain of 3nugjxwokcugkxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3NUGjXwoKCUgkxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
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

- kasan.stack=off/on - enable stacks collection
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
 mm/kasan/hw_tags.c | 144 +++++++++++++++++++++++++++++++++++++++++++++
 mm/kasan/kasan.h   |  16 +++++
 mm/kasan/report.c  |  14 ++++-
 4 files changed, 189 insertions(+), 7 deletions(-)

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
index bd8bf05c8034..52984825c75f 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -8,6 +8,8 @@
 
 #define pr_fmt(fmt) "kasan: " fmt
 
+#include <linux/init.h>
+#include <linux/jump_label.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
 #include <linux/memory.h>
@@ -17,11 +19,153 @@
 
 #include "kasan.h"
 
+enum kasan_arg_mode {
+	KASAN_ARG_MODE_DEFAULT,
+	KASAN_ARG_MODE_OFF,
+	KASAN_ARG_MODE_PROD,
+	KASAN_ARG_MODE_FULL,
+};
+
+enum kasan_arg_stacks {
+	KASAN_ARG_STACKS_DEFAULT,
+	KASAN_ARG_STACKS_OFF,
+	KASAN_ARG_STACKS_ON,
+};
+
+enum kasan_arg_fault {
+	KASAN_ARG_FAULT_DEFAULT,
+	KASAN_ARG_FAULT_REPORT,
+	KASAN_ARG_FAULT_PANIC,
+};
+
+static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
+static enum kasan_arg_stacks kasan_arg_stacks __ro_after_init;
+static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
+
+/* Whether KASAN is enabled at all. */
+DEFINE_STATIC_KEY_FALSE_RO(kasan_flag_enabled);
+EXPORT_SYMBOL(kasan_flag_enabled);
+
+/* Whether to collect alloc/free stack traces. */
+DEFINE_STATIC_KEY_FALSE_RO(kasan_flag_stacks);
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
+static int __init early_kasan_flag_stacks(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "off"))
+		kasan_arg_stacks = KASAN_ARG_STACKS_OFF;
+	else if (!strcmp(arg, "on"))
+		kasan_arg_stacks = KASAN_ARG_STACKS_ON;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan.stacks", early_kasan_flag_stacks);
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
 /* kasan_init_hw_tags() is called for each CPU. */
 void kasan_init_hw_tags(void)
 {
+	/* Choose KASAN mode if kasan boot parameter is not provided. */
+	if (kasan_arg_mode == KASAN_ARG_MODE_DEFAULT) {
+		if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
+			kasan_arg_mode = KASAN_ARG_MODE_FULL;
+		else
+			kasan_arg_mode = KASAN_ARG_MODE_PROD;
+	}
+
+	/* If KASAN isn't enabled, do nothing. */
+	if (kasan_arg_mode == KASAN_ARG_MODE_OFF)
+		return;
+
+	/* Only process the boot parameters on boot CPU. */
+	if (smp_processor_id() == 0) {
+		/* Preset parameter values based on the mode. */
+		switch (kasan_arg_mode) {
+		case KASAN_ARG_MODE_OFF:
+			return;
+		case KASAN_ARG_MODE_PROD:
+			static_branch_enable(&kasan_flag_enabled);
+			break;
+		case KASAN_ARG_MODE_FULL:
+			static_branch_enable(&kasan_flag_enabled);
+			static_branch_enable(&kasan_flag_stacks);
+			break;
+		default:
+			break;
+		}
+
+		/* Now, optionally override the presets. */
+
+		switch (kasan_arg_stacks) {
+		case KASAN_ARG_STACKS_OFF:
+			static_branch_disable(&kasan_flag_stacks);
+			break;
+		case KASAN_ARG_STACKS_ON:
+			static_branch_enable(&kasan_flag_stacks);
+			break;
+		default:
+			break;
+		}
+
+		switch (kasan_arg_fault) {
+		case KASAN_ARG_FAULT_REPORT:
+			kasan_flag_panic = false;
+			break;
+		case KASAN_ARG_FAULT_PANIC:
+			kasan_flag_panic = true;
+			break;
+		default:
+			break;
+		}
+	}
+
+	/* Init tags for each CPU. */
 	hw_init_tags(KASAN_TAG_MAX);
 
+	/* Only print the message on boot CPU. */
 	if (smp_processor_id() == 0)
 		pr_info("KernelAddressSanitizer initialized\n");
 }
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index ba850285a360..8a4cd9618142 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -5,6 +5,22 @@
 #include <linux/kasan.h>
 #include <linux/stackdepot.h>
 
+#ifdef CONFIG_KASAN_HW_TAGS
+#include <linux/jump_label.h>
+DECLARE_STATIC_KEY_FALSE(kasan_flag_stacks);
+static inline bool kasan_stack_collection_enabled(void)
+{
+	return static_branch_unlikely(&kasan_flag_stacks);
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/050977b6a6e0baee4afb4e701b600af32ee85ee6.1604534322.git.andreyknvl%40google.com.
