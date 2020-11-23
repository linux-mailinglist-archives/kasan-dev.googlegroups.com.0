Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWFQ6D6QKGQEYZMFDZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E6122C1574
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:15:21 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id i10sf3888388ljg.11
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:15:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162521; cv=pass;
        d=google.com; s=arc-20160816;
        b=rkJXjNnoiybcUkw9+FYp/ZlowOtae9tGudHsWFyx2SVizLqi1utBW5G3kyVYv/Llnq
         +fd0E4yFLrdlxH/AAXncaozZVw5w34J4CQbl12fxhfEkLS49vmnUAnMEz0GLxLuRAs0Q
         cp+ifsYOgAWoRKACAhtth2xw8YHHmhmxwuRwRavOechYNAy+zNZg6uNR4Ee14+IjfizV
         kg4vgZShPYk67t/xK99XB1to2ZaZ/TEq2yOs7wrvLdtiRWZeyQ+l1jDg671EyrtwqNwz
         ovdFNk//12eBS6XH6vyA4TvBg91DP2kicqNxPBiqqTkpe7aLBmjpuAveWFere7xkgbCM
         gFvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=T6gqn5pQp4PjsLgGa4ffMviUNlPDnEG7r6vbK6+1kA8=;
        b=RP4PqbAN4tICNQEH4alkwUnT6tkAsj+F9OJec5g/haL24I79NugC+Y1IVKNss3zfUd
         /uomLWCY1b/wBHCu3Nw6s59M0/P7JVhth5lQkZi8ZFVf3f3b+eQ1tkzqHJQJMH6Qm7zP
         QmKKCAZ+mw19LVQJZk/y+gVWyW5cOeCJtAdjBZxH1QmPLs2lDWWwhmHtPK+C51p+2vPP
         V4dRWAu+sCtITzXsCFPR76yfSeuXE6YBoc/F90hZkM5J7cHB5jD3lKGzukpNk4gUmx+0
         3GbkGijZ3+dnzvR1YF368h3QZ4otA1RmhUEyTMKD972xwcoW/o/T41i0j2YICJp0rh6e
         3gKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="GvA/EBeX";
       spf=pass (google.com: domain of 3vxi8xwokcxwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Vxi8XwoKCXwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=T6gqn5pQp4PjsLgGa4ffMviUNlPDnEG7r6vbK6+1kA8=;
        b=VdezlHMTDbqrGmmhVAMqcEGl6FGWJ31tinFDIr49DPjRg9oSuz6wsSWqItuPBpFHUR
         GarjQ2SWgfJZBn1J75aEoGtulKkKYGeeqFaa63Fm4OozWiuGV4CEU/eYkRH3555XjqJ0
         Wcx1nXaXPwGnDIpA6DYX3hbTFJMYA+OD+Tdm+ByDULmz17qYkq+Ls2SNXQzb3v9E9KyV
         mruJcOZVDpDlAoYGoAzwmoGWBprR5z9Jc1BImjRaJmFOQSRBqL4PVtUYsBXE5u+xaJbh
         BUDgJb4KtstiXZDqsJHRc7gpyUB0DklQaXNUyWsLuMu4Dz26BF55kHW2hKnZIWJrKb0o
         bDGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T6gqn5pQp4PjsLgGa4ffMviUNlPDnEG7r6vbK6+1kA8=;
        b=Or/TS48LMZ/UC+1Mt4wE+dXB4LB0C+nvNuKQVaEJrjzglM0uJ8jDDvp3Ksjn6E0gb2
         WhmMcxDlMLLDXRe26G+vqr9IFOsqPKSewRa8xjeyKMvMeFdRFN+URSMUcXdazVPHQNAt
         IjhNpeMu1K5mizzMahUwi3qUzXYRsxsdStRQLf6vZ+UecL0vDPY5tEt7TNDMtVSMDbXG
         OQdBfxTtc14zLcxZqPKt/+/EB0+YjTQ/Z0Ov7IfR/B7nzkKgJXz0J4H7QSaC+QfZB9aw
         QY+nYsV3MIHyi2ukqgDtztOeOYgqp+GUw1UzRfjcSxRmeC81bT0AgH7ts/MGaFzp7plQ
         Kifw==
X-Gm-Message-State: AOAM531W+xGBS9qb3d9iQ7N7Yikhx6XnomNdZa4X7dMA+o88DKpfMKRr
	f5DrW+hrukI9z+XiuPXXQPs=
X-Google-Smtp-Source: ABdhPJyPD5Fj6sEuEQcRW4JrmnOS8Sv0Nsmv2jlHKfu/HSYAZlBzAsxbqUaa+FQfRP49p8CdyFE5cQ==
X-Received: by 2002:ac2:53af:: with SMTP id j15mr381032lfh.256.1606162520936;
        Mon, 23 Nov 2020 12:15:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9059:: with SMTP id n25ls611849ljg.3.gmail; Mon, 23 Nov
 2020 12:15:20 -0800 (PST)
X-Received: by 2002:a2e:9a52:: with SMTP id k18mr424372ljj.34.1606162519960;
        Mon, 23 Nov 2020 12:15:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162519; cv=none;
        d=google.com; s=arc-20160816;
        b=UgfVuXaQThLvKRVhpkG4aUv+S+/ivaHK6EAzT7Ru1lYU/B7Zo42Gg5NlqJRqxPToQ3
         dwl9je3dvHjWl/oCfFmyVkSNkY1SIFL93e7NuzZ2PoVFNVF15aWQvplflF6aN76TBt45
         7APnpyW5TMnKhluWYwOHwO+614X/6aIeWZZN7vwAYd0DtPRJ0J/QkhhVgJ9l8tO9hqVt
         VSstPSVFNb+xxt1qmPKQAfZtdTCzt1cmAubg9yhH89xwEyOgeYBG7obTAceVGuugLYaR
         jxg303f5GMAShGbbm6iyyTb9SiU/oRyiypYrqW74J5ZTEkauAmnrRDrWP2QByusiVKiG
         KYZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=jfEhV0tAQhE/zbKKPTCT6UIAQVQtbAcePK8Pzf7KaDc=;
        b=rHV/rzCvxqnKXC+rBr7koRAzRQkbGtk861Lu5W/Er3uUyMGmKWZ5pUIYe2hDCeM+wy
         10JTwcsPtv7ZihX3iLqxfQo91iKU1xwDzyl2SCff5V2TjgFWDEpY9Ic2uKzxeMlsFxC7
         RcuP7BM0t3xXXvFXVTOiJY6Icas0DO322SxQ0BxGbH22dPMgt7aEkr4ixe5wm5PWtJzw
         dXt0FOG7sxsPD15guUTN2zvfC52uvsYST00hKlooRZEhbK41O3yb+ryZqkGy1lzG1nWG
         H1IZDwrbNh3KxNTC1t/RzdC2xxF2j5ASu1nYnjj4QM61bcTFXj6I7a2Ye9dA47wafpwZ
         69LA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="GvA/EBeX";
       spf=pass (google.com: domain of 3vxi8xwokcxwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Vxi8XwoKCXwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 23si200977lfa.10.2020.11.23.12.15.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:15:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vxi8xwokcxwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id g17so165014wmg.1
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:15:19 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:9901:: with SMTP id
 b1mr648770wme.18.1606162519408; Mon, 23 Nov 2020 12:15:19 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:41 +0100
In-Reply-To: <cover.1606162397.git.andreyknvl@google.com>
Message-Id: <cb093613879d8d8841173f090133eddeb4c35f1f.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606162397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 11/19] kasan: add and integrate kasan boot parameters
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="GvA/EBeX";       spf=pass
 (google.com: domain of 3vxi8xwokcxwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Vxi8XwoKCXwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/If7d37003875b2ed3e0935702c8015c223d6416a4
---
 mm/kasan/common.c  |  22 +++++--
 mm/kasan/hw_tags.c | 151 +++++++++++++++++++++++++++++++++++++++++++++
 mm/kasan/kasan.h   |  16 +++++
 mm/kasan/report.c  |  14 ++++-
 4 files changed, 196 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 1ac4f435c679..a11e3e75eb08 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -135,6 +135,11 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
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
@@ -171,6 +176,8 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 
 size_t kasan_metadata_size(struct kmem_cache *cache)
 {
+	if (!kasan_stack_collection_enabled())
+		return 0;
 	return (cache->kasan_info.alloc_meta_offset ?
 		sizeof(struct kasan_alloc_meta) : 0) +
 		(cache->kasan_info.free_meta_offset ?
@@ -263,11 +270,13 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
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
@@ -307,6 +316,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	rounded_up_size = round_up(cache->object_size, KASAN_GRANULE_SIZE);
 	poison_range(object, rounded_up_size, KASAN_KMALLOC_FREE);
 
+	if (!kasan_stack_collection_enabled())
+		return false;
+
 	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
 			unlikely(!(cache->flags & SLAB_KASAN)))
 		return false;
@@ -357,7 +369,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	poison_range((void *)redzone_start, redzone_end - redzone_start,
 		     KASAN_KMALLOC_REDZONE);
 
-	if (cache->flags & SLAB_KASAN)
+	if (kasan_stack_collection_enabled() && (cache->flags & SLAB_KASAN))
 		set_alloc_info(cache, (void *)object, flags);
 
 	return set_tag(object, tag);
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 863fed4edd3f..30ce88935e9d 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -8,18 +8,115 @@
 
 #define pr_fmt(fmt) "kasan: " fmt
 
+#include <linux/init.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
 #include <linux/memory.h>
 #include <linux/mm.h>
+#include <linux/static_key.h>
 #include <linux/string.h>
 #include <linux/types.h>
 
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
@@ -27,6 +124,60 @@ void kasan_init_hw_tags_cpu(void)
 /* kasan_init_hw_tags() is called once on boot CPU. */
 void __init kasan_init_hw_tags(void)
 {
+	/* If hardware doesn't support MTE, do nothing. */
+	if (!system_supports_mte())
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
+	case KASAN_ARG_MODE_DEFAULT:
+		/* Shouldn't happen as per the check above. */
+		WARN_ON(1);
+		return;
+	case KASAN_ARG_MODE_OFF:
+		/* If KASAN is disabled, do nothing. */
+		return;
+	case KASAN_ARG_MODE_PROD:
+		static_branch_enable(&kasan_flag_enabled);
+		break;
+	case KASAN_ARG_MODE_FULL:
+		static_branch_enable(&kasan_flag_enabled);
+		static_branch_enable(&kasan_flag_stacktrace);
+		break;
+	}
+
+	/* Now, optionally override the presets. */
+
+	switch (kasan_arg_stacktrace) {
+	case KASAN_ARG_STACKTRACE_DEFAULT:
+		break;
+	case KASAN_ARG_STACKTRACE_OFF:
+		static_branch_disable(&kasan_flag_stacktrace);
+		break;
+	case KASAN_ARG_STACKTRACE_ON:
+		static_branch_enable(&kasan_flag_stacktrace);
+		break;
+	}
+
+	switch (kasan_arg_fault) {
+	case KASAN_ARG_FAULT_DEFAULT:
+		break;
+	case KASAN_ARG_FAULT_REPORT:
+		kasan_flag_panic = false;
+		break;
+	case KASAN_ARG_FAULT_PANIC:
+		kasan_flag_panic = true;
+		break;
+	}
+
 	pr_info("KernelAddressSanitizer initialized\n");
 }
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8aa83b7ad79e..d01a5ac34f70 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -6,6 +6,22 @@
 #include <linux/kfence.h>
 #include <linux/stackdepot.h>
 
+#ifdef CONFIG_KASAN_HW_TAGS
+#include <linux/static_key.h>
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
index 76a0e3ae2049..ffa6076b1710 100644
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cb093613879d8d8841173f090133eddeb4c35f1f.1606162397.git.andreyknvl%40google.com.
