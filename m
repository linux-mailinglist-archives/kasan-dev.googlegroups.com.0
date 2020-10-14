Return-Path: <kasan-dev+bncBDX4HWEMTEBRBT6GTX6AKGQEE6WAT6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 001CF28E801
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 22:45:04 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id a1sf270681otb.14
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 13:45:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602708304; cv=pass;
        d=google.com; s=arc-20160816;
        b=KwHkEaAQzYyZ7BtmO4X70vo1t3CE7tCAB10pAUFDC3XfL9KwGoQE7LMubyroTHrfRK
         TwOQpu6xKHvQ6HvqM2gIGOXptFE3d9fsjcyWLunla9HPd2qTxtehEuBecD0J9mnLaQfD
         BkRO8C0XSl0Jy+dNN/T9MCohgjinVe4e6FV3E7n8FtZ7jA1LIca49u0BTGhZjvN4Xo9D
         jDmwYm+1xPi0/cpl/SebXn1kH2fTG9OIwNz9wLxLABy3hUhHwpZmEjKySy1C82dV/9on
         XvOKV9s+DLBgonXFJStV3dB32dDuExOBt6GEpMriT8obor1vi+9mCdXxZSp3A+R4f2/c
         8wEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=LKaqh+rM3TZJMG8ajYk9fLo3nTkfJC2JuU726+jgPd8=;
        b=CXbmrG4krrAjDy3v5MJjvTw2fd5A9w0d60que+oU28HLO8y/hVYAYxL8RNYYFUtphj
         40k1bihc0v4dc1n32Zj2nCuZt5f3VYzGGM64zCh5E+AP+t/wEACCqDxPlwNFQbVMs7Ez
         Usn4+78G5bwZ4ZaIEggj7MmQqeB6yxV6QH39fnSMDR1O41B++DHPAyMv52XY63IY7uHb
         jCZqv3bOFxKB4zA+eJcZndNfRrLtdQbWjrViF31enAfJBBW63XqsXI2+PHm/kfsyvSDC
         rm+TuzuTpAU4ZsfvePFZXs+ihRSAYRum0X8lMenNZejxwEwdqCTJi4wS/heyU6yfL6ld
         S8qA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=caicryyE;
       spf=pass (google.com: domain of 3tmohxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3TmOHXwoKCTUReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LKaqh+rM3TZJMG8ajYk9fLo3nTkfJC2JuU726+jgPd8=;
        b=nPCwO0C4sWQrzVLEf0SSIdUmDl1rqpcO8dy2VnAcKWv4RJculpGQVKXASiUbtzmeCl
         iqwVBdZXMxnCvlMP1vvftvYqx6iES8vfk/W3Ml4XUezhKzpAuED1rVCMuSlpboDHgbW5
         rrHiQSVbZ4ur/ovPxMJpYNtLWf4D1Jj1NY90m3AZKpzE/g8krQB2EwRSrCnq4pRrM8BX
         TiEkUNXuPEZQXW7gMHnYK0SZWKPSHQUj2bz0Dv4uPXXMjdONDAH6X6AR8P0/TM7RRWJy
         AcMY5Kf2fAbHiJRsHM58K876LKy7d0BF9gj28QuU3LeEWZ6CR0+592atU6D4gzN9C+5Y
         0PtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LKaqh+rM3TZJMG8ajYk9fLo3nTkfJC2JuU726+jgPd8=;
        b=FLR15wl74HA4ncHuky2euJ43rAbWd8yqM6WBhAmWuCeFp7p1EPbT/wNSwSEOJZn8SQ
         PV6wNAAMW8HHZ066me1BJwoK7RqetN7JPVnGxqZwsnwWlBnGjVNZiSQSe6wSCV2NwUQ3
         3o/Xb63bWzeuGBq8Zca9oOZsu7bOjZVfCJ8OO31uUcrtbKZo5XUw4M0zGyQwbQh/qMsv
         7rwXj/KZ72f7cjJJ/MqbHdqPHokCGKBcH2TrIUURUY4dFeGwg4Et/cr+N6k/p2OfYt7L
         8JtJT4U7RBeX50utwFTFXhorWrh/gluJ79i/FO+LpU+KIaeBohtH7B0OcYvM7RzhuyJw
         OR6w==
X-Gm-Message-State: AOAM530ZAPY4P7IR1UBESlvQ3nGMHAYnuWDT2gSCie2cYhiwIjZc35uI
	kOKoWWgz6qbxvw84Rp5U78A=
X-Google-Smtp-Source: ABdhPJzSSaOtF1X7OCprG4c+WHlePgiHcOb/1NAnfG6Ae/ad2tCwYvbVFkwfvShiTy8303WCaqZt9A==
X-Received: by 2002:a05:6830:14d0:: with SMTP id t16mr366612otq.362.1602708303936;
        Wed, 14 Oct 2020 13:45:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:c1:: with SMTP id t1ls83874oic.7.gmail; Wed, 14 Oct
 2020 13:45:03 -0700 (PDT)
X-Received: by 2002:a05:6808:1c8:: with SMTP id x8mr1120oic.100.1602708303595;
        Wed, 14 Oct 2020 13:45:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602708303; cv=none;
        d=google.com; s=arc-20160816;
        b=TfX/7l2M441bP2meOvB6wQ5l8fAaUV1L86hi8KtbS4/upLzDMSfK/NbgkMQsFXWicu
         W0CLGHSPIHly3O46zhW94BtdTVCN63hw+WqI7fiEAA/Kg5OSbh4UXa13uE+Yt0sguY0N
         PpIaoJttYZOByWPX7IBCcotrKm31ioKpSFvGui+kZdiM3wHduAm7ChIBEL9evDP6iPv1
         SZWX9y8miYu0DtuJrsYhzm3H5fxhvwObvTSu+RKbk7dZ/ZEd6P2uj8nMv2cJh6NtLpJg
         hZ0Y9yCGs4qB86hKu4ILcTO5J2N5s0vBcJ/6jl3Qqo+21hMDScvb+tBxiAmDIOD4KaK9
         WYHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=SUndFZwmd/UI7ffIXpzXKFFOW5Rrpznt5Bq+QYZ8r0w=;
        b=fEfu91+km5he7pgkYWgTafwbzmG2X1GaaZ677xWaFkrcQ4EfhLtnLithXD7RBEUgYW
         aEkMLrXNBqWr6dOCHz96HYm+iM/cyoaBCenkHXSnUz9rwhALfH4bmbqhkCTvOFeMTR/x
         DVwG1V9H7dbSgWLQBchQ2/HbueuY4eIejdWqpMRAqT08ElgtI1tyZED9hIR/HcBa5HNz
         CkDdyOcafIw9FLi0Ams+GT8EYDJUhueQBSfUhjeOxsGTolMUZkXAIFeM5uO19o56J+mW
         eB81olKEJau1uRS60+PVLbDllEyXkaCTpxp0MzMApK4FBr7C0jGBsSIFT+LGSicCmjlF
         8BzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=caicryyE;
       spf=pass (google.com: domain of 3tmohxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3TmOHXwoKCTUReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id r6si115468oth.4.2020.10.14.13.45.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Oct 2020 13:45:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tmohxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id h16so523352qtr.8
        for <kasan-dev@googlegroups.com>; Wed, 14 Oct 2020 13:45:03 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4f46:: with SMTP id
 eu6mr1409445qvb.9.1602708302995; Wed, 14 Oct 2020 13:45:02 -0700 (PDT)
Date: Wed, 14 Oct 2020 22:44:36 +0200
In-Reply-To: <cover.1602708025.git.andreyknvl@google.com>
Message-Id: <c44b27703fb2fa11029ecd92522a66988295dfb6.1602708025.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH RFC 8/8] kasan: add and integrate kasan_mode boot param
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=caicryyE;       spf=pass
 (google.com: domain of 3tmohxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3TmOHXwoKCTUReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
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

TODO: no meaningful description here yet, please see the cover letter
      for this RFC series.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/If7d37003875b2ed3e0935702c8015c223d6416a4
---
 mm/kasan/common.c  | 69 +++++++++++++++++++++++++---------------------
 mm/kasan/generic.c |  4 +++
 mm/kasan/hw_tags.c | 53 +++++++++++++++++++++++++++++++++++
 mm/kasan/kasan.h   |  8 ++++++
 mm/kasan/report.c  | 10 +++++--
 mm/kasan/sw_tags.c |  4 +++
 6 files changed, 115 insertions(+), 33 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a3e67d49b893..d642d5fce1e5 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -135,35 +135,37 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	unsigned int redzone_size;
 	int redzone_adjust;
 
-	/* Add alloc meta. */
-	cache->kasan_info.alloc_meta_offset = *size;
-	*size += sizeof(struct kasan_alloc_meta);
-
-	/* Add free meta. */
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC) &&
-	    (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
-	     cache->object_size < sizeof(struct kasan_free_meta))) {
-		cache->kasan_info.free_meta_offset = *size;
-		*size += sizeof(struct kasan_free_meta);
-	}
-
-	redzone_size = optimal_redzone(cache->object_size);
-	redzone_adjust = redzone_size -	(*size - cache->object_size);
-	if (redzone_adjust > 0)
-		*size += redzone_adjust;
-
-	*size = min_t(unsigned int, KMALLOC_MAX_SIZE,
-			max(*size, cache->object_size + redzone_size));
+	if (static_branch_unlikely(&kasan_debug)) {
+		/* Add alloc meta. */
+		cache->kasan_info.alloc_meta_offset = *size;
+		*size += sizeof(struct kasan_alloc_meta);
+
+		/* Add free meta. */
+		if (IS_ENABLED(CONFIG_KASAN_GENERIC) &&
+		    (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
+		     cache->object_size < sizeof(struct kasan_free_meta))) {
+			cache->kasan_info.free_meta_offset = *size;
+			*size += sizeof(struct kasan_free_meta);
+		}
 
-	/*
-	 * If the metadata doesn't fit, don't enable KASAN at all.
-	 */
-	if (*size <= cache->kasan_info.alloc_meta_offset ||
-			*size <= cache->kasan_info.free_meta_offset) {
-		cache->kasan_info.alloc_meta_offset = 0;
-		cache->kasan_info.free_meta_offset = 0;
-		*size = orig_size;
-		return;
+		redzone_size = optimal_redzone(cache->object_size);
+		redzone_adjust = redzone_size -	(*size - cache->object_size);
+		if (redzone_adjust > 0)
+			*size += redzone_adjust;
+
+		*size = min_t(unsigned int, KMALLOC_MAX_SIZE,
+				max(*size, cache->object_size + redzone_size));
+
+		/*
+		 * If the metadata doesn't fit, don't enable KASAN at all.
+		 */
+		if (*size <= cache->kasan_info.alloc_meta_offset ||
+				*size <= cache->kasan_info.free_meta_offset) {
+			cache->kasan_info.alloc_meta_offset = 0;
+			cache->kasan_info.free_meta_offset = 0;
+			*size = orig_size;
+			return;
+		}
 	}
 
 	*flags |= SLAB_KASAN;
@@ -180,6 +182,7 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
 struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
 					      const void *object)
 {
+	WARN_ON(!static_branch_unlikely(&kasan_debug));
 	return (void *)reset_tag(object) + cache->kasan_info.alloc_meta_offset;
 }
 
@@ -187,6 +190,7 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 					    const void *object)
 {
 	BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
+	WARN_ON(!static_branch_unlikely(&kasan_debug));
 	return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
 }
 
@@ -266,8 +270,10 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 	if (!(cache->flags & SLAB_KASAN))
 		return (void *)object;
 
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	__memset(alloc_meta, 0, sizeof(*alloc_meta));
+	if (static_branch_unlikely(&kasan_debug)) {
+		alloc_meta = kasan_get_alloc_meta(cache, object);
+		__memset(alloc_meta, 0, sizeof(*alloc_meta));
+	}
 
 	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
 		object = set_tag(object, assign_tag(cache, object, true, false));
@@ -305,6 +311,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	kasan_poison_memory(object, rounded_up_size, KASAN_KMALLOC_FREE);
 
 	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
+			!static_branch_unlikely(&kasan_debug) ||
 			unlikely(!(cache->flags & SLAB_KASAN)))
 		return false;
 
@@ -351,7 +358,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
 		KASAN_KMALLOC_REDZONE);
 
-	if (cache->flags & SLAB_KASAN)
+	if (static_branch_unlikely(&kasan_debug) && cache->flags & SLAB_KASAN)
 		set_alloc_info(cache, (void *)object, flags);
 
 	return set_tag(object, tag);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index d259e4c3aefd..9d968eaedc98 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -33,6 +33,10 @@
 #include "kasan.h"
 #include "../slab.h"
 
+/* See the comments in hw_tags.c */
+DEFINE_STATIC_KEY_TRUE_RO(kasan_enabled);
+DEFINE_STATIC_KEY_TRUE_RO(kasan_debug);
+
 /*
  * All functions below always inlined so compiler could
  * perform better optimizations in each of __asan_loadX/__assn_storeX
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index b372421258c8..fc6ab1c8b155 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -8,6 +8,8 @@
 
 #define pr_fmt(fmt) "kasan: " fmt
 
+#include <linux/init.h>
+#include <linux/jump_label.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
 #include <linux/memory.h>
@@ -17,8 +19,57 @@
 
 #include "kasan.h"
 
+enum kasan_mode {
+	KASAN_MODE_OFF,
+	KASAN_MODE_ON,
+	KASAN_MODE_DEBUG,
+};
+
+static enum kasan_mode kasan_mode __ro_after_init;
+
+/* Whether KASAN is enabled at all. */
+/* TODO: ideally no KASAN callbacks when this is disabled. */
+DEFINE_STATIC_KEY_FALSE_RO(kasan_enabled);
+
+/* Whether to collect debugging info, e.g. alloc/free stack traces. */
+DEFINE_STATIC_KEY_FALSE_RO(kasan_debug);
+
+/* Whether to use syncronous or asynchronous tag checking. */
+static bool kasan_sync __ro_after_init;
+
+static int __init early_kasan_mode(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (strcmp(arg, "on") == 0)
+		kasan_mode = KASAN_MODE_ON;
+	else if (strcmp(arg, "debug") == 0)
+		kasan_mode = KASAN_MODE_DEBUG;
+	return 0;
+}
+early_param("kasan_mode", early_kasan_mode);
+
 void __init kasan_init_tags(void)
 {
+	/* TODO: system_supports_tags() always returns 0 here, fix. */
+	if (0 /*!system_supports_tags()*/)
+		return;
+
+	switch (kasan_mode) {
+	case KASAN_MODE_OFF:
+		return;
+	case KASAN_MODE_ON:
+		static_branch_enable(&kasan_enabled);
+		break;
+	case KASAN_MODE_DEBUG:
+		static_branch_enable(&kasan_enabled);
+		static_branch_enable(&kasan_debug);
+		kasan_sync = true;
+		break;
+	}
+
+	/* TODO: choose between sync and async based on kasan_sync. */
 	init_tags(KASAN_TAG_MAX);
 
 	pr_info("KernelAddressSanitizer initialized\n");
@@ -60,6 +111,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
 {
 	struct kasan_alloc_meta *alloc_meta;
 
+	WARN_ON(!static_branch_unlikely(&kasan_debug));
 	alloc_meta = kasan_get_alloc_meta(cache, object);
 	kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
 }
@@ -69,6 +121,7 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 {
 	struct kasan_alloc_meta *alloc_meta;
 
+	WARN_ON(!static_branch_unlikely(&kasan_debug));
 	alloc_meta = kasan_get_alloc_meta(cache, object);
 	return &alloc_meta->free_track[0];
 }
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 47d6074c7958..3712e7a39717 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -279,6 +279,14 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define get_mem_tag(addr)			arch_get_mem_tag(addr)
 #define set_mem_tag_range(addr, size, tag)	arch_set_mem_tag_range((addr), (size), (tag))
 
+#ifdef CONFIG_KASAN_HW_TAGS
+DECLARE_STATIC_KEY_FALSE(kasan_enabled);
+DECLARE_STATIC_KEY_FALSE(kasan_debug);
+#else
+DECLARE_STATIC_KEY_TRUE(kasan_enabled);
+DECLARE_STATIC_KEY_TRUE(kasan_debug);
+#endif
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index dee5350b459c..ae956a29ad4e 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -159,8 +159,8 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
 		(void *)(object_addr + cache->object_size));
 }
 
-static void describe_object(struct kmem_cache *cache, void *object,
-				const void *addr, u8 tag)
+static void describe_object_stacks(struct kmem_cache *cache, void *object,
+					const void *addr, u8 tag)
 {
 	struct kasan_alloc_meta *alloc_meta = kasan_get_alloc_meta(cache, object);
 
@@ -188,7 +188,13 @@ static void describe_object(struct kmem_cache *cache, void *object,
 		}
 #endif
 	}
+}
 
+static void describe_object(struct kmem_cache *cache, void *object,
+				const void *addr, u8 tag)
+{
+	if (static_branch_unlikely(&kasan_debug))
+		describe_object_stacks(cache, object, addr, tag);
 	describe_object_addr(cache, object, addr);
 }
 
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 099af6dc8f7e..50e797a16e17 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -33,6 +33,10 @@
 #include "kasan.h"
 #include "../slab.h"
 
+/* See the comments in hw_tags.c */
+DEFINE_STATIC_KEY_TRUE_RO(kasan_enabled);
+DEFINE_STATIC_KEY_TRUE_RO(kasan_debug);
+
 static DEFINE_PER_CPU(u32, prng_state);
 
 void __init kasan_init_tags(void)
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c44b27703fb2fa11029ecd92522a66988295dfb6.1602708025.git.andreyknvl%40google.com.
