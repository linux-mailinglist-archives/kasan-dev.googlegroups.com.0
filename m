Return-Path: <kasan-dev+bncBAABBNOJ3GMAMGQELYEDDLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id D2F355ADA8C
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:06:02 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id v21-20020a05600c215500b003a83c910d83sf1937286wml.3
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:06:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662411957; cv=pass;
        d=google.com; s=arc-20160816;
        b=rU6zVXsVpk1VzT153RSMWgc7jS3hFppC03ONgHtxbiyr+y/QzmGIEw+SE9wwlvbZko
         v+/8SWo5H8oDlVoaG6xQXGo+4Adk5mLjS0iixpdWOGo0MjLrnJZ81W/n5RFpC0zMjzq5
         CbgfVZqCxV36yzAVs+soUrVkhB3P7wMwcAJ5PdDuOv/PdnwdPcW/dTtt3f1alE1bVzyD
         T5Oh7yDf/ezrrGRC0U8TqOCcveKxTG0z9o6xOE5pOslJ3ayd4agsOlL4XKfeIbE/lOEs
         mrM+EAY8jO66eRh4NyEWnaKRSk0XPWXqB/0SN3eyJZYh80khFx1nRqzz60huUcwNbi2U
         Lnmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+VEICwD0nICXp8R29s0a2v+FN6YSu1qz8rPYZcaAfA4=;
        b=WJrYjW+nuyV884aQSznpp2ruRqlUIdfv8m4JKxP2yqSW0aDa3z3JCX+oGw8cbODEaZ
         aybKnX9lUdn6gLHMxmciOQlnMGJznPcuvyNuxNzkmAV+OiVocXxNNPM4y1Mtx2vzDuC4
         CgZRW7rkFhkglgaUj2d61mqIbbn1mw48FGYzZdcaz3d5fp4SCWBDiPVlk5WKwXf3FhXF
         ZzyHDs7YNc2u+9wLVnMlqaakt9Yel9CQO1tFPk2aUloPbxvLQwyjkCxT8qMc9n7v9szV
         A/iUrlRhuKmScDG3L/nZq6TqFt1K+dv5TUlFkZvdqU/wmyBnPxoIAx+l0NpXsC2oWoqW
         SQ5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=d4ge2iXO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=+VEICwD0nICXp8R29s0a2v+FN6YSu1qz8rPYZcaAfA4=;
        b=UTegBOs4Tmodcl6XctuRIjN2YTIoF5jfPGhHW5p6LwaWcV/auQ4CjkaUhYlr9khXGt
         huKxp82lQtAfIhPJrFhDiXuMCxPXPrHoSE29cb+QwCYxsDQwqVBdaVfFDMMsF+vBv5WZ
         kjYbxRtdfwJFrpJvkjxrasZmqgsdChTjAzx12jICe0c00QY6kfuWXUugedOYfNCDJw35
         rMxyScjF7Ezq0mUh/JO6QUC7LuVkeWTOInRACZVIu1ZnpqGPYCLVZ0GBLD68dxNKTLBZ
         /1Ij5eVdgeYRtbhG96u2LTsNoSQu4zmVf3FnGlZcwzsvPokZoNIDm/4ZxkKNWdsaw+pY
         Ps4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=+VEICwD0nICXp8R29s0a2v+FN6YSu1qz8rPYZcaAfA4=;
        b=wK0N8lNOUtYJRQT66AxWtDFeXlcKuDY+l+erm09Thfxmfu0kzNmVgNOFw+EI0tAajN
         +gDcwOorgiT5v8NrciENPEW6xE6CZ1VxzkPuuVMxq1JOhYyiaQHFPf1vZGYxDo71n1aP
         3A192XvL0E2q2gCV5naPWgNiYuFB2ux033jmGiq9vCEypQV+kZ+5s53ugQLOqr46reRG
         Ujn0SVthtHEGz98qydvZseQhhQTO1xlAPgeVoycdjWaJatdPveffpnclKivKpyko3l1l
         rMh0Qw/LECehDDMVM2lyujw7g9rCHzq+4fjRjtWAYAPArX7PV3hey1VQlYDK3V6Iq8zo
         AUzA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1Ky3RL5W8pVNNu/Vv/EWLQT3NrzxyQxIt7lJxBIIAqJnbr5nGQ
	ODZOK2hSIN/ykXCgBTzQZ2I=
X-Google-Smtp-Source: AA6agR60iocpqK66arE9edQWe53hmXfFr1r8so68Nfh8Bazs6uT6NOAvYlTHmgN7MbJW094Dy1h2DQ==
X-Received: by 2002:a5d:6c62:0:b0:222:c8cd:2b8 with SMTP id r2-20020a5d6c62000000b00222c8cd02b8mr24726701wrz.124.1662411957583;
        Mon, 05 Sep 2022 14:05:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:60c7:0:b0:228:c8fc:9de8 with SMTP id x7-20020a5d60c7000000b00228c8fc9de8ls191761wrt.1.-pod-prod-gmail;
 Mon, 05 Sep 2022 14:05:56 -0700 (PDT)
X-Received: by 2002:a5d:66ce:0:b0:228:a430:673f with SMTP id k14-20020a5d66ce000000b00228a430673fmr3021718wrw.355.1662411956872;
        Mon, 05 Sep 2022 14:05:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662411956; cv=none;
        d=google.com; s=arc-20160816;
        b=NDi8QFS8OECu0VJntQ1l1F2+343m3RokuJnqFpFnoCouWdjbn+4tEFAjo+4sDm+KIC
         Jaj9g4997qSBKiZCWbSp0dorSNPOu+AhiVvvbSMLH7pwvf7bsUQDej4luvX+ispQMZl9
         TfQhDj4yElIPA4e6pDUDou9DQhIYUxAMiCKSAtYbJWPw0AtjWvIuosr/TQBVnbEYW1D/
         ZhrOiSth+2B2TZSkSkG59pAT21cA1fxFUepNH8N/RBxwfb/rgq2JlX2rwDMSn927dSNI
         EkRoFtoLUX3ZuFyAJGC/OTQ2CCFYYMZQM/YcMYtBhEpjjpHq7IAu/t/BWe1ZqxT6dwvS
         6kqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=btqlB1PcyI2oEVK30B4u2+ZtYIXUDjtBMu4es4RldM8=;
        b=fYVu2ZN5nj0LRZhU86Ew2LjBkD9wUStMgT5vbc56eIg85UStNAVx6C/vEUkIUreidJ
         kAynnvbjsjC5RDV9QU5nwCkgkHeIRkn8cH0bcC8Kbhg5XxoSIO0PL9xq+WY/tm8H4pOc
         zvajSmeTHgnpmZdEJSFfQd9vCsaFLfJ+TDW0FNbs3imuSKkbbF8NwgwAyiN3DAnfx63L
         nkpuTa7i4LFoBhHaM/GB9FI87qS6QWHTuKqPTEfGBmKzrMTE4jBILRh5WE7m1MRStF6M
         mMNv1QNBr8vugzOxnVqFyuyC5dpI6NbvKJHJ7E1RjfY26uG6K1nMlZo0I65TZt063Uk5
         4y9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=d4ge2iXO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id p11-20020a5d59ab000000b0021e8b3a5ffesi272121wrr.2.2022.09.05.14.05.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:05:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 05/34] kasan: drop CONFIG_KASAN_TAGS_IDENTIFY
Date: Mon,  5 Sep 2022 23:05:20 +0200
Message-Id: <4c66ba98eb237e9ed9312c19d423bbcf4ecf88f8.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=d4ge2iXO;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Drop CONFIG_KASAN_TAGS_IDENTIFY and related code to simplify making
changes to the reporting code.

The dropped functionality will be restored in the following patches in
this series.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/Kconfig.kasan      |  8 --------
 mm/kasan/kasan.h       | 12 +-----------
 mm/kasan/report_tags.c | 28 ----------------------------
 mm/kasan/tags.c        | 21 ++-------------------
 4 files changed, 3 insertions(+), 66 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index f0973da583e0..ca09b1cf8ee9 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -167,14 +167,6 @@ config KASAN_STACK
 	  as well, as it adds inline-style instrumentation that is run
 	  unconditionally.
 
-config KASAN_TAGS_IDENTIFY
-	bool "Memory corruption type identification"
-	depends on KASAN_SW_TAGS || KASAN_HW_TAGS
-	help
-	  Enables best-effort identification of the bug types (use-after-free
-	  or out-of-bounds) at the cost of increased memory consumption.
-	  Only applicable for the tag-based KASAN modes.
-
 config KASAN_VMALLOC
 	bool "Check accesses to vmalloc allocations"
 	depends on HAVE_ARCH_KASAN_VMALLOC
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index d401fb770f67..15c718782c1f 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -169,23 +169,13 @@ struct kasan_track {
 	depot_stack_handle_t stack;
 };
 
-#if defined(CONFIG_KASAN_TAGS_IDENTIFY) && defined(CONFIG_KASAN_SW_TAGS)
-#define KASAN_NR_FREE_STACKS 5
-#else
-#define KASAN_NR_FREE_STACKS 1
-#endif
-
 struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
 	/* Generic mode stores free track in kasan_free_meta. */
 #ifdef CONFIG_KASAN_GENERIC
 	depot_stack_handle_t aux_stack[2];
 #else
-	struct kasan_track free_track[KASAN_NR_FREE_STACKS];
-#endif
-#ifdef CONFIG_KASAN_TAGS_IDENTIFY
-	u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
-	u8 free_track_idx;
+	struct kasan_track free_track;
 #endif
 };
 
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index e25d2166e813..35cf3cae4aa4 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -5,37 +5,9 @@
  */
 
 #include "kasan.h"
-#include "../slab.h"
 
 const char *kasan_get_bug_type(struct kasan_report_info *info)
 {
-#ifdef CONFIG_KASAN_TAGS_IDENTIFY
-	struct kasan_alloc_meta *alloc_meta;
-	struct kmem_cache *cache;
-	struct slab *slab;
-	const void *addr;
-	void *object;
-	u8 tag;
-	int i;
-
-	tag = get_tag(info->access_addr);
-	addr = kasan_reset_tag(info->access_addr);
-	slab = kasan_addr_to_slab(addr);
-	if (slab) {
-		cache = slab->slab_cache;
-		object = nearest_obj(cache, slab, (void *)addr);
-		alloc_meta = kasan_get_alloc_meta(cache, object);
-
-		if (alloc_meta) {
-			for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
-				if (alloc_meta->free_pointer_tag[i] == tag)
-					return "use-after-free";
-			}
-		}
-		return "out-of-bounds";
-	}
-#endif
-
 	/*
 	 * If access_size is a negative number, then it has reason to be
 	 * defined as out-of-bounds bug type.
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 1ba3c8399f72..e0e5de8ce834 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -30,39 +30,22 @@ void kasan_save_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
 	struct kasan_alloc_meta *alloc_meta;
-	u8 idx = 0;
 
 	alloc_meta = kasan_get_alloc_meta(cache, object);
 	if (!alloc_meta)
 		return;
 
-#ifdef CONFIG_KASAN_TAGS_IDENTIFY
-	idx = alloc_meta->free_track_idx;
-	alloc_meta->free_pointer_tag[idx] = tag;
-	alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
-#endif
-
-	kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
+	kasan_set_track(&alloc_meta->free_track, GFP_NOWAIT);
 }
 
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
 	struct kasan_alloc_meta *alloc_meta;
-	int i = 0;
 
 	alloc_meta = kasan_get_alloc_meta(cache, object);
 	if (!alloc_meta)
 		return NULL;
 
-#ifdef CONFIG_KASAN_TAGS_IDENTIFY
-	for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
-		if (alloc_meta->free_pointer_tag[i] == tag)
-			break;
-	}
-	if (i == KASAN_NR_FREE_STACKS)
-		i = alloc_meta->free_track_idx;
-#endif
-
-	return &alloc_meta->free_track[i];
+	return &alloc_meta->free_track;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4c66ba98eb237e9ed9312c19d423bbcf4ecf88f8.1662411799.git.andreyknvl%40google.com.
