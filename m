Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2O4ZCWQMGQEVMLRFLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D0DE83BDCE
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jan 2024 10:48:27 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-5101569ed09sf849442e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jan 2024 01:48:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706176106; cv=pass;
        d=google.com; s=arc-20160816;
        b=lkNotUL5f2EF3FmCwNYLDMWrySRn0oaxbsZNl4oLNfqHq7TFuojHCgwGhPjAjP5+5k
         GbBhWDUlo7nHDK586d23wFG+Icw24x6bpfxkQuEsfD/jcRuiGMAZIwW1r9Dpn3/lgZAJ
         r3VGmBsvT6xcJ4pjYHN6UA2x1aADxO7WWqXmrlgY7cMx2I0kPxmnTrEPu+6AEXgM0iZJ
         aXh9SamODfAbY7YSmUpFdElv+iZqsNMlkXw1Q/dmlk8S7MPds8IrDuS4uYPnuNniA9I9
         pQtVU5T/+5HCdSw9Ug92+Pm5Dg6h+r3AqVqvWgtiHCA/wxy1OnxVnBAnutIkPe4BQVop
         jLFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=44VcUGon4fQNI/XeVjFWuRY8WFDQzOP5ed1xIGF7lRE=;
        fh=Q6WTJ5ZnjiuB6HF3Kna6PPHtjylj1os0kvM6d8ajbeE=;
        b=s32/P9jmWCzArkhaHi3jZBYfkcterRQ22mtt7gcHBog0y6QgzwhGUb7fJCaVwtHV+X
         2U3kR2/9g+rPcdVP87CvvLpa8545u21n2P22XvbBbaalyKN1Pw/rYhI6LWdCWMtDXUaP
         llpu7bbS5Ykp+CiUd2xBCBwxy1uMCtDPLc+WvFB4XcErQ5Ma0C+wOjbLsoxC7gj8tXb4
         LP98FN8KXmx+/5moVPM/3WSjWqIISW6RPKACMCU5vwjQzAYuaXgOCZvf0sEXwfeX1sCt
         5JEP/9/YS9exNUZC6LdrQNebTkEa7Lt6XtRVnFYd4UQKjgE4PSLe2YyMhPrDKgufgh7A
         qyrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Zimw18nw;
       spf=pass (google.com: domain of 3zy6yzqukccakr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Zy6yZQUKCcAkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706176106; x=1706780906; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=44VcUGon4fQNI/XeVjFWuRY8WFDQzOP5ed1xIGF7lRE=;
        b=cOiuIojrDBy8+xmeOHA6jOpPLouZt0kOS4o5AWkM+kypDHEY/+3wmh+ARkdM/6U9Z5
         0oY5rrY8qiVJOqGiTQi4A5K3wMlSDO+tGdhqWqzJZpkhyECnCA6rv3Nb3QygpUrKUcOD
         5Sxr1LcNLJlBcrPIqCWEWnowz2SgKdf5rR2qDeds/nmiTJ0LlNiuUCfZYMj0J+oTTE7B
         yVUNdlUQml03FrpDWwMdVpjthhN38y5uHSGgTXKR1aWclJfBoWVY4ROm4boDYvbykXoU
         ND3uPj3XxrnWQxYjHmbBJHKMxVr1Xm3/xZDQlS8IWBemu8hpEHx3zeQVczOWOWkji6R9
         kWtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706176106; x=1706780906;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=44VcUGon4fQNI/XeVjFWuRY8WFDQzOP5ed1xIGF7lRE=;
        b=F31Sr0FISZNg90es80o/3YGJRv/4qOmAk+y8sStzz0+f4iqtpKj+N3wjGrWPBI0bho
         8nEUnu+Fiqplts9wZILlMXlBecZdpdjNL6/IJCjIPDNzdw1h/eOClxmIY82yeTiL8X4v
         1oOopzDNOCk4MCHU++vIjIFBN8eJidqoYkgc5ln0J7BiXOZ743LuTR4G48chYFKiYahX
         xlzRx/ysu+4w2/vKiU483+QUEG5I/OyBKCEcC0xhhPCc2MYcTGZobrdxMSbrsm3z3/1X
         R1MnDrcCZWj+PRewejrcrOaFLIaVe5cD9PfLrOG5HSzkh9voOl65xj8ITvPZ2YDsN0My
         dqWA==
X-Gm-Message-State: AOJu0YxTObwF0Utjp4pvfGHDybMMZrJWjNH2sbnL2bCubdg/gsJqhTon
	hRnRpBYGtAMmTo8cwaUPu0VzK4nfpbvWxQIoyslBwtkZdiS5zH9B
X-Google-Smtp-Source: AGHT+IFApq8uqlnQrSvDKYVYK6kTUx9Gy9+3VFlpN41TmOGWtj82LXnzp+M8Ow4DgTptFZNVfbISjQ==
X-Received: by 2002:ac2:5611:0:b0:510:c7d:8cdf with SMTP id v17-20020ac25611000000b005100c7d8cdfmr345703lfd.101.1706176105998;
        Thu, 25 Jan 2024 01:48:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:20d0:b0:510:20d3:5d7f with SMTP id
 u16-20020a05651220d000b0051020d35d7fls51463lfr.1.-pod-prod-01-eu; Thu, 25 Jan
 2024 01:48:24 -0800 (PST)
X-Received: by 2002:a05:6512:3190:b0:50e:b25e:94d8 with SMTP id i16-20020a056512319000b0050eb25e94d8mr413201lfe.41.1706176103770;
        Thu, 25 Jan 2024 01:48:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706176103; cv=none;
        d=google.com; s=arc-20160816;
        b=IxgBphiH7AX8JwSGikRVq1897aYsdnZyhFnxo/QPzooOOlMBnxRcTs5vB+8cssgBPE
         X9kDLcJfFmR0IpF63U5/MLav9/90xWJLp3PDqh1bKAPSqwto3P02jtjEzUzKudeG6//L
         YCS0Xug1tnXhT1pNe6Wb3264wmVYUuFBBuzPUgQc8EdHXsGjgQovgKJAtYzJgJ9U+FIw
         7//b4nd7kYiOfm4OE1ZOEvdl5SzSy/vKXsHnroU5ugSA9i3wrzFI4SHQ21u+XzyZ6Qfw
         NuzTkkzElYKnkfT3cQo/cxlcqlZ6KqwfTUuhIdcMqx4PVj2MMWBGzAsA5O6voQRBfKg0
         gHbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=R76x7/0RnR583W2gtQWaNlBYwLgRcgwa4b5YYEtfgyM=;
        fh=Q6WTJ5ZnjiuB6HF3Kna6PPHtjylj1os0kvM6d8ajbeE=;
        b=oFxJdxF7h0KqIwdcUlS248o4MjL21/3h8Z01y9faOjT2D0Q40lZvVbI/zCgi0qhV67
         MFhpsYOUtgvhVwyFS35QltZbWDhKhokAUarY3Rf3yetCeueX2sKfeJr0wYZ+Z2haIpBJ
         pAQB4NswsH9F6HChgBh9eCPVZ9F0AfJ+SE2l/gSg6esQyvPBb+9TWxO1Dzs3fltQy3Bp
         ww8dmfsXI6iUB0QarFk7zjgWLKNKMHOCenU8/XF/tEB2sDnlF78Ywgwf8lvIjkKbn/Su
         TIWBlJpxjJJA7l6tyk0ocf9GFzEl3hhkVXdSGXo8zSPqPyUqu8jyJLaIwddgCWnpYuqh
         Neiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Zimw18nw;
       spf=pass (google.com: domain of 3zy6yzqukccakr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Zy6yZQUKCcAkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id k19-20020ac24f13000000b005100ff746absi135105lfr.10.2024.01.25.01.48.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Jan 2024 01:48:23 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zy6yzqukccakr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-a2c4e9cb449so371058966b.1
        for <kasan-dev@googlegroups.com>; Thu, 25 Jan 2024 01:48:23 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:57d7:c308:70aa:3dee])
 (user=elver job=sendgmr) by 2002:a17:907:c24d:b0:a31:747c:b3c7 with SMTP id
 tj13-20020a170907c24d00b00a31747cb3c7mr4623ejc.3.1706176103117; Thu, 25 Jan
 2024 01:48:23 -0800 (PST)
Date: Thu, 25 Jan 2024 10:47:43 +0100
In-Reply-To: <20240125094815.2041933-1-elver@google.com>
Mime-Version: 1.0
References: <20240125094815.2041933-1-elver@google.com>
X-Mailer: git-send-email 2.43.0.429.g432eaa2c6b-goog
Message-ID: <20240125094815.2041933-2-elver@google.com>
Subject: [PATCH 2/2] kasan: revert eviction of stack traces in generic mode
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Zimw18nw;       spf=pass
 (google.com: domain of 3zy6yzqukccakr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Zy6yZQUKCcAkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

This partially reverts commits cc478e0b6bdf, 63b85ac56a64, 08d7c94d9635,
a414d4286f34, and 773688a6cb24 to make use of variable-sized stack depot
records, since eviction of stack entries from stack depot forces fixed-
sized stack records. Care was taken to retain the code cleanups by the
above commits.

Eviction was added to generic KASAN as a response to alleviating the
additional memory usage from fixed-sized stack records, but this still
uses more memory than previously.

With the re-introduction of variable-sized records for stack depot, we
can just switch back to non-evictable stack records again, and return
back to the previous performance and memory usage baseline.

Before (observed after a KASAN kernel boot):

  pools: 597
  allocations: 29657
  frees: 6425
  in_use: 23232
  freelist_size: 3493

After:

  pools: 315
  allocations: 28964
  frees: 0
  in_use: 28964
  freelist_size: 0

As can be seen from the number of "frees", with a generic KASAN config,
evictions are no longer used but due to using variable-sized records, I
observe a reduction of 282 stack depot pools (saving 4512 KiB) with my
test setup.

Fixes: cc478e0b6bdf ("kasan: avoid resetting aux_lock")
Fixes: 63b85ac56a64 ("kasan: stop leaking stack trace handles")
Fixes: 08d7c94d9635 ("kasan: memset free track in qlink_free")
Fixes: a414d4286f34 ("kasan: handle concurrent kasan_record_aux_stack calls")
Fixes: 773688a6cb24 ("kasan: use stack_depot_put for Generic mode")
Signed-off-by: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
---
 mm/kasan/common.c  |  3 +--
 mm/kasan/generic.c | 54 ++++++----------------------------------------
 mm/kasan/kasan.h   |  8 -------
 3 files changed, 8 insertions(+), 57 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 610efae91220..ad32803e34e9 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -65,8 +65,7 @@ void kasan_save_track(struct kasan_track *track, gfp_t flags)
 {
 	depot_stack_handle_t stack;
 
-	stack = kasan_save_stack(flags,
-			STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
+	stack = kasan_save_stack(flags, STACK_DEPOT_FLAG_CAN_ALLOC);
 	kasan_set_track(track, stack);
 }
 
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index df6627f62402..8bfb52b28c22 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -485,16 +485,6 @@ void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
 	if (alloc_meta) {
 		/* Zero out alloc meta to mark it as invalid. */
 		__memset(alloc_meta, 0, sizeof(*alloc_meta));
-
-		/*
-		 * Prepare the lock for saving auxiliary stack traces.
-		 * Temporarily disable KASAN bug reporting to allow instrumented
-		 * raw_spin_lock_init to access aux_lock, which resides inside
-		 * of a redzone.
-		 */
-		kasan_disable_current();
-		raw_spin_lock_init(&alloc_meta->aux_lock);
-		kasan_enable_current();
 	}
 
 	/*
@@ -506,18 +496,8 @@ void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
 
 static void release_alloc_meta(struct kasan_alloc_meta *meta)
 {
-	/* Evict the stack traces from stack depot. */
-	stack_depot_put(meta->alloc_track.stack);
-	stack_depot_put(meta->aux_stack[0]);
-	stack_depot_put(meta->aux_stack[1]);
-
-	/*
-	 * Zero out alloc meta to mark it as invalid but keep aux_lock
-	 * initialized to avoid having to reinitialize it when another object
-	 * is allocated in the same slot.
-	 */
-	__memset(&meta->alloc_track, 0, sizeof(meta->alloc_track));
-	__memset(meta->aux_stack, 0, sizeof(meta->aux_stack));
+	/* Zero out alloc meta to mark it as invalid. */
+	__memset(meta, 0, sizeof(*meta));
 }
 
 static void release_free_meta(const void *object, struct kasan_free_meta *meta)
@@ -526,9 +506,6 @@ static void release_free_meta(const void *object, struct kasan_free_meta *meta)
 	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREE_META)
 		return;
 
-	/* Evict the stack trace from the stack depot. */
-	stack_depot_put(meta->free_track.stack);
-
 	/* Mark free meta as invalid. */
 	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREE;
 }
@@ -571,8 +548,6 @@ static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
 	struct kmem_cache *cache;
 	struct kasan_alloc_meta *alloc_meta;
 	void *object;
-	depot_stack_handle_t new_handle, old_handle;
-	unsigned long flags;
 
 	if (is_kfence_address(addr) || !slab)
 		return;
@@ -583,33 +558,18 @@ static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
 	if (!alloc_meta)
 		return;
 
-	new_handle = kasan_save_stack(0, depot_flags);
-
-	/*
-	 * Temporarily disable KASAN bug reporting to allow instrumented
-	 * spinlock functions to access aux_lock, which resides inside of a
-	 * redzone.
-	 */
-	kasan_disable_current();
-	raw_spin_lock_irqsave(&alloc_meta->aux_lock, flags);
-	old_handle = alloc_meta->aux_stack[1];
 	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
-	alloc_meta->aux_stack[0] = new_handle;
-	raw_spin_unlock_irqrestore(&alloc_meta->aux_lock, flags);
-	kasan_enable_current();
-
-	stack_depot_put(old_handle);
+	alloc_meta->aux_stack[0] = kasan_save_stack(0, depot_flags);
 }
 
 void kasan_record_aux_stack(void *addr)
 {
-	return __kasan_record_aux_stack(addr,
-			STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
+	return __kasan_record_aux_stack(addr, STACK_DEPOT_FLAG_CAN_ALLOC);
 }
 
 void kasan_record_aux_stack_noalloc(void *addr)
 {
-	return __kasan_record_aux_stack(addr, STACK_DEPOT_FLAG_GET);
+	return __kasan_record_aux_stack(addr, 0);
 }
 
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
@@ -620,7 +580,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 	if (!alloc_meta)
 		return;
 
-	/* Evict previous stack traces (might exist for krealloc or mempool). */
+	/* Invalidate previous stack traces (might exist for krealloc or mempool). */
 	release_alloc_meta(alloc_meta);
 
 	kasan_save_track(&alloc_meta->alloc_track, flags);
@@ -634,7 +594,7 @@ void kasan_save_free_info(struct kmem_cache *cache, void *object)
 	if (!free_meta)
 		return;
 
-	/* Evict previous stack trace (might exist for mempool). */
+	/* Invalidate previous stack trace (might exist for mempool). */
 	release_free_meta(object, free_meta);
 
 	kasan_save_track(&free_meta->free_track, 0);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index d0f172f2b978..216ae0ef1e4b 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -6,7 +6,6 @@
 #include <linux/kasan.h>
 #include <linux/kasan-tags.h>
 #include <linux/kfence.h>
-#include <linux/spinlock.h>
 #include <linux/stackdepot.h>
 
 #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
@@ -265,13 +264,6 @@ struct kasan_global {
 struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
 	/* Free track is stored in kasan_free_meta. */
-	/*
-	 * aux_lock protects aux_stack from accesses from concurrent
-	 * kasan_record_aux_stack calls. It is a raw spinlock to avoid sleeping
-	 * on RT kernels, as kasan_record_aux_stack_noalloc can be called from
-	 * non-sleepable contexts.
-	 */
-	raw_spinlock_t aux_lock;
 	depot_stack_handle_t aux_stack[2];
 };
 
-- 
2.43.0.429.g432eaa2c6b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240125094815.2041933-2-elver%40google.com.
