Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVPR3WWQMGQE64VMRAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C07D840261
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 11:07:19 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-55a471a29fbsf667933a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 02:07:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706522838; cv=pass;
        d=google.com; s=arc-20160816;
        b=XPiP5nkEDSinOEzOawStLlDqqTh5slLvWlE3IRh8SVmW68EOC2Fk+wjfkxNNVbv8Im
         LDC0VYsynNc4uVQp73/dsJcgJQkiECp5BJwJ7/SveygTZTle6l8BCSGnq8FxqYtTxu3m
         9I3hur70LEL2ZO44Uc6+eble8U/CqxL8k1pNQRlH84HHtBc3qAv64EoclVALNg0j/7ZY
         Wd0jvooBxw62lqII2naakZ7fT3ZeZSdvLEcvcwFROb4zrWcO4IX1+SvabiqclpT/KPUI
         fQbynZ+l7/fvODlcIt+ISqu0z8idmESoB6myqZCIdYeJVszO8kzV9WhIZ5OG1MVrzla6
         p+dQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=mt1nFNOGDFJajOdbsP0eCeroFNJ5EYGYfF3+cfplnG8=;
        fh=Q6WTJ5ZnjiuB6HF3Kna6PPHtjylj1os0kvM6d8ajbeE=;
        b=EhGqQBAA6q4e2HHv74wM/gzf2GoD4OvM8mymcF2LIt5AvKkzGVyyoWPSotuwaSM8l+
         Z8Pj4Hf51p9CwIEXv8m474yb3/0luyYzwPIg1Lxv1Fn7pKOm5KUu6NSJPEL3HEWTwPps
         HxU94WWaAFLkeL2Cx9K8bYYy6CYeDBSQ8x9tmTV68yQeaUyQMVjXHlQoIhEkChoyn9oi
         XTYpghSTsQiJPDJbv3wUnQcsD3trak7KsaMD3xlnabtiRcwzU6u93hFpbIiSXSk5qu+9
         6xNg/eA+kTLHYvjWtDz3bPawTbvX6/2mYTcNuacwpF/yKV/NkTvkiMRbqz70AMzZ9gIO
         vquw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DvmRLpby;
       spf=pass (google.com: domain of 303i3zqukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=303i3ZQUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706522838; x=1707127638; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=mt1nFNOGDFJajOdbsP0eCeroFNJ5EYGYfF3+cfplnG8=;
        b=lHlOQq/vds0opWhvh9LZIjoV8vPi3YteskIvXmSWtODNQsuGgyZWrZMkXaqZH7gPhS
         UlWcO/zPBBghgzDlauZy7QpBlGn7tUvFex8l5RrEtbXgx45oo9GWIG3+cT7Pg4yFVnbD
         k/KkkJ7XzXgXydKThuysXPxJciNI7nt8veDSE2FnhK2Vv91eyfdjFqzYOoA5l9+iA6HV
         bbN2A2l0N3HDgQWmAaPHWcLSt3e1LvsWYWo6rvTWmJfxet+Ttv5xCULwd96Ph0v68UVv
         ee04OKim7V4Ouxf0Vd95r0Kcx4pcE1fRxxbcYFndUzw767UmxuAsoPgBPgt8nRS45r1r
         q70A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706522838; x=1707127638;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mt1nFNOGDFJajOdbsP0eCeroFNJ5EYGYfF3+cfplnG8=;
        b=IfdcAT71N7AHRhiiOd0tYP+jG05FKiQSTU5nXdxnmXvqFBtbE8bB8Mtgs3jDuGW4ra
         KwhCIsUha5VU3seVQr9xBEuImS+PrR3Am89TmcIHViab3AAznX4jMtNQ/6F2rIsaDuyI
         /+fY+P7LOPLY/Fj2wyiYfvW/uUi0I5w0qqsH2yAVepssuZjlcbYw3iA1JG7Op5HorAv6
         +xWF/J7AW92Dbplw1ThWtXW3Lu6S+lSwwG94dwFLleGXxorBuuKsh2lDWbrAvQnP628z
         AIO+PrcP3/7XwHUirpzEYZaGXEdSz03bf9ATXLqLJs9QlfiQNM/tjm91Jj2C1PRMCdBU
         JHZg==
X-Gm-Message-State: AOJu0Yx7y07zGDMKAIlKvc2qM/+5Nn2MC95iN1ngE5yopx3odi/ivfJ/
	kS2+yrJOQSbGN6+lRQHrwMHXu7B1tAISGxPqP3fIt5h6oeGBuhwu
X-Google-Smtp-Source: AGHT+IFbd4xmaqbeAmudoU4Ni6/CmW0MUKjmquqhvo2Hcodg8/UQKviniQpQKq1DaaeDYSWOS7EbOA==
X-Received: by 2002:a05:6402:22c9:b0:55e:f36f:16d7 with SMTP id dm9-20020a05640222c900b0055ef36f16d7mr1688623edb.25.1706522837961;
        Mon, 29 Jan 2024 02:07:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:f0c:b0:55e:d845:aafa with SMTP id
 i12-20020a0564020f0c00b0055ed845aafals525547eda.0.-pod-prod-01-eu; Mon, 29
 Jan 2024 02:07:16 -0800 (PST)
X-Received: by 2002:a17:906:f90e:b0:a35:6ba4:6cfb with SMTP id lc14-20020a170906f90e00b00a356ba46cfbmr3137242ejb.30.1706522835817;
        Mon, 29 Jan 2024 02:07:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706522835; cv=none;
        d=google.com; s=arc-20160816;
        b=iW/QRc7Y2k8h13ZKJSrvKTr2KUpMPBPFo1jdQwKXWaO8iJlLL2JpNCHpEncogoiUPc
         coS/gIwjqU9X5pf1JpZ2+suDPKIlqC+Tjs2Srr0i2Cs7dY92szp/irUPc3eqT6NPNB3a
         tePggLUxvwwp1lBmUcORWrHKxvAP/M8EXgKpUqGgBEY1mjK5y7wX55Koz4gMfnGFQ5Sr
         +Hh0EnUKWMMQTwAjXwl/M0fa6XFoP4mr3TtLWAF1zI98Jgt1EQynDHEvRtl7UzM+xDNt
         kaMHiFo8QhPZGdlzTUtqiuk2t4FYA495+tFhr9Ss/UYdeIbBiIW6q8Zc97tiAB1lAELU
         vJUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=+qmvJzBHNfclU7yyqgUvOeu3NcuQrq93zAHIMt+tsRw=;
        fh=Q6WTJ5ZnjiuB6HF3Kna6PPHtjylj1os0kvM6d8ajbeE=;
        b=Yoe2j0HXojIlrVJGjCmSAS4Ic4rrEH6by6HAIRIiCG0/0TbPMb8MPBaLkUnfrxHKT5
         i0TKKsnfDU/S3YHXA9uU7Z1lSMVc+QimUOQt1eKinX5begFdfGUddQRJi6JG9GnVo5vx
         0R6Fnj7KNGH5D+uVGMgLm20HJL21SVupQ0G9KYkmscX5w0/rNESCLtzoZNpR2pZ5FcJ8
         YXrjGO0qMCDog1qCCvSzhWMql54PZtoLCU5DhvadgmmoqB81kbtp8vIYztSa2KQ4QuWE
         qDeB6uxSlRg+v1TcSEVP554/ZvYqBRwiS1k1n7UOcIIrwkKsGABAUcpeGBLV1NDzz7Tl
         ABVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DvmRLpby;
       spf=pass (google.com: domain of 303i3zqukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=303i3ZQUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id v18-20020a1709063bd200b00a34bcf27488si332990ejf.2.2024.01.29.02.07.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jan 2024 02:07:15 -0800 (PST)
Received-SPF: pass (google.com: domain of 303i3zqukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-a35a649c608so48561166b.2
        for <kasan-dev@googlegroups.com>; Mon, 29 Jan 2024 02:07:15 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:cb16:eb72:6e81:bff1])
 (user=elver job=sendgmr) by 2002:a17:906:c097:b0:a34:a9e3:5524 with SMTP id
 f23-20020a170906c09700b00a34a9e35524mr27051ejz.5.1706522835498; Mon, 29 Jan
 2024 02:07:15 -0800 (PST)
Date: Mon, 29 Jan 2024 11:07:02 +0100
In-Reply-To: <20240129100708.39460-1-elver@google.com>
Mime-Version: 1.0
References: <20240129100708.39460-1-elver@google.com>
X-Mailer: git-send-email 2.43.0.429.g432eaa2c6b-goog
Message-ID: <20240129100708.39460-2-elver@google.com>
Subject: [PATCH v2 2/2] kasan: revert eviction of stack traces in generic mode
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=DvmRLpby;       spf=pass
 (google.com: domain of 303i3zqukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=303i3ZQUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
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
  refcounted_allocations: 17547
  refcounted_frees: 6477
  refcounted_in_use: 11070
  freelist_size: 3497
  persistent_count: 12163
  persistent_bytes: 1717008

After:

  pools: 319
  refcounted_allocations: 0
  refcounted_frees: 0
  refcounted_in_use: 0
  freelist_size: 0
  persistent_count: 29397
  persistent_bytes: 5183536

As can be seen from the counters, with a generic KASAN config,
refcounted allocations and evictions are no longer used. Due to using
variable-sized records, I observe a reduction of 278 stack depot pools
(saving 4448 KiB) with my test setup.

Fixes: cc478e0b6bdf ("kasan: avoid resetting aux_lock")
Fixes: 63b85ac56a64 ("kasan: stop leaking stack trace handles")
Fixes: 08d7c94d9635 ("kasan: memset free track in qlink_free")
Fixes: a414d4286f34 ("kasan: handle concurrent kasan_record_aux_stack calls")
Fixes: 773688a6cb24 ("kasan: use stack_depot_put for Generic mode")
Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
---
v2:
* Revert kasan_release_object_meta() as well (no longer needed) to catch
  use-after-free-before-realloc bugs.
* Add more comments.
---
 mm/kasan/common.c     |  8 ++---
 mm/kasan/generic.c    | 68 +++++--------------------------------------
 mm/kasan/kasan.h      | 10 -------
 mm/kasan/quarantine.c |  5 +++-
 4 files changed, 14 insertions(+), 77 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 610efae91220..6ca63e8dda74 100644
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
 
@@ -266,10 +265,9 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 		return true;
 
 	/*
-	 * If the object is not put into quarantine, it will likely be quickly
-	 * reallocated. Thus, release its metadata now.
+	 * Note: Keep per-object metadata to allow KASAN print stack traces for
+	 * use-after-free-before-realloc bugs.
 	 */
-	kasan_release_object_meta(cache, object);
 
 	/* Let slab put the object onto the freelist. */
 	return false;
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index df6627f62402..fc9cf1860efb 100644
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
@@ -526,27 +506,10 @@ static void release_free_meta(const void *object, struct kasan_free_meta *meta)
 	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREE_META)
 		return;
 
-	/* Evict the stack trace from the stack depot. */
-	stack_depot_put(meta->free_track.stack);
-
 	/* Mark free meta as invalid. */
 	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREE;
 }
 
-void kasan_release_object_meta(struct kmem_cache *cache, const void *object)
-{
-	struct kasan_alloc_meta *alloc_meta;
-	struct kasan_free_meta *free_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (alloc_meta)
-		release_alloc_meta(alloc_meta);
-
-	free_meta = kasan_get_free_meta(cache, object);
-	if (free_meta)
-		release_free_meta(object, free_meta);
-}
-
 size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
 {
 	struct kasan_cache *info = &cache->kasan_info;
@@ -571,8 +534,6 @@ static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
 	struct kmem_cache *cache;
 	struct kasan_alloc_meta *alloc_meta;
 	void *object;
-	depot_stack_handle_t new_handle, old_handle;
-	unsigned long flags;
 
 	if (is_kfence_address(addr) || !slab)
 		return;
@@ -583,33 +544,18 @@ static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
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
@@ -620,7 +566,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 	if (!alloc_meta)
 		return;
 
-	/* Evict previous stack traces (might exist for krealloc or mempool). */
+	/* Invalidate previous stack traces (might exist for krealloc or mempool). */
 	release_alloc_meta(alloc_meta);
 
 	kasan_save_track(&alloc_meta->alloc_track, flags);
@@ -634,7 +580,7 @@ void kasan_save_free_info(struct kmem_cache *cache, void *object)
 	if (!free_meta)
 		return;
 
-	/* Evict previous stack trace (might exist for mempool). */
+	/* Invalidate previous stack trace (might exist for mempool). */
 	release_free_meta(object, free_meta);
 
 	kasan_save_track(&free_meta->free_track, 0);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index d0f172f2b978..fb2b9ac0659a 100644
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
 
@@ -398,10 +390,8 @@ struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
 struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 						const void *object);
 void kasan_init_object_meta(struct kmem_cache *cache, const void *object);
-void kasan_release_object_meta(struct kmem_cache *cache, const void *object);
 #else
 static inline void kasan_init_object_meta(struct kmem_cache *cache, const void *object) { }
-static inline void kasan_release_object_meta(struct kmem_cache *cache, const void *object) { }
 #endif
 
 depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags);
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 3ba02efb952a..6958aa713c67 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -145,7 +145,10 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
 	void *object = qlink_to_object(qlink, cache);
 	struct kasan_free_meta *free_meta = kasan_get_free_meta(cache, object);
 
-	kasan_release_object_meta(cache, object);
+	/*
+	 * Note: Keep per-object metadata to allow KASAN print stack traces for
+	 * use-after-free-before-realloc bugs.
+	 */
 
 	/*
 	 * If init_on_free is enabled and KASAN's free metadata is stored in
-- 
2.43.0.429.g432eaa2c6b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240129100708.39460-2-elver%40google.com.
