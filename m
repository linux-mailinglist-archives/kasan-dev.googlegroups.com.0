Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4WBX6WQMGQEAXSPADA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E6FD8393C8
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jan 2024 16:53:23 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2cccd597247sf40966511fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jan 2024 07:53:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706025203; cv=pass;
        d=google.com; s=arc-20160816;
        b=x/oz5IoYyovdyby3wfS2ZqzHsbJUlsaU/K+TdFkrH1glm07mpAMOycLjAZUDk1B+J0
         21L9M8m8Q0TZeqPiMt5tuvEln8OCNdjLworbeS+7pvyYjuiCuecLLdRPaxQNuAWLUnEZ
         oE1Qwp9hSx8OdzgZ5QVsx4vJGADYcDBZKoEXR8GjQXw0TqCPx1kKyMOHhl56fN3f/R2e
         tnTQ9McrP6pnu9WJIDpfDiRwK7/6kmmHuMoOe5bejVHrG3UISRTaJbf/R0u3LMFtx26i
         SGSVuItr2UnupmPMUCvnGhGd605sH3d6+8V1u40OmfNaTkeqyWB25uTQntjcSA8h6mtE
         pQ4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=iphS65vzDf8oHgDIMP/TFsM6Pr89ZYi2Y2QSJRX240s=;
        fh=lPwuHQi+SN018bZccQZBbW1u3+s+TubAat/49IA973Q=;
        b=qUACeZhxsgbuFDZBWK8gCD1vCzKQIBeTQqQvOYLLIoQvHL5sai91YVOI5n8M21vOC3
         0rtbyMPWLsyKlDnob2QMwxr9XV3uPVKA31DqR+jFKbFYpB691ku3dTry0sVAoqNMCxjW
         BRnwS1maY4hY24+ChVrJAQ2+3aEOADMTeCgkAz9uZpd0zoun0moTizXEr7YeAItZ/vEc
         Ts/9UlPZ+YP2gSd/l6fBgRurv2R/t6s8H7abuBgHccPxZrEZBrsHpD11ype+2l/+mBrP
         muvWG+JsOxnKxgmhHRf8fP8OXS3/kNVhZQefocs42rm+KXDcp+UMOz1wYRnLrExLsnLF
         yriw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MSaFf7fl;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706025203; x=1706630003; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=iphS65vzDf8oHgDIMP/TFsM6Pr89ZYi2Y2QSJRX240s=;
        b=gCq0E3tpvCUJTEz/l47zkEYZ/sf9dAVqt8I+DBCwKa7N91Us0EjF2rjtfe0SJZhg8E
         CKz5VeHWyq2jYx6M1k5qy5gY0tXODXjJYCcehXJbcQCqDpxgWJwWGuRnhYxgN6Tz50VJ
         ipnjfXyRnajOXz5U1ikmVHQW7Z4AVi+bh0yblj2ycl3YDzfwkKIUb0gTtKsAK2A9d0or
         YQdDudBUMoWhoJBe5UsmRUSrEzS+F39mARfMpLyfxmdbNpPjZHNdLtz2nNJ6aE45/DJV
         we1QYS2zec1nZepfcqWZhS1Yh+UcR59+wcPoKgyRAXh+/ZRfmElHss/30WlNda4eX46G
         1XPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706025203; x=1706630003;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iphS65vzDf8oHgDIMP/TFsM6Pr89ZYi2Y2QSJRX240s=;
        b=ay6LM7sjJ3q5zbiX1t/BdhonjjYj+bCpPxb0lBTQjriX3SyTa1EEPJh+wAT8dzlPZi
         SfQiKw3lyiukmNPDFILhpuY2EcQ6HGQazawKNfW+Vy0OK6j6+GuG38KyNgmHmCKEeco6
         bzd75f1LRFSHDHVDmm3ex/9JBECH/BIZkjI6GrYwNeCEaD+Dg4aBSbrhjr5p2MRDcAHu
         ySfmKNO7gl8RWwcuDalcqJ2MX5H5cwlO1ix2+IHrTujATfIuppBUQEn0yA7CYng8JZgy
         mcMltTao/HqgDCBxrQdo5iDaP7BBGIsMhw/i7l54xqwNBKTZkFNXdlahD/LpdNP2XOVY
         iz7g==
X-Gm-Message-State: AOJu0YwLmKlFw85ITeFgu9hLI51CKp8te4FxVX9SLhG4ucjGLvVCqCcc
	bBGfkhlOXYLLl+vFxtMWpQtb1bBqz0+QXhomgZ/1pp8I4jXt+e77
X-Google-Smtp-Source: AGHT+IHFZHCEisePOe4c8F6TFt5HYjyGTAdxB1Q4xxt3mlZ5DbrcXVC9FiWiEqyaOb6ApjMYlfBXLg==
X-Received: by 2002:a2e:7316:0:b0:2cd:fb2c:9ea2 with SMTP id o22-20020a2e7316000000b002cdfb2c9ea2mr1866ljc.168.1706025202509;
        Tue, 23 Jan 2024 07:53:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9bc9:0:b0:2cd:eb51:129b with SMTP id w9-20020a2e9bc9000000b002cdeb51129bls232378ljj.2.-pod-prod-08-eu;
 Tue, 23 Jan 2024 07:53:20 -0800 (PST)
X-Received: by 2002:a2e:2c15:0:b0:2cd:f47e:c0a4 with SMTP id s21-20020a2e2c15000000b002cdf47ec0a4mr1105ljs.157.1706025200190;
        Tue, 23 Jan 2024 07:53:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706025200; cv=none;
        d=google.com; s=arc-20160816;
        b=Hd6jGYZu7XI4fJrommm7a0rdCQ/lFb62fkEQBZJUajJGHYZAdw51c8vnZNysfRxbTi
         HmOeE3gvckO/7bOiCJz5zvg8WuZVZc/Kp+DVW9V7vuGaIuguzfUOREOkt2lIPmc3P44W
         ESQPFRokEaXYvRvYkNqCO4JrxOjJUVi8//+neVzZVfBAtGQlJy+Me2DS3mNARQjNQ4Q9
         GdsEXAzeLb+FMaYHNAYZjqzD9Vh7YSjSpEj1DhzeDgDF7xohvnu9cBiFHaXIAZfzJkqv
         9dLcA/R2SmQFm/NY5D/VndhxSMu/EZezKsEaX0EiaeKdtqlIqBaVeFKMmwEFvRZ5LJZz
         H7Fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=wN1zYbmyQqMAelG24I+F79Wy9Nx29GGurhOHrEZCBhQ=;
        fh=lPwuHQi+SN018bZccQZBbW1u3+s+TubAat/49IA973Q=;
        b=tISVp9nvjDHc4puz/dc8XgB4qpeHzrLbbFcyJ+Z7eVU1WTVh/J3jtoDn18F02SPbOD
         cg/18IPK+PheInWH2cLu6URGAD8HBWWy/ym0DDL3b7Sbf38uVhm+QDoyLqhX/bshO/qV
         vNI6lrpx6CcICFy6jb3KSBDcuy9dJrD0lzLEVAkhrD7p3npApWm2YxF1Wyz18MI5u8CU
         xgU5B0v7/EJ+heVq2ee4csDYVwKaBmQruVpz8b5myMZLep6z7V04DK64lQY+ZGq5M5Pn
         IS3/jDjYZ9NKDUo4eXaFbH/CGG7OFWP+xpnM8zqTToiQmofdTZSEVIzDoevlTyJFva7Q
         Wuzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MSaFf7fl;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id f25-20020a2e9199000000b002ccc27fab8csi820090ljg.7.2024.01.23.07.53.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Jan 2024 07:53:20 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-33922d2cb92so4001550f8f.1
        for <kasan-dev@googlegroups.com>; Tue, 23 Jan 2024 07:53:20 -0800 (PST)
X-Received: by 2002:a5d:58f4:0:b0:337:d860:b260 with SMTP id f20-20020a5d58f4000000b00337d860b260mr1500203wrd.177.1706025199197;
        Tue, 23 Jan 2024 07:53:19 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:9c:201:3ba0:aeb0:d827:1aee])
        by smtp.gmail.com with ESMTPSA id df10-20020a5d5b8a000000b0033947d7651asm1391689wrb.5.2024.01.23.07.53.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Jan 2024 07:53:18 -0800 (PST)
Date: Tue, 23 Jan 2024 16:53:13 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Subject: Re: [RFC PATCH] stackdepot: use variable size records for
 non-evictable entries
Message-ID: <Za_g6QkbGoAcXBNH@elver.google.com>
References: <20240122171215.319440-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240122171215.319440-2-elver@google.com>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=MSaFf7fl;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

And on top of this we can make KASAN generic happier again:

Objections?

------ >8 ------

From: Marco Elver <elver@google.com>
Date: Tue, 23 Jan 2024 12:11:36 +0100
Subject: [PATCH RFC] kasan: revert eviction of stack traces in generic mode

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
observe a reduction of 282 stack depot pools (saving 4512 KiB).

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Za_g6QkbGoAcXBNH%40elver.google.com.
