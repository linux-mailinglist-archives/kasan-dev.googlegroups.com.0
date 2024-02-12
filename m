Return-Path: <kasan-dev+bncBC7OD3FKWUERBSVAVKXAMGQEVYXMJPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B8F8851FE7
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:28 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1d93f4aad50sf37945ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774027; cv=pass;
        d=google.com; s=arc-20160816;
        b=OWCArqdI5CbZReXTj6Iwt+SoTDCEwdLHHgPL2Ksh0qq+8VnkdVW1N+vQ4zM+VG9mou
         7I1+e7ZzygOuiua9wtzP75+i8OByBq3UDUk+s+3hL/UM+FH0XoAenxseuLOG/OIp+e93
         BLxkaIichti6QGTxyXIHSYnkRo6bHNntjYCw4DaE5nP176lGy5fo0+o63Vp5QE/7bZ7q
         rA76k8+Dn1fsvc/DQId4dGgxrsFPPwfZurtkF0mwtrzMpGrruKHLBRHOKZsqxLN/+QwM
         hvW2x5oMlExBv/d0qzxW8G6UzpdtpXc2gHmJT+JJ0YyR502VICUQAdqHH57y2kl3kjlj
         w2aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=0E1GAMyl4c5YBDawujJyukJzn2lXRZoXnSJxyJWd7yw=;
        fh=4lx62DEhQ3ku2J0ruETcR+NNATjQ9F+ErKu95nJ0s7o=;
        b=dtfeudyKZDFL7PROgUBnKxqNfJ+utH7mYfTMJakbheJHKIWytwZ2DT/XCWxT83b21E
         9jgAcM361/DjGldWIiXERPY49cNLFsF4xwcdxQjSANMh1lbuu51o8twHg/rRyhN0Doz+
         MDgbOjD26G7a0USugB4/3TMtNZJELzK/DVgktmoXSBuhA33h8gYWcuX+U782IeWA/9YT
         wisxFoQLkQhTcQPVbLW6qlm6Y7qd73Bl47TGQuWdxKCRbMs7abwPTWxJtERlB8WDWu/V
         nGvBS9zL2E5jZAnBQyiuUh6HMxJFX+07EVRsATe8P1gokI5EB4PxUmE6rHd1tEwWdGya
         2SIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=t+6+1x8m;
       spf=pass (google.com: domain of 3sjdkzqykccc574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3SJDKZQYKCcc574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774027; x=1708378827; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=0E1GAMyl4c5YBDawujJyukJzn2lXRZoXnSJxyJWd7yw=;
        b=rnmG7daGNRtpG+qkxnukjoAdvMNYwkL2cR99LjGdnj7qYU9y7Y4bIiT/UOuwKPNX3t
         ZvsRaUy3auW0+UM+5ciTdIidsIffjblrPkjSQrgcfTaKAhlARoILQfeOYe1XL6mU5OuP
         moN2hkv1gXYKr2N9BclKUGy4D1qMKbxGkkOnx7f0t3pi8JNJtqAeYQabffPjhmdEtKJj
         tcl6HNERlkAW8vDOySG0j0U4OAxYFvzaAQCgnysSMLQSgMGbC2JVvjtunDXIVqRaYmF5
         JcHURXAGlU4NMB6zPKpFO5ussd7jX0Gm0RKg2lpwWKH1yOWsEzNj94UjhfZOiEjordWw
         +H9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774027; x=1708378827;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0E1GAMyl4c5YBDawujJyukJzn2lXRZoXnSJxyJWd7yw=;
        b=TIHVcs6ZhgQAU76IHDpK1E7eSx9JhCHFSO9wAiMqX785g9jPyigX5pF3M4f1WzOC89
         v7mjB7kp11ZsYzEd4yYXnyOajUq/Lbq9i34uD8Bd/tze0jElm6JvXqcQDxQlFrlNxqXx
         5GPHJ8jqPGbbRS7KITw0gxYf/dtEoKgveJiOO7xFYvQBWljbtIpn1vLGk33fhnOfMg4O
         0Gx1zGdxBGNhppCU8+eT3MehS92hGN+3nm4VkGaZo/q8np0qebroxmkCghqN+c39konc
         UHHQxGb/UpJQXPf+4GJYNTRYbu1L31OHniLpM/bD2Pqh3FqeAnAcAJph9l+dOU/2OupJ
         c2fw==
X-Gm-Message-State: AOJu0YxJjLzeLi4ddzmE2E2H9120TD+Kr6msg902R9M08q/SJBGOCO1p
	C/mQddJdVdUqjnnAmONXLxQX0hEYcxyAx0GE6SqjUPY5BfuKKNGw
X-Google-Smtp-Source: AGHT+IH5q1KUCLHypWe24e5K6Us6OLFP16Oaoip3X71vRQ4UCibUAvHciODsrLROywQqZaasOIRNwg==
X-Received: by 2002:a17:903:2111:b0:1d5:ed04:4d0e with SMTP id o17-20020a170903211100b001d5ed044d0emr21110ple.24.1707774026725;
        Mon, 12 Feb 2024 13:40:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5516:0:b0:59a:78b5:20dd with SMTP id e22-20020a4a5516000000b0059a78b520ddls3102909oob.2.-pod-prod-08-us;
 Mon, 12 Feb 2024 13:40:25 -0800 (PST)
X-Received: by 2002:a9d:74c2:0:b0:6e2:d9a0:b2b0 with SMTP id a2-20020a9d74c2000000b006e2d9a0b2b0mr7611946otl.0.1707774025447;
        Mon, 12 Feb 2024 13:40:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774025; cv=none;
        d=google.com; s=arc-20160816;
        b=QP/7Epj0Zm1NyRHS9kGemDr4irvr0ukEsQUZwHjDjCQS+i0GU9AYyawPtjHO2Vfb5Q
         kxtxEU+zHYcQ6in6DT3nytybbyuN9hpM9UUoF63U89oglf8hqHbbEJRumiWA+9hU/UiX
         wLRCjYRZgOgOM4sunpCRFroV5OdjhacOvoQhC8oqDEcr4k5VDjsXKha1lgnKEmVJCKMh
         z8rycZbqdmqFlAM2qc9kNMWLuSk42ZIvOKAjTYhL/2x+LjztfopNnhHQyK4fw1nIzX7n
         e+Px5eNS+WiY08KPdQ7bFJy4DKwLzCXqiPf11JGlyu/LTY0+LcjtUEJPh4Jy8CFF8XSx
         WYxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=nNnBkPYeQ1kRTTlryOW31uuwa/BW+/OIiMnW19R7vGw=;
        fh=4lx62DEhQ3ku2J0ruETcR+NNATjQ9F+ErKu95nJ0s7o=;
        b=iUoy7uKaIJRFLq679yd/D8FHjwkrVjiPF4D4uYu8tC8WCde7kQFlE/lOQW23lgu0EQ
         2Fufbu/wvtK3dBZoUEKW4YnrbDHr2IVAiTTqQZCpr0XfsMJMN8GuCdJUt6UTsN8MqvMe
         R8sBfi7nSIUjBq7gV4KyFrEA4CPZ+2ZZe0ZRZz8U8aZTyXofr6IbsXyeYpWeklKRAwsJ
         4bE1agSOW8IY0WqA+8xZzu/yQHWa8KnJwSTyH6XI+FGQMIkY6e+uAlVhMn7LMFISkP22
         NDZDu43hjO2kyNT6CEH2QiiS3WAwzotl9zp4FI7oCATTo7ymqOS2WvELmmyQ28Q0HdDZ
         qxVQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=t+6+1x8m;
       spf=pass (google.com: domain of 3sjdkzqykccc574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3SJDKZQYKCcc574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCWCwMgnJtagKWtnpBbI3Qv3FduHWYqS9gw6FXRHfSNuPwoDB1MEC+tLtbD5tezUf1e0hkAVvWKwei5dOxG0vP+tBfAsxVDk517aSg==
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id n2-20020a056830320200b006e2df32b368si153720ott.1.2024.02.12.13.40.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sjdkzqykccc574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dbf216080f5so5719291276.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:25 -0800 (PST)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a05:6902:154b:b0:dc7:5aad:8965 with SMTP id
 r11-20020a056902154b00b00dc75aad8965mr2054600ybu.0.1707774024786; Mon, 12 Feb
 2024 13:40:24 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:10 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-25-surenb@google.com>
Subject: [PATCH v3 24/35] mempool: Hook up to memory allocation profiling
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=t+6+1x8m;       spf=pass
 (google.com: domain of 3sjdkzqykccc574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3SJDKZQYKCcc574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

This adds hooks to mempools for correctly annotating mempool-backed
allocations at the correct source line, so they show up correctly in
/sys/kernel/debug/allocations.

Various inline functions are converted to wrappers so that we can invoke
alloc_hooks() in fewer places.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/mempool.h | 73 ++++++++++++++++++++---------------------
 mm/mempool.c            | 36 ++++++++------------
 2 files changed, 49 insertions(+), 60 deletions(-)

diff --git a/include/linux/mempool.h b/include/linux/mempool.h
index 7be1e32e6d42..69e65ca515ee 100644
--- a/include/linux/mempool.h
+++ b/include/linux/mempool.h
@@ -5,6 +5,8 @@
 #ifndef _LINUX_MEMPOOL_H
 #define _LINUX_MEMPOOL_H
 
+#include <linux/sched.h>
+#include <linux/alloc_tag.h>
 #include <linux/wait.h>
 #include <linux/compiler.h>
 
@@ -39,18 +41,32 @@ void mempool_exit(mempool_t *pool);
 int mempool_init_node(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
 		      mempool_free_t *free_fn, void *pool_data,
 		      gfp_t gfp_mask, int node_id);
-int mempool_init(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
+
+int mempool_init_noprof(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
 		 mempool_free_t *free_fn, void *pool_data);
+#define mempool_init(...)						\
+	alloc_hooks(mempool_init_noprof(__VA_ARGS__))
 
 extern mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
 			mempool_free_t *free_fn, void *pool_data);
-extern mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
+
+extern mempool_t *mempool_create_node_noprof(int min_nr, mempool_alloc_t *alloc_fn,
 			mempool_free_t *free_fn, void *pool_data,
 			gfp_t gfp_mask, int nid);
+#define mempool_create_node(...)					\
+	alloc_hooks(mempool_create_node_noprof(__VA_ARGS__))
+
+#define mempool_create(_min_nr, _alloc_fn, _free_fn, _pool_data)	\
+	mempool_create_node(_min_nr, _alloc_fn, _free_fn, _pool_data,	\
+			    GFP_KERNEL, NUMA_NO_NODE)
 
 extern int mempool_resize(mempool_t *pool, int new_min_nr);
 extern void mempool_destroy(mempool_t *pool);
-extern void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask) __malloc;
+
+extern void *mempool_alloc_noprof(mempool_t *pool, gfp_t gfp_mask) __malloc;
+#define mempool_alloc(...)						\
+	alloc_hooks(mempool_alloc_noprof(__VA_ARGS__))
+
 extern void *mempool_alloc_preallocated(mempool_t *pool) __malloc;
 extern void mempool_free(void *element, mempool_t *pool);
 
@@ -62,19 +78,10 @@ extern void mempool_free(void *element, mempool_t *pool);
 void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data);
 void mempool_free_slab(void *element, void *pool_data);
 
-static inline int
-mempool_init_slab_pool(mempool_t *pool, int min_nr, struct kmem_cache *kc)
-{
-	return mempool_init(pool, min_nr, mempool_alloc_slab,
-			    mempool_free_slab, (void *) kc);
-}
-
-static inline mempool_t *
-mempool_create_slab_pool(int min_nr, struct kmem_cache *kc)
-{
-	return mempool_create(min_nr, mempool_alloc_slab, mempool_free_slab,
-			      (void *) kc);
-}
+#define mempool_init_slab_pool(_pool, _min_nr, _kc)			\
+	mempool_init(_pool, (_min_nr), mempool_alloc_slab, mempool_free_slab, (void *)(_kc))
+#define mempool_create_slab_pool(_min_nr, _kc)			\
+	mempool_create((_min_nr), mempool_alloc_slab, mempool_free_slab, (void *)(_kc))
 
 /*
  * a mempool_alloc_t and a mempool_free_t to kmalloc and kfree the
@@ -83,17 +90,12 @@ mempool_create_slab_pool(int min_nr, struct kmem_cache *kc)
 void *mempool_kmalloc(gfp_t gfp_mask, void *pool_data);
 void mempool_kfree(void *element, void *pool_data);
 
-static inline int mempool_init_kmalloc_pool(mempool_t *pool, int min_nr, size_t size)
-{
-	return mempool_init(pool, min_nr, mempool_kmalloc,
-			    mempool_kfree, (void *) size);
-}
-
-static inline mempool_t *mempool_create_kmalloc_pool(int min_nr, size_t size)
-{
-	return mempool_create(min_nr, mempool_kmalloc, mempool_kfree,
-			      (void *) size);
-}
+#define mempool_init_kmalloc_pool(_pool, _min_nr, _size)		\
+	mempool_init(_pool, (_min_nr), mempool_kmalloc, mempool_kfree,	\
+		     (void *)(unsigned long)(_size))
+#define mempool_create_kmalloc_pool(_min_nr, _size)			\
+	mempool_create((_min_nr), mempool_kmalloc, mempool_kfree,	\
+		       (void *)(unsigned long)(_size))
 
 /*
  * A mempool_alloc_t and mempool_free_t for a simple page allocator that
@@ -102,16 +104,11 @@ static inline mempool_t *mempool_create_kmalloc_pool(int min_nr, size_t size)
 void *mempool_alloc_pages(gfp_t gfp_mask, void *pool_data);
 void mempool_free_pages(void *element, void *pool_data);
 
-static inline int mempool_init_page_pool(mempool_t *pool, int min_nr, int order)
-{
-	return mempool_init(pool, min_nr, mempool_alloc_pages,
-			    mempool_free_pages, (void *)(long)order);
-}
-
-static inline mempool_t *mempool_create_page_pool(int min_nr, int order)
-{
-	return mempool_create(min_nr, mempool_alloc_pages, mempool_free_pages,
-			      (void *)(long)order);
-}
+#define mempool_init_page_pool(_pool, _min_nr, _order)			\
+	mempool_init(_pool, (_min_nr), mempool_alloc_pages,		\
+		     mempool_free_pages, (void *)(long)(_order))
+#define mempool_create_page_pool(_min_nr, _order)			\
+	mempool_create((_min_nr), mempool_alloc_pages,			\
+		       mempool_free_pages, (void *)(long)(_order))
 
 #endif /* _LINUX_MEMPOOL_H */
diff --git a/mm/mempool.c b/mm/mempool.c
index dbbf0e9fb424..c47ff883cf36 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -240,17 +240,17 @@ EXPORT_SYMBOL(mempool_init_node);
  *
  * Return: %0 on success, negative error code otherwise.
  */
-int mempool_init(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
-		 mempool_free_t *free_fn, void *pool_data)
+int mempool_init_noprof(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
+			mempool_free_t *free_fn, void *pool_data)
 {
 	return mempool_init_node(pool, min_nr, alloc_fn, free_fn,
 				 pool_data, GFP_KERNEL, NUMA_NO_NODE);
 
 }
-EXPORT_SYMBOL(mempool_init);
+EXPORT_SYMBOL(mempool_init_noprof);
 
 /**
- * mempool_create - create a memory pool
+ * mempool_create_node - create a memory pool
  * @min_nr:    the minimum number of elements guaranteed to be
  *             allocated for this pool.
  * @alloc_fn:  user-defined element-allocation function.
@@ -265,17 +265,9 @@ EXPORT_SYMBOL(mempool_init);
  *
  * Return: pointer to the created memory pool object or %NULL on error.
  */
-mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
-				mempool_free_t *free_fn, void *pool_data)
-{
-	return mempool_create_node(min_nr, alloc_fn, free_fn, pool_data,
-				   GFP_KERNEL, NUMA_NO_NODE);
-}
-EXPORT_SYMBOL(mempool_create);
-
-mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
-			       mempool_free_t *free_fn, void *pool_data,
-			       gfp_t gfp_mask, int node_id)
+mempool_t *mempool_create_node_noprof(int min_nr, mempool_alloc_t *alloc_fn,
+				      mempool_free_t *free_fn, void *pool_data,
+				      gfp_t gfp_mask, int node_id)
 {
 	mempool_t *pool;
 
@@ -291,7 +283,7 @@ mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
 
 	return pool;
 }
-EXPORT_SYMBOL(mempool_create_node);
+EXPORT_SYMBOL(mempool_create_node_noprof);
 
 /**
  * mempool_resize - resize an existing memory pool
@@ -374,7 +366,7 @@ int mempool_resize(mempool_t *pool, int new_min_nr)
 EXPORT_SYMBOL(mempool_resize);
 
 /**
- * mempool_alloc - allocate an element from a specific memory pool
+ * mempool_alloc_noprof - allocate an element from a specific memory pool
  * @pool:      pointer to the memory pool which was allocated via
  *             mempool_create().
  * @gfp_mask:  the usual allocation bitmask.
@@ -387,7 +379,7 @@ EXPORT_SYMBOL(mempool_resize);
  *
  * Return: pointer to the allocated element or %NULL on error.
  */
-void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
+void *mempool_alloc_noprof(mempool_t *pool, gfp_t gfp_mask)
 {
 	void *element;
 	unsigned long flags;
@@ -454,7 +446,7 @@ void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
 	finish_wait(&pool->wait, &wait);
 	goto repeat_alloc;
 }
-EXPORT_SYMBOL(mempool_alloc);
+EXPORT_SYMBOL(mempool_alloc_noprof);
 
 /**
  * mempool_alloc_preallocated - allocate an element from preallocated elements
@@ -562,7 +554,7 @@ void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data)
 {
 	struct kmem_cache *mem = pool_data;
 	VM_BUG_ON(mem->ctor);
-	return kmem_cache_alloc(mem, gfp_mask);
+	return kmem_cache_alloc_noprof(mem, gfp_mask);
 }
 EXPORT_SYMBOL(mempool_alloc_slab);
 
@@ -580,7 +572,7 @@ EXPORT_SYMBOL(mempool_free_slab);
 void *mempool_kmalloc(gfp_t gfp_mask, void *pool_data)
 {
 	size_t size = (size_t)pool_data;
-	return kmalloc(size, gfp_mask);
+	return kmalloc_noprof(size, gfp_mask);
 }
 EXPORT_SYMBOL(mempool_kmalloc);
 
@@ -597,7 +589,7 @@ EXPORT_SYMBOL(mempool_kfree);
 void *mempool_alloc_pages(gfp_t gfp_mask, void *pool_data)
 {
 	int order = (int)(long)pool_data;
-	return alloc_pages(gfp_mask, order);
+	return alloc_pages_noprof(gfp_mask, order);
 }
 EXPORT_SYMBOL(mempool_alloc_pages);
 
-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-25-surenb%40google.com.
