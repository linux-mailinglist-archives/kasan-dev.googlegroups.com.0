Return-Path: <kasan-dev+bncBC7OD3FKWUERB7EV36UQMGQEWB3ADEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0828E7D5262
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:42 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3574a84ec3fsf54574475ab.2
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155261; cv=pass;
        d=google.com; s=arc-20160816;
        b=iMQO+UllewQEqUYfEVamCJEY/6ivPoQcjqIlDGL4dT9mSLNRHYMNy2vsQIdZ7xK4H2
         ONvNazkhMKvH/7J31N72fklb5fURWTpLopp67xTL6kBXI2VHO6whFkvtLoVbSTe7e3o0
         aFQgPh9guS1r3ya7e1rJxMwyI1r0L3+FJfE9y/bvF3j/IlB60PSWt1aFFgWNudFN82bK
         fTb9EhKGa7HcrzrhrzczEvV1OKSCi71bZ9BxFctuVcKChHdv0dEmF8NHGUyqHCDcn7o+
         Qm+NfwSLf+eyhjSaD6grWghUWlxiIrEe7V8D0KUsGRkydsannfaKRWPjuC1qzmuYyodP
         JsPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=PvEgpvGYNkXJJrZYU6g38lGndEm+WA4l777nUTKbwzA=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=M7yJwetzg+KRUPUgpb/vR/DXp+wL7WqIpJa5l4gsqIkV3VF8K8tNDZpVTg89HA5BJY
         PHNyQWbYzT6/kGYhzZSFjUFXufCMIYLxN3maCcTp7O7LiQAZkIgAi4vlqAZUXPfYaryu
         iTYxahDWiYpXJcB0M10eDtvazqeCrRzwEjwmv5QGlirB2GCR3XP0Pxq/bCkqHhn7JrMc
         Tf8rNZlU9FGTuNes2AyMSMpCoCY7yw7wzSCchfYX6Jr5SQg4El+5EB21elAlHWlyYW8c
         r41V4zhDGOn9XhOxcxbbGDrHZvkLKv8/NPqlm1x9Tz+aM4UDGA9zB+V9d257qD0jEdwU
         Ww+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=X2DlJRUj;
       spf=pass (google.com: domain of 3-8o3zqykcaasurenbgoogle.comkasan-devgooglegroups.com@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3-8o3ZQYKCaASURENBGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155261; x=1698760061; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=PvEgpvGYNkXJJrZYU6g38lGndEm+WA4l777nUTKbwzA=;
        b=KWOKeCft2vS1MISjPhAuknMqQEOiPEwCDpmiZ/Aqh1gSdlsTwoBepIZN4IMjL322C4
         kdpzdUiG5peIAATQr6R9yHeXEtn8lZ/+24lOMApGK3qP2uQPrE72HxzKTaoAIaFTy7Tr
         oaaG8CuqXvFshyLLhBy02nyEml36o/hp9xDYFBwAs53j3DTT2rWLEw8R2ImsU4C/razZ
         p+waPTwvHJyDUYl9BgcyEXVYYhv5BJVX83rJpCewmIVCYblgfuHqFRWFhNHdIHlqJKPf
         LffFSFnpUFj+71hCpGCFIwHJ7RxHHA0wZu8/tCmgJz2SwdR8ApLBan6j2bu3+5n95EOS
         t0wQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155261; x=1698760061;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PvEgpvGYNkXJJrZYU6g38lGndEm+WA4l777nUTKbwzA=;
        b=hfQxYc/TBZlCEIhqB2VIAeRoBZ2T2L4VH0R2Dbo6JohSHbgpbXbSIixU94aRb717S+
         g2FN984DGNXoEBbEwNjSsFZQprFtFe4pdUmrSwLrXxVCSOb0Z/c1uPrw32FlBewYXaRf
         NFdbiRK4KCEy3Jvlv0AxEhgAx5wdFUztxEvjLBccPwjR3MU7nlxtZOCafusw52wv6nEJ
         hjycFr4b8aYjOEbnlSdCDky1AUt6TNT20xQs/otvGddapa5UxkAlvydtSIAyAeCH7Mcz
         H+Z2HDVmRPKQiGrPb/vRRMv6QEUgAJ0MurC5ned8HzqNaBCNnce4RzSdXGCbXQcKeQGR
         km+w==
X-Gm-Message-State: AOJu0YzLcq21xdCoL2fJU3zbDep3ebjMwSvr/TGuo0aeB3UHCnN+HzOR
	3i1S80EfxnRTSzcakhqTPz8=
X-Google-Smtp-Source: AGHT+IGLJHgx7j+YUIOOtJULqmhuQ+P+1lYhe+8rQcxCdD8cQjJxKFon7H+jWL/gE0R/h5Q7gNig4A==
X-Received: by 2002:a05:6e02:1b01:b0:357:3e6d:d543 with SMTP id i1-20020a056e021b0100b003573e6dd543mr15316882ilv.23.1698155260871;
        Tue, 24 Oct 2023 06:47:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:ca6:b0:348:81c5:d1cf with SMTP id
 6-20020a056e020ca600b0034881c5d1cfls175549ilg.1.-pod-prod-06-us; Tue, 24 Oct
 2023 06:47:40 -0700 (PDT)
X-Received: by 2002:a92:c54b:0:b0:357:c8c4:3d0d with SMTP id a11-20020a92c54b000000b00357c8c43d0dmr10859406ilj.28.1698155260253;
        Tue, 24 Oct 2023 06:47:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155260; cv=none;
        d=google.com; s=arc-20160816;
        b=Wg9R5UIvMt3cg/psvSgJAJhT+zsc14wMk/8l6yHtp885r/juNQbp3s9lF2aILbNQcE
         cdFGqs5eSt3oTe42JXXC9sPt/WaKZpqerfUaz0RA6joRLzi0kTH0+Af65PnGIu/JGpC0
         ADopd4rdBxEwUfAeCl5R9AUbPDvC0XCfMSd5XG0liEX+5zph9NHWk8EonwoLyrJHEChg
         jLH17yam0siW/LJIDlIIHIAXluccHrIZQJ63W+vjrbSyrZmqiRJf9xmTSZ15T7S7ze6U
         +qFeYL3KQt8B0pLGHWp7PU/IXwT88GMwklpqNxnnlSx62nVrQabtsV+AIux4BHUF1735
         B8CA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=2MflihaSbuQmiTaEEI/kjjxwB9AeuC8B0gJ477WMkrk=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=Q+S3BMmsj9Fc2GsNl2k+mB07d9qzDiJtFLGoMZ4FcfsG6aR7oEhYRibnKCqN4pYof8
         ojvDxWlKDXTVGntyo3lNpK6QEdpwlPWWpJGr+5mmQ8/neZiY+hRIU7mt3gfitoV2fl2n
         F/zMasBC4c4maemxJjYAITujZft/QLjMl6BBZLtyF1DhbfUFspVc4+AeuqIMn9PpCFpd
         H/G9HIoN+b2vKvvlokYz1DYgUqlYR9QqTg/bz9LtiHjEGnnbqJZexOAmz6VxBGuzVcsd
         I831uvsZ1Qu1wkCsBQYudGvvWN/vYSxQHqF/NnFLoBquG5wT+8Th6RqICUJo8PHo/8zO
         BpZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=X2DlJRUj;
       spf=pass (google.com: domain of 3-8o3zqykcaasurenbgoogle.comkasan-devgooglegroups.com@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3-8o3ZQYKCaASURENBGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id cn5-20020a056e02388500b0035250544598si846486ilb.1.2023.10.24.06.47.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-8o3zqykcaasurenbgoogle.comkasan-devgooglegroups.com@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-d9a3a38b96cso5081102276.0
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:40 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a5b:8c1:0:b0:da0:5452:29e4 with SMTP id
 w1-20020a5b08c1000000b00da0545229e4mr18077ybq.0.1698155259614; Tue, 24 Oct
 2023 06:47:39 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:23 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-27-surenb@google.com>
Subject: [PATCH v2 26/39] mempool: Hook up to memory allocation profiling
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
 header.i=@google.com header.s=20230601 header.b=X2DlJRUj;       spf=pass
 (google.com: domain of 3-8o3zqykcaasurenbgoogle.comkasan-devgooglegroups.com@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3-8o3ZQYKCaASURENBGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--surenb.bounces.google.com;
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
 mm/mempool.c            | 34 ++++++++-----------
 2 files changed, 48 insertions(+), 59 deletions(-)

diff --git a/include/linux/mempool.h b/include/linux/mempool.h
index 4aae6c06c5f2..9fa126aa19b5 100644
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
 extern void mempool_free(void *element, mempool_t *pool);
 
 /*
@@ -61,19 +77,10 @@ extern void mempool_free(void *element, mempool_t *pool);
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
@@ -82,17 +89,12 @@ mempool_create_slab_pool(int min_nr, struct kmem_cache *kc)
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
@@ -101,16 +103,11 @@ static inline mempool_t *mempool_create_kmalloc_pool(int min_nr, size_t size)
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
index 734bcf5afbb7..4fd949178449 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -230,17 +230,17 @@ EXPORT_SYMBOL(mempool_init_node);
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
@@ -255,17 +255,9 @@ EXPORT_SYMBOL(mempool_init);
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
 
@@ -281,7 +273,7 @@ mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
 
 	return pool;
 }
-EXPORT_SYMBOL(mempool_create_node);
+EXPORT_SYMBOL(mempool_create_node_noprof);
 
 /**
  * mempool_resize - resize an existing memory pool
@@ -377,7 +369,7 @@ EXPORT_SYMBOL(mempool_resize);
  *
  * Return: pointer to the allocated element or %NULL on error.
  */
-void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
+void *mempool_alloc_noprof(mempool_t *pool, gfp_t gfp_mask)
 {
 	void *element;
 	unsigned long flags;
@@ -444,7 +436,7 @@ void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
 	finish_wait(&pool->wait, &wait);
 	goto repeat_alloc;
 }
-EXPORT_SYMBOL(mempool_alloc);
+EXPORT_SYMBOL(mempool_alloc_noprof);
 
 /**
  * mempool_free - return an element to the pool.
@@ -515,7 +507,7 @@ void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data)
 {
 	struct kmem_cache *mem = pool_data;
 	VM_BUG_ON(mem->ctor);
-	return kmem_cache_alloc(mem, gfp_mask);
+	return kmem_cache_alloc_noprof(mem, gfp_mask);
 }
 EXPORT_SYMBOL(mempool_alloc_slab);
 
@@ -533,7 +525,7 @@ EXPORT_SYMBOL(mempool_free_slab);
 void *mempool_kmalloc(gfp_t gfp_mask, void *pool_data)
 {
 	size_t size = (size_t)pool_data;
-	return kmalloc(size, gfp_mask);
+	return kmalloc_noprof(size, gfp_mask);
 }
 EXPORT_SYMBOL(mempool_kmalloc);
 
@@ -550,7 +542,7 @@ EXPORT_SYMBOL(mempool_kfree);
 void *mempool_alloc_pages(gfp_t gfp_mask, void *pool_data)
 {
 	int order = (int)(long)pool_data;
-	return alloc_pages(gfp_mask, order);
+	return alloc_pages_noprof(gfp_mask, order);
 }
 EXPORT_SYMBOL(mempool_alloc_pages);
 
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-27-surenb%40google.com.
