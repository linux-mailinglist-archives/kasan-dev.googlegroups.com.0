Return-Path: <kasan-dev+bncBC7OD3FKWUERBANE3GXAMGQEQNVFFGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id B190C85E790
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:54 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id 46e09a7af769-6e2f83064e3sf2379260a34.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544513; cv=pass;
        d=google.com; s=arc-20160816;
        b=N2QKHiEjZ1aBVVPc3NJWU7h/BJdJ1dmPTNOwPtcRJ05eeEt1+cKnYBVXp73zT+yTOI
         0S6wYLkAOP04yTR+m+emY1lAkVEY7/uUlG5gedRvwbeRCAtcyimhNc15X4eWblQsru+C
         ikMO74b7D1MsLB4kcOz4jixsod8ImgQXjP5ukpJDmAdH29ZIztkBLeCUgnFz4/dyGgvN
         DBTkjAyQoztESHRyAzJDNiKCjYWPbCkrKwmIttHrpKYLnE9qzAfI+EKP8UOX1r4z32Dp
         l9HZs14Tj0j+eHtOccaB2e50frbxyOXqHd9DF+GG6AI96FgRUybl918S3x1nIkfBKq3z
         6S8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=D31cjs+kFQpytwrYw2sRL+nQ7BGd9It48lR3GexP3Kk=;
        fh=2MZE9i3rzkNNzGnqEuXvEoJ9v4D/eQxNwROdgaFTRPw=;
        b=EVpx8XDkHy8+2Bx2EHm6NZXyd6lWIjuYUeeLtruvseOJb4qAN70hOg3JYA9coHqsVa
         TRp4dRWLqvloAZ/5B8Ue+k2ZPhQTjTcm+Cp72Ffk27QcXVWn5DrIk40Lx/PKi8Wa/4Ws
         LpQxLhE1mSRhjf2u0jJgFsPhUhZh46tR4kYFJ8jj6IGpYXcgiW8eF6erAgK/41l1eJPf
         ARl9zJ3xHH7QbXXEw9aHFD//Gcme3y0KB5JghttnKnFd2tXTFnwYmIfj67tE0/CqQjIM
         YdlYGwKVadmzE9Xmhd+Qr4A1eL12JoghWuTnj+vkEPw41otnhSX5XQvvh1vsxP63xXl3
         otWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="F0KJXc/w";
       spf=pass (google.com: domain of 3_1hwzqykctigifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3_1HWZQYKCTIgifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544513; x=1709149313; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=D31cjs+kFQpytwrYw2sRL+nQ7BGd9It48lR3GexP3Kk=;
        b=uFLrePD4kPk5T67k0zGUMvg9LScC2iYmefqGP9A/t+udqy0HlZhNXSWxueyirJO+6J
         gqYc7McOt/sHxy1i884Rs/hIQ51rMRz1QjC3Rm7OKhVMAZ7tho0/rkycmuHwJl/z8f2Q
         4Ow25wyNwt8RO3Hjcub1bfErI39yia6AFRqy+Yx+A0KPlnojhdFk3ywCOK+2ZF2aB813
         FG3ZNk1Zx288dLV1W0xuv0Nqe6RmOw+sHAe4O3mg9aq3dPAHzee5NHT4mXDD36PhhjAB
         3AF5o6efefvnHMukt+4p6yyO91VSazhaliL9tg8JCLO4dvFxEvI5bNuezqZUKemFO3QT
         vqKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544513; x=1709149313;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=D31cjs+kFQpytwrYw2sRL+nQ7BGd9It48lR3GexP3Kk=;
        b=PrxYqyZ8CC9ipJIqT6Dh7/2l8aHZwteiIUHSqn6XNqG87nUQBF6Q07lhwrpWUsdZZD
         2O98D3h+s6hiEwiWYb8cVUbe3dLQ7PxYkK6aoQvqIQ6vkP+ovGd0NIC7QWUXO884MXXb
         lKU6+Xlin4jMfvEFkJ3nDa5lKRC5OTnTMDOw1yIh7N8NJ68OMRZ/5ZxL7WZtE2JiD/Tz
         3oq6iIFLRtUzyT0oYJwRBCBEFzg1YTU4OhaSHxdbeQEK/L+ViVm+VgvJIkxDqKRmUm0Q
         fiqHHtwz84n1pkV7xSCnyET1MuplYagNMy0oeU5U2CE13C0g1If5DLbZPGNj+4DMaV19
         rkoA==
X-Forwarded-Encrypted: i=2; AJvYcCWFrveRrjkFIM4SL6/etFpQc5UN7XXblgJrDbsLMg3DAEHuZ9R/WJdY7nSY4QPH+fsS1SGzC+waXfIQ6//cEPZI2NEpJxo9sA==
X-Gm-Message-State: AOJu0YzZIIsD8cgP6T9rYdrTphJipbSu66+Sg0XMFdOulvQQzTITic7I
	9x8o8MRoW1je6NapMSvjkvpcfABnXp066Qoxqicz4mBC78PrGWga
X-Google-Smtp-Source: AGHT+IEXx3/4zk5C0Pyf6kkTjdhjw1OTiZl+6FIssEtuqiTqHLz8GaUElmNSHaa5ki3GZ/MClCikcA==
X-Received: by 2002:a9d:6008:0:b0:6e2:e415:28e4 with SMTP id h8-20020a9d6008000000b006e2e41528e4mr20653385otj.3.1708544513223;
        Wed, 21 Feb 2024 11:41:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5b87:0:b0:42e:323a:553a with SMTP id a7-20020ac85b87000000b0042e323a553als2438285qta.1.-pod-prod-09-us;
 Wed, 21 Feb 2024 11:41:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXgSBpK/c8SaVM8JtLHy8Xzpq7iPFntmjTkjKM0TicPqydP7BrYM6sPLhTCnZnyvdX9s3rMKsDg767krrXcUtAik3YtcCt9uEfijQ==
X-Received: by 2002:a05:6102:b09:b0:470:605a:69d with SMTP id b9-20020a0561020b0900b00470605a069dmr11227583vst.25.1708544512406;
        Wed, 21 Feb 2024 11:41:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544512; cv=none;
        d=google.com; s=arc-20160816;
        b=vddj7HfqLG+JeAlEY22zkJ3qkTcbEFBmpk0uP/7P0KBqNnfqg32yOUI+acBI/398Vp
         is6bd9ZkMGuVpepnhsE+vfyQ9ZjlqXii+0j/7+yrEhewGjAI4YaZzFjVGEGRooh4/8Di
         27j27oVzdd5OIll2GoFD2sJj43s0BcW55WJuxWzpgJ7zzQrqss8zWiK5Xf6cwKDO8C7A
         BKOjU5DVqdfB82hjyP4f4Jnr+KS64O/Nlxlk85ibACzi7M7h5vWSOvcl/VsFpewTOCAa
         9tojCrjEmmfuKlOZcIKbfwMH+GKWGstqXZ7C38xCxHUeT6ZOaOXQCnhqoMImUGV+3w3H
         dAhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=YoA/f6AawOcdYOB/BdjtQvWuhk/43MsQdrDrIZmlE2o=;
        fh=DynBRayAKiAlprBXB7cc9tq7nvp6zDzO+k+Qck9oo74=;
        b=z51cQA1zCP9/QGJL3UiHt/fFv0aLRxu/lbMWScgOwbRZ1wQu8oCHiSyLoVahzhah/I
         S+LD8zi2ZBbLqwvBPnqYI6XB2QgbP8jXuKJ8sTlSioybPV2EUTfpYIE8QorQ5yQQJwkk
         akzM7f+BRtGDEO7e3RVz12UhJrVf7LfopNaQ2qiahA1/KjIWbZ3OcpJy01QyuZLfCX0F
         mMBznAxhp3duWKzGkNgJp8ZTuBtU9cRof9JFjXhKi5icmNEDeCZKlgzqD9fGeBDpDNr0
         JPSjfo+y+g5NwdDtghDdxnPr2NYDe0VYZMOBxuM33cMiOk54YUTQ3sJqXVvzVPo9NUPE
         P4CA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="F0KJXc/w";
       spf=pass (google.com: domain of 3_1hwzqykctigifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3_1HWZQYKCTIgifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id o7-20020a0561023f8700b00471b755bb08si33833vsv.1.2024.02.21.11.41.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:52 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_1hwzqykctigifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dcdc3db67f0so148948276.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:52 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXc4TXabIiS6LpkF823Ikuq/NK0CWGdMjHjIiMm510R5pWVyAhAd/UPHh4BexvQN6dQYfKa1pLsY9BG2WbeOT9G24zovat113+ERQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a25:c5cd:0:b0:dc7:463a:46d2 with SMTP id
 v196-20020a25c5cd000000b00dc7463a46d2mr46740ybe.0.1708544511751; Wed, 21 Feb
 2024 11:41:51 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:38 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-26-surenb@google.com>
Subject: [PATCH v4 25/36] mempool: Hook up to memory allocation profiling
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
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
 header.i=@google.com header.s=20230601 header.b="F0KJXc/w";       spf=pass
 (google.com: domain of 3_1hwzqykctigifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3_1HWZQYKCTIgifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
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
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-26-surenb%40google.com.
