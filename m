Return-Path: <kasan-dev+bncBC7OD3FKWUERBK66X6RAMGQEUGOLHKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id C00226F33EB
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:56:12 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id 41be03b00d2f7-51b67183546sf1424464a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:56:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960171; cv=pass;
        d=google.com; s=arc-20160816;
        b=A5zKJDD8ke7Qkh7GXu4B9P6gwTPPNkoh41ZbIw4iRC6orPireGWSZAL4XMxdI9Ds3M
         QTnEInxvkBtJafo1ub/epcttQ/DfOx90zMR/GLn/78D1336yesubdSPgo3QfVUFpoN6T
         6/PT2RhNDYf3sO/HbWuOCxjcr/YlkycgLL+tNTnoxxNw1Kd/qa013rhw0Q5X3aqH0UW/
         YT08Vlrh5ELgilhWukybteGTO3tjRmc0OKXdNB2RTRLAJ+HIovayL/R1G2ilFnorNsVE
         MAhaOlGL+AUCKDBkrdDRCS6Z/Gj7QRxMGUB/ezT0R9GYq0SszuYR62fWXOg10v9wMKDb
         WHsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=TCwaQtL4UZQMjt7DIMXhGf7yTOeKPavCRBs5c4CBOJU=;
        b=zZpFoAyxb8MZ448FpgilFvPJpn1A5rxUDSTdIjXVQz9MfdARO35aMhxAxF6xK3itQ1
         D6zoGRXKDvojVuQMWO19q9OSHKYTFS0djSX7ufOnW5B53/g/FQxPh0jCa/NYf2buWiQf
         bad1n/qiL9e+aaLoB08mHKVC4Hv9E4MOEUhmU/NbdWK84XmXjaxlEdfkBNo4FgniJUYC
         pFsMEe5/I35NvXiiO25jKjUQ4LCDvvvKKjJpvWaVlS2tfadJQtDTU1CY9Af/nzyTuoAQ
         m9g/p/dvIpIsmli7/ducJLZfGcx95d747HG4U4bo2mfmlxFB8k19bD39qnJ4xZ7JJ2Ty
         LAqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=WvFBiHp4;
       spf=pass (google.com: domain of 3ke9pzaykcxagifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Ke9PZAYKCXAgifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960171; x=1685552171;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=TCwaQtL4UZQMjt7DIMXhGf7yTOeKPavCRBs5c4CBOJU=;
        b=M1fjzsJkSBtwRCv0TLvpVNRmDDn4J0K/eOVPIBWCvRk0Q7PzdAUZG8/xM6XP9Yz3pB
         u94wtfeguU05llvHAu/d5HcznktfNmqNty+fzdCu039bOPi78DllyHwZvjOhMDFY8jlB
         5kDdjt+oVeQK09i+Jlht+PATNNxXI4d5IE9pMaSPgIFyttIl2jK40wpKW4R69xEE9LZP
         DdCNLQ6zwnNpfdGp4bOA/6nhARBwg+wFk4Gp67JSjjQuUuQKOxAz70KIkmzdSJIKHYvn
         2yZMbN1+aW2Fsyxb6kHZRzw1ZE2HZoddNkagj/UNXtcTWXUDwqM6B+1YLVNITcvkhY8J
         x7rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960171; x=1685552171;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TCwaQtL4UZQMjt7DIMXhGf7yTOeKPavCRBs5c4CBOJU=;
        b=gfW4mmBXobtkayMgXsRe295liQX1ET5QEynfVmXGEK/BCevAa5TEQwqqswRiRk37yA
         jP2iZ10svyjVI62rjT1UA5ZYHLKWySbr7S3XMrYqDAEReVI1Bdyw6zStlX7I8EcKddDS
         90JDHs7h6bvSXgYp3ZiIngT52MiEh4MvlkvRmeNODEVHbK4UbWIEgC2nkrQBhozpKa2s
         oyawQvr8nHLbNAz5fxZN6KgwFvFpBGSoUCAFpCwssuhqw0vI4L7vnvsR/T1HmGCyB+Yq
         AfLgxFP5Dd1Mi4nmRPrS/Yj7xiE7HZw/xzGg2GhBTuHkQQN2grHRZSSLzczqqbU4/uIg
         8eQg==
X-Gm-Message-State: AC+VfDycZb2VChn2JdOs1WLT9lqS//5rILk8NX0/ZhbT+KR5Zr1oYO9M
	Ded0dRuX3ToVpExZ/JqI1Yg=
X-Google-Smtp-Source: ACHHUZ7j3HGjtCsigtq8rYZDLHjRQFclTBfFocvqU9DglfiJriE2HK0OzP+szSMTgjMqJABoHEqp7A==
X-Received: by 2002:a63:2a0d:0:b0:513:290b:7516 with SMTP id q13-20020a632a0d000000b00513290b7516mr3485101pgq.3.1682960171360;
        Mon, 01 May 2023 09:56:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:dac5:b0:1a8:b9d:bab0 with SMTP id
 q5-20020a170902dac500b001a80b9dbab0ls11719543plx.4.-pod-prod-gmail; Mon, 01
 May 2023 09:56:10 -0700 (PDT)
X-Received: by 2002:a17:902:d489:b0:1a9:b3a8:2b0a with SMTP id c9-20020a170902d48900b001a9b3a82b0amr17535105plg.15.1682960170634;
        Mon, 01 May 2023 09:56:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960170; cv=none;
        d=google.com; s=arc-20160816;
        b=ANw1LGGy+9MwIFGrSXpicKyI2sVtmwxd/Xl13UT5V9AMmnh6x5uX66d3qVmdxTyjTr
         s7I4jBgABUyuIjALaBiCl267PrGHvBxGBI9PblwA4rUuimq8dUwQFTMOn7eE6ifeaD9B
         KxmmC6/ikFAdygub7yB4tUiEyhBIT3BEUW/CAUjIT51UxiU71Jz8ybmiTZkI2+jqyY7I
         rPxIobwSvTq0Wt3rpG4rNx8eD5Rh8knzNj3EAGTulR3S/QMZA20M4rI7TnRoa0kF8pTN
         xu3f1stihZ0Sg8xvfsmi/9gAkakJp8T7P10Ikzl81hzut6VxO0pYlc8FcQoBhTA83M5B
         aa6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=sqvz5oeuoJjzyL5d6pTK46j/h0psspf4+63tRdELHAU=;
        b=bPanRu/KxzCvBW8SYQje3kEyvezQDVaWaZn4W0LoR3IHP8oAmYYYWgn5WDaNl7rtOH
         57ofbI3ExBsBuBoEpgJ8m9YeXCfL/vs93lEHMIvxQx7qgm4BPUhXaAdlTyEcmNjnG694
         V1YYgiE2BBrnCFdGW8n9JSL3Vm72vpWGoAyQMd9qYmGa7MugbeFtTiMe963nQjzrH23d
         rBFoRgDByYiblWAAuBDp/w8COSIm2gMe29DWnNewN1OfLea9F8URQ35FDcRwSyrK8iDp
         pDnaxBx982qgKo5Zhddf1PipcQwvmtv74KaVqi6LmoxyUwu/GuSSTDAOJCh5GJouhbG4
         LTXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=WvFBiHp4;
       spf=pass (google.com: domain of 3ke9pzaykcxagifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Ke9PZAYKCXAgifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id ka11-20020a170903334b00b001aaf7c46645si194251plb.11.2023.05.01.09.56.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:56:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ke9pzaykcxagifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-b9a7d92d0f7so4769869276.1
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:56:10 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a25:cd08:0:b0:b9a:7cfe:9bf1 with SMTP id
 d8-20020a25cd08000000b00b9a7cfe9bf1mr5044873ybf.8.1682960169618; Mon, 01 May
 2023 09:56:09 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:37 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-28-surenb@google.com>
Subject: [PATCH 27/40] mempool: Hook up to memory allocation profiling
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
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=WvFBiHp4;       spf=pass
 (google.com: domain of 3ke9pzaykcxagifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Ke9PZAYKCXAgifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
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
 mm/mempool.c            | 28 ++++++----------
 2 files changed, 45 insertions(+), 56 deletions(-)

diff --git a/include/linux/mempool.h b/include/linux/mempool.h
index 4aae6c06c5f2..aa6e886b01d7 100644
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
+int _mempool_init(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
 		 mempool_free_t *free_fn, void *pool_data);
+#define mempool_init(...)			\
+	alloc_hooks(_mempool_init(__VA_ARGS__), int, -ENOMEM)
 
 extern mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
 			mempool_free_t *free_fn, void *pool_data);
-extern mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
+
+extern mempool_t *_mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
 			mempool_free_t *free_fn, void *pool_data,
 			gfp_t gfp_mask, int nid);
+#define mempool_create_node(...)			\
+	alloc_hooks(_mempool_create_node(__VA_ARGS__), mempool_t *, NULL)
+
+#define mempool_create(_min_nr, _alloc_fn, _free_fn, _pool_data)	\
+	mempool_create_node(_min_nr, _alloc_fn, _free_fn, _pool_data,	\
+			    GFP_KERNEL, NUMA_NO_NODE)
 
 extern int mempool_resize(mempool_t *pool, int new_min_nr);
 extern void mempool_destroy(mempool_t *pool);
-extern void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask) __malloc;
+
+extern void *_mempool_alloc(mempool_t *pool, gfp_t gfp_mask) __malloc;
+#define mempool_alloc(_pool, _gfp)			\
+	alloc_hooks(_mempool_alloc((_pool), (_gfp)), void *, NULL)
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
index 734bcf5afbb7..4fc90735853c 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -230,17 +230,17 @@ EXPORT_SYMBOL(mempool_init_node);
  *
  * Return: %0 on success, negative error code otherwise.
  */
-int mempool_init(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
+int _mempool_init(mempool_t *pool, int min_nr, mempool_alloc_t *alloc_fn,
 		 mempool_free_t *free_fn, void *pool_data)
 {
 	return mempool_init_node(pool, min_nr, alloc_fn, free_fn,
 				 pool_data, GFP_KERNEL, NUMA_NO_NODE);
 
 }
-EXPORT_SYMBOL(mempool_init);
+EXPORT_SYMBOL(_mempool_init);
 
 /**
- * mempool_create - create a memory pool
+ * mempool_create_node - create a memory pool
  * @min_nr:    the minimum number of elements guaranteed to be
  *             allocated for this pool.
  * @alloc_fn:  user-defined element-allocation function.
@@ -255,15 +255,7 @@ EXPORT_SYMBOL(mempool_init);
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
+mempool_t *_mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
 			       mempool_free_t *free_fn, void *pool_data,
 			       gfp_t gfp_mask, int node_id)
 {
@@ -281,7 +273,7 @@ mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
 
 	return pool;
 }
-EXPORT_SYMBOL(mempool_create_node);
+EXPORT_SYMBOL(_mempool_create_node);
 
 /**
  * mempool_resize - resize an existing memory pool
@@ -377,7 +369,7 @@ EXPORT_SYMBOL(mempool_resize);
  *
  * Return: pointer to the allocated element or %NULL on error.
  */
-void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
+void *_mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
 {
 	void *element;
 	unsigned long flags;
@@ -444,7 +436,7 @@ void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
 	finish_wait(&pool->wait, &wait);
 	goto repeat_alloc;
 }
-EXPORT_SYMBOL(mempool_alloc);
+EXPORT_SYMBOL(_mempool_alloc);
 
 /**
  * mempool_free - return an element to the pool.
@@ -515,7 +507,7 @@ void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data)
 {
 	struct kmem_cache *mem = pool_data;
 	VM_BUG_ON(mem->ctor);
-	return kmem_cache_alloc(mem, gfp_mask);
+	return _kmem_cache_alloc(mem, gfp_mask);
 }
 EXPORT_SYMBOL(mempool_alloc_slab);
 
@@ -533,7 +525,7 @@ EXPORT_SYMBOL(mempool_free_slab);
 void *mempool_kmalloc(gfp_t gfp_mask, void *pool_data)
 {
 	size_t size = (size_t)pool_data;
-	return kmalloc(size, gfp_mask);
+	return _kmalloc(size, gfp_mask);
 }
 EXPORT_SYMBOL(mempool_kmalloc);
 
@@ -550,7 +542,7 @@ EXPORT_SYMBOL(mempool_kfree);
 void *mempool_alloc_pages(gfp_t gfp_mask, void *pool_data)
 {
 	int order = (int)(long)pool_data;
-	return alloc_pages(gfp_mask, order);
+	return _alloc_pages(gfp_mask, order);
 }
 EXPORT_SYMBOL(mempool_alloc_pages);
 
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-28-surenb%40google.com.
