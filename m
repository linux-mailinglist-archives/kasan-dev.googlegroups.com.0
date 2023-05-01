Return-Path: <kasan-dev+bncBC7OD3FKWUERBI66X6RAMGQEQWGJMGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id B18B76F33E1
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:56:04 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-3f0a65d5a1dsf35934931cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:56:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960163; cv=pass;
        d=google.com; s=arc-20160816;
        b=mfkMLLJ6uXfgwt43OTf8E0FGB2z5/4nPlLMW24YD+PJVFbI/1ZRC6zjZEm6Yb95WGC
         nKhumAVjyJ/mMLhzEFV3Zv2KtMaSPwPR6jv6CB9rOiiCDwJi5iiHtCS/+jsSCcXAAU2z
         KWmLC1qIDT48b/nQWlKiPpG5Jx7GdqLUj2e9d1XdO/+6RVE+DA3AVpYZX5Y4y21+EVag
         5geU3LFs2tnzC6Hx2A994Xp6jDFt8/jHNrn9rGnXjR+CevcIWCaxkm+XIjceTqlqCMnd
         TY8G1CfQFBQa83ixii++IbaVD985q3/gLvKljpKl4QEySksc6be4FcxPQMoFisFRfteK
         s8Wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=q7QwzpICmPgqM1xZo2cdyN9bEyLGyVSOKPfVToV95wk=;
        b=pZ6qIa8LN9LjaO/7lMxSCQz7yUhfaonn00cI6LEJY9v3CMNb58zD3k3Jfka4rvLeq6
         F5nO9LlVzZSO4+2KjENRY8x+VJlK8x4FlS0FV+f/ZEOgmiLR+kWKYNl5CJ6WgZwVrlOw
         Haua8CEmOzcuUgQQv1z6MuqIpyuY29yysiypug7MMr6vxSyaSaIrb3AUXUCeEUqYoaaV
         5Yf4aLA12ovQiWM5zJRk3Pv0SknA5KB0UYpSb4lWujCF9eRc6MUqLOWEXUCNG31DpNUX
         MqXxKMCSxpAMwBWAcOi1Jsy69jnYWnJ8pmF9bwKivd3HHuLpfUODQGkXF8uBX6Kkc6xZ
         WBsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="E3/DZ7A2";
       spf=pass (google.com: domain of 3iu9pzaykcwkzbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Iu9PZAYKCWkZbYLUINVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960163; x=1685552163;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=q7QwzpICmPgqM1xZo2cdyN9bEyLGyVSOKPfVToV95wk=;
        b=fbCSQzwi6Vlb5XmGQDlc1RjksFsU9oJYKMcsl9nDGUBY8zLpIAc6PNi3pwaU3Cma5x
         OgCJqocb7gWpcg6na6T+7LEKoTVo4v/B81IiPqwOiF5Un2Y67MdfHUYaz5RCSXozS4RG
         UScWfCtGIs//IFlFGFPjq6w0Q7VRRoSYKoC6FfEOCPVL9dTzJIxK2yQh1m1rT/h1QyfJ
         k+GQdKOqph3U+P2kLQKQDqkteEQNDBao4dATLvP2qpbfU6TL3YrEyRsuiHrlkmOT+RVl
         KzpAs4t7mnBkiZOTWB6yYZTDFAo+j4xhbbgvtX+rskzG865TPbMyXcbbxWkP30SpLp53
         wLbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960163; x=1685552163;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=q7QwzpICmPgqM1xZo2cdyN9bEyLGyVSOKPfVToV95wk=;
        b=k+IcR8ccZ4j9I2kiKOMMGsh/L0T1oyV2QOvD8gauOjw+nV1aXK/j72EeB8+AFKtegP
         NbL/mR5DO9I4wL+iMm9rdpnKvYYrb810VEDSn9wVkYavBCmAq3Kyo7q7TIBULaNFf+Jl
         e7rMGi63mBzh7EzDJ9iamqAJtQQZ0iuc17M36Kg1KFqTd4vQ2AgAsV1kssShQKIvQgN6
         1WSdhAqQDRvnWjrWp7AbYeA4zn7semsSL3dN/vsNCO7bly1TimQc5etdGmSaVjzjKRBi
         bsDdYcjhfleB6XtpatacQ+QxT1b/vogpqcw9Fxi26T9W1EAnXv8Zmh4p/DZ6qtP0/v1k
         eYiw==
X-Gm-Message-State: AC+VfDzBLBdYBgAAjSq8VO1vSfH/o1gDSMHieZaPa/rK/Os9G+P7RaMh
	eL6A/liEAQh6NkcZRLOTa/8=
X-Google-Smtp-Source: ACHHUZ7Usk7zely2Qj2FrU1AsGwsYpe6jPcJgIWxJFv3kVboYm3E1zw55N+/nFx0IE+bxybosvaswA==
X-Received: by 2002:a05:622a:1a21:b0:3ef:2db1:6e59 with SMTP id f33-20020a05622a1a2100b003ef2db16e59mr5245470qtb.9.1682960163742;
        Mon, 01 May 2023 09:56:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5907:0:b0:61a:86aa:41cb with SMTP id ez7-20020ad45907000000b0061a86aa41cbls2275917qvb.9.-pod-prod-gmail;
 Mon, 01 May 2023 09:56:03 -0700 (PDT)
X-Received: by 2002:a05:6214:20c4:b0:616:58f1:284b with SMTP id 4-20020a05621420c400b0061658f1284bmr885727qve.33.1682960163176;
        Mon, 01 May 2023 09:56:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960163; cv=none;
        d=google.com; s=arc-20160816;
        b=i9+5O8+PXU8W+DxSMnuEdqcrDGW5PCGgtzRuTSHLF8QOws+1GHGzs2PQYCRxP7Vjex
         rxQH8jm1C0C/hHDdNWp8peln8b7F12QFMVMTMqDhQ245Np8SCcygSk6YHFDp2vwhvrst
         ObTTENiNueERwwGX1lz/RzEop1wCF5PLN4j7gzW81E7tidAikDDo//zyfvTZsDa4TZxY
         dc9IgTBX3SlQx5ebVGUUhy9A/SvDshjtyKVxL1jbOxigswzEdpn6LEiTwiHJlTEMIMaF
         pR/uqrPaKGyU/i1JgNi8OuQ0aoRvFzvhLMQrFwi1DvWCRke5lcqXjF4q1cDkC+MLHcCM
         XCng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=UqN7FeV7aPqCmKItkyIx4xBxa3o94vtL5Phvca7QUfw=;
        b=vPMOYpHAHOM8c28Ahq4QaD4wTR9Zop+sV+frmqEkrZHgzdVUvEIoiliwXROIrb1Bd/
         qz0i4I7U/d1oBFpWOKA6kGJUEtboSrXkw9bfEa7tpJOLLvfcLPtLAEz0RlhKqKTxG1vT
         csnHVNIq/nL2bYjB94eeqvwp4kHACw6XbSfLZEvemAZn8/FO8qUD0E38VCDiV23wdY5L
         UngvbWwE0QXECtKKb8m61sWr//+UqsrA6E05dm/eZ8f7FhA34lkO5XTmSINdbad6fKqS
         Zwg27MbcoWQgGtQYWuZng+lIplYqMWXhGRen6NA5PXiy7fI2u+5aNqWAOfqe6y6J3Dj1
         Z55A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="E3/DZ7A2";
       spf=pass (google.com: domain of 3iu9pzaykcwkzbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Iu9PZAYKCWkZbYLUINVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id oo9-20020a056214450900b00619eb7752desi321515qvb.0.2023.05.01.09.56.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:56:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3iu9pzaykcwkzbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b96ee51ee20so3263579276.3
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:56:03 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a05:6902:18d6:b0:b8f:3647:d757 with SMTP id
 ck22-20020a05690218d600b00b8f3647d757mr9026699ybb.11.1682960162837; Mon, 01
 May 2023 09:56:02 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:34 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-25-surenb@google.com>
Subject: [PATCH 24/40] mm/slab: add allocation accounting into slab allocation
 and free paths
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
 header.i=@google.com header.s=20221208 header.b="E3/DZ7A2";       spf=pass
 (google.com: domain of 3iu9pzaykcwkzbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Iu9PZAYKCWkZbYLUINVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--surenb.bounces.google.com;
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

Account slab allocations using codetag reference embedded into slabobj_ext.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/linux/slab_def.h |  2 +-
 include/linux/slub_def.h |  4 ++--
 mm/slab.c                |  4 +++-
 mm/slab.h                | 35 +++++++++++++++++++++++++++++++++++
 4 files changed, 41 insertions(+), 4 deletions(-)

diff --git a/include/linux/slab_def.h b/include/linux/slab_def.h
index a61e7d55d0d3..23f14dcb8d5b 100644
--- a/include/linux/slab_def.h
+++ b/include/linux/slab_def.h
@@ -107,7 +107,7 @@ static inline void *nearest_obj(struct kmem_cache *cache, const struct slab *sla
  *   reciprocal_divide(offset, cache->reciprocal_buffer_size)
  */
 static inline unsigned int obj_to_index(const struct kmem_cache *cache,
-					const struct slab *slab, void *obj)
+					const struct slab *slab, const void *obj)
 {
 	u32 offset = (obj - slab->s_mem);
 	return reciprocal_divide(offset, cache->reciprocal_buffer_size);
diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
index f6df03f934e5..e8be5b368857 100644
--- a/include/linux/slub_def.h
+++ b/include/linux/slub_def.h
@@ -176,14 +176,14 @@ static inline void *nearest_obj(struct kmem_cache *cache, const struct slab *sla
 
 /* Determine object index from a given position */
 static inline unsigned int __obj_to_index(const struct kmem_cache *cache,
-					  void *addr, void *obj)
+					  void *addr, const void *obj)
 {
 	return reciprocal_divide(kasan_reset_tag(obj) - addr,
 				 cache->reciprocal_size);
 }
 
 static inline unsigned int obj_to_index(const struct kmem_cache *cache,
-					const struct slab *slab, void *obj)
+					const struct slab *slab, const void *obj)
 {
 	if (is_kfence_address(obj))
 		return 0;
diff --git a/mm/slab.c b/mm/slab.c
index ccc76f7455e9..026f0c08708a 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3367,9 +3367,11 @@ static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
 static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
 					 unsigned long caller)
 {
+	struct slab *slab = virt_to_slab(objp);
 	bool init;
 
-	memcg_slab_free_hook(cachep, virt_to_slab(objp), &objp, 1);
+	memcg_slab_free_hook(cachep, slab, &objp, 1);
+	alloc_tagging_slab_free_hook(cachep, slab, &objp, 1);
 
 	if (is_kfence_address(objp)) {
 		kmemleak_free_recursive(objp, cachep->flags);
diff --git a/mm/slab.h b/mm/slab.h
index f953e7c81e98..f9442d3a10b2 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -494,6 +494,35 @@ prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
 
 #endif /* CONFIG_SLAB_OBJ_EXT */
 
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+
+static inline void alloc_tagging_slab_free_hook(struct kmem_cache *s, struct slab *slab,
+					void **p, int objects)
+{
+	struct slabobj_ext *obj_exts;
+	int i;
+
+	if (!mem_alloc_profiling_enabled())
+		return;
+
+	obj_exts = slab_obj_exts(slab);
+	if (!obj_exts)
+		return;
+
+	for (i = 0; i < objects; i++) {
+		unsigned int off = obj_to_index(s, slab, p[i]);
+
+		alloc_tag_sub(&obj_exts[off].ref, s->size);
+	}
+}
+
+#else
+
+static inline void alloc_tagging_slab_free_hook(struct kmem_cache *s, struct slab *slab,
+					void **p, int objects) {}
+
+#endif /* CONFIG_MEM_ALLOC_PROFILING */
+
 #ifdef CONFIG_MEMCG_KMEM
 void mod_objcg_state(struct obj_cgroup *objcg, struct pglist_data *pgdat,
 		     enum node_stat_item idx, int nr);
@@ -776,6 +805,12 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
 					 s->flags, flags);
 		kmsan_slab_alloc(s, p[i], flags);
 		obj_exts = prepare_slab_obj_exts_hook(s, flags, p[i]);
+
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+		/* obj_exts can be allocated for other reasons */
+		if (likely(obj_exts) && mem_alloc_profiling_enabled())
+			alloc_tag_add(&obj_exts->ref, current->alloc_tag, s->size);
+#endif
 	}
 
 	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-25-surenb%40google.com.
