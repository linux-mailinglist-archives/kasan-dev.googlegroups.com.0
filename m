Return-Path: <kasan-dev+bncBC7OD3FKWUERB2OE6GXQMGQEDH3C2EA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 34788885DBF
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:38:02 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3684b6a0c94sf10813155ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:38:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039081; cv=pass;
        d=google.com; s=arc-20160816;
        b=A59In/fIUfiUPbVKdMg/HZ8RCxNUlAxuuH/o6nBR34NzmgWqfx+oqaLXEQQNxGrloW
         Bv675pNkap+9uCGFKr3nidbJ2KtQ3TFKiZrVxug94pobv5JB01OnTxsAAn4O5gM+IlkX
         A+si/35V/YQrOMP2MXvCYu1QZowzJnCzuJzKqeAGXJDZpHPlA/d8z1JRPCc1TOTgpzD9
         F9+1WftppXmuQWPidsJudAPesWUJnK4IOB9Xq6nI7APxNWQNUuvqq1UT7fKLPBi/viYK
         OCRTBktopxR2uatJTajODpkOrfSL7Cs3g0sVy5uzfEPeEys1P4QGxyhZDLJ6P6NLkBZh
         p3cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=msL0l/yZeEEt4N1W8zfbP6meJ0WSIOoFPDfSpT67CMw=;
        fh=4HCEHUdemOvqxlVb6vpvdEFUMD9c+0hiNlhpJFfSI5o=;
        b=m293D9h0eM9KaSOqQSfF6+PPdH1l06Qytb0FxEkP3/HOXh65ETy1fVqnZomq/kJDgM
         bYHTqCmpm8CbpIE2UbobFbAu//2rHzkLPvsrqnkBB4UuQt846g1uS0XhG8F1L5jshh9h
         mYya23I7FQqVc8UkDm+6Dy+FeoEhvtwS2XmgjA3MJLK6qzpcHewr09LkcW6noK+0rLGV
         R96Lbvl6FCrTJGKz1nR+R1lmo0yFMoph1bpw13UBr4nXHmCzAD9YRJafoTnNce3wpWt7
         WDu8l0lNT215DIZBGdR13BERRTUO4BSAUYEts7yLBZocksI9rUZ1zbzOfLD8gIBdeYTm
         GZSw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ish3cLr2;
       spf=pass (google.com: domain of 3z2l8zqykcvqegd09x2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Z2L8ZQYKCVQEGD09x2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039081; x=1711643881; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=msL0l/yZeEEt4N1W8zfbP6meJ0WSIOoFPDfSpT67CMw=;
        b=S0tY1YOStbdgcs04lwbnkrCMr4biE4iIySi0ywWbne7/Iiij8MBwtDmvLeIPhmHqYW
         AoLX8hECfDgD0L42FKhb7OujCZI3vPWtjlRNl/iTuxStIA7+MQ261c7HzAWmm6xm2662
         xY1ZsZQUX8cdpK1ooyuqqlLIASoimOXJwGKVyn0ZNCSEv8P9DgBivQA2A2rq2WBWtDYz
         SoTsq2Xgw3l1naHKXF72j6p7WC7DiMMBXPjmApHxIeQ8rZ3kfh7srF521nL9UwmeXwZ9
         oDHwkTnmOFCvLC7AHse71JssYC+Yit4EhLFv15VRtFnIDIeyhv4dr1BH9f6rIaCipZid
         oAOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039081; x=1711643881;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=msL0l/yZeEEt4N1W8zfbP6meJ0WSIOoFPDfSpT67CMw=;
        b=drW2gXFLl1eHigYFrksoKuyaEzlL5OnCT5N9qHai06pxqN73oHX90h2XsduzQKdtOc
         neSgH+1b6dVCqkNyVA4ncCYWtYIAwEcYWbVimsBa7Vk4GL7L8CEYsStZKdx1mz5dKjIO
         h6PwiYo1en2R0pm/0fzqVTzEkchB4S6XG5BK1rVQnudhaykm1QkkGrP+emsM2XfIZNeK
         fhWlSlxLsVEsY6Zdu9tQGGVIK3/QbTE+mmoUlcxwDa/UbxCh41HKOph7MLqtpDV3J5sR
         t7SO7p2bdRusEfRXBr5SMFIHYqrMFFi87hYvyn/61gQ8OSsMRpa8WebQBb4E5QNSGS0l
         7zbg==
X-Forwarded-Encrypted: i=2; AJvYcCWPHJ3oTlaFfCpJVWIuX4szvwESIUinWnq2q3ZZwooemQpjkWTFNNUe6ORCl3X+osoOjxjqAQa70J8whAXk0fnetm6V/DzUNQ==
X-Gm-Message-State: AOJu0Yz3/kzKj05CXfRQgv+t0gyj9iANPKn7aJvR/w9ZZ3/yVz3+ShTe
	318bw/aJgT5KgZE28u0mkmLbhJE7lI5d7935jwNNBAVNly9jKgLM
X-Google-Smtp-Source: AGHT+IE0wdhWlsrYmfWgZU5QAlOOF1ayb1+9JgWctxGUzT5wmY3I8/eefpCgAC4c2vPPvtxqkL09wQ==
X-Received: by 2002:a05:6e02:485:b0:367:84ac:e3ab with SMTP id b5-20020a056e02048500b0036784ace3abmr49995ils.14.1711039081096;
        Thu, 21 Mar 2024 09:38:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a61:b0:366:c09b:649b with SMTP id
 w1-20020a056e021a6100b00366c09b649bls770933ilv.1.-pod-prod-02-us; Thu, 21 Mar
 2024 09:38:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX6wSERQ9YqtcmDhc1FLWg7XFF7XMPIlNroEyYIqc34iWhs0ENZOhPFn6HVGLPu44349BBQqwLK69eBSzvVmBJLDtY6+aBgwTwUUg==
X-Received: by 2002:a5d:83d4:0:b0:7c8:41c7:6ac5 with SMTP id u20-20020a5d83d4000000b007c841c76ac5mr23971202ior.6.1711039080363;
        Thu, 21 Mar 2024 09:38:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039080; cv=none;
        d=google.com; s=arc-20160816;
        b=Ih8dAvkJOIX16KmD+X2OWYI2IyEoMC2vCAIVwWln2VR/Go2HuAB2GHfPlkzdcHmeJh
         pP4v7sqjFLCVc5rdAquorr3USfGU3TxtrYjIcL6P0NXFF/DidXGj0sQs5yKQLlA5VQC8
         thhTror+UaDxoxViOadxx5U46AxX7CX9qYKPNeEvPx0osUhRxtMBfR+jgRPPwg8ICIiJ
         obLFJjKqAhu6c7kkINg4Z5gCQNWz47aXyK+zuTDYxdeHl5W1SJ3Wza26RlGOwprj/TiB
         cv7H8N7wxE+osNB+rlh8u51R0wt1uUwqZxXpL3J6iDLWSLLgHjnUj6v71RyORab8Oprn
         czUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=qDb8iz8I8QS6d+rOBOAu9Y4ek6cz/wlqKmX9e9H3T5g=;
        fh=WHA0Y6OCdtQzuL7zMpUBRJK+fRw+/6FU03Wj6oRM9dc=;
        b=IcspHpuG+NTzFmbFxniI4bWASkac0IefpFbPW+HgfCnJfV/WIAqC+pi77Wbk377Pm3
         571yPKYOJhAM1D2vyFoHxLNHtCrB44yKGGLsNuICa/1XEZZSg2DUi6KwX72R/yAP9Rct
         BTHSXs94jsGY9pH+V1Y61a7Mk3ZpwLO9JxRb151m+5PiBRyQk70eq+M7fkuLC6ivRFQM
         gaWp+LlU4no55gE0DeB+v7xIUhYbVG3Ze8i0vKXYjiYTb84Ht7OM4zFwVHyoIJcUhYPA
         dne12aQILFf5CZgMmfjkT5XOFJ5vtuQ6Y0pwMpMwOHnSNaGmQ9hqu/Ic3GMsfluAc/07
         Gatg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ish3cLr2;
       spf=pass (google.com: domain of 3z2l8zqykcvqegd09x2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Z2L8ZQYKCVQEGD09x2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id n17-20020a056638265100b004791bba666esi852753jat.6.2024.03.21.09.38.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:38:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3z2l8zqykcvqegd09x2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dd0ae66422fso2413455276.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:38:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX0PmVW7H3KrRIctgmixyQ+RvRrdwZm+tViRvKjCwNFjD5RmsfMnmURZIzyFunudXJ1cAOIhy4bvWaLM+GH7aRjpl1ZWGGB2E8ZzA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:1604:b0:dd9:2782:d1c6 with SMTP id
 bw4-20020a056902160400b00dd92782d1c6mr9210ybb.1.1711039079759; Thu, 21 Mar
 2024 09:37:59 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:45 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-24-surenb@google.com>
Subject: [PATCH v6 23/37] mm/slab: add allocation accounting into slab
 allocation and free paths
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
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ish3cLr2;       spf=pass
 (google.com: domain of 3z2l8zqykcvqegd09x2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Z2L8ZQYKCVQEGD09x2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--surenb.bounces.google.com;
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
Reviewed-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 96 ++++++++++++++++++++++++++++++++++++++++++++++++++++++-
 1 file changed, 95 insertions(+), 1 deletion(-)

diff --git a/mm/slub.c b/mm/slub.c
index 666dcc3b8a26..5840ab963319 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1932,7 +1932,68 @@ static inline void free_slab_obj_exts(struct slab *slab)
 	kfree(obj_exts);
 	slab->obj_exts = 0;
 }
+
+static inline bool need_slab_obj_ext(void)
+{
+	if (mem_alloc_profiling_enabled())
+		return true;
+
+	/*
+	 * CONFIG_MEMCG_KMEM creates vector of obj_cgroup objects conditionally
+	 * inside memcg_slab_post_alloc_hook. No other users for now.
+	 */
+	return false;
+}
+
+static inline struct slabobj_ext *
+prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
+{
+	struct slab *slab;
+
+	if (!p)
+		return NULL;
+
+	if (s->flags & SLAB_NO_OBJ_EXT)
+		return NULL;
+
+	if (flags & __GFP_NO_OBJ_EXT)
+		return NULL;
+
+	slab = virt_to_slab(p);
+	if (!slab_obj_exts(slab) &&
+	    WARN(alloc_slab_obj_exts(slab, s, flags, false),
+		 "%s, %s: Failed to create slab extension vector!\n",
+		 __func__, s->name))
+		return NULL;
+
+	return slab_obj_exts(slab) + obj_to_index(s, slab, p);
+}
+
+static inline void
+alloc_tagging_slab_free_hook(struct kmem_cache *s, struct slab *slab, void **p,
+			     int objects)
+{
+#ifdef CONFIG_MEM_ALLOC_PROFILING
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
+#endif
+}
+
 #else /* CONFIG_SLAB_OBJ_EXT */
+
 static int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 			       gfp_t gfp, bool new_slab)
 {
@@ -1942,6 +2003,24 @@ static int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 static inline void free_slab_obj_exts(struct slab *slab)
 {
 }
+
+static inline bool need_slab_obj_ext(void)
+{
+	return false;
+}
+
+static inline struct slabobj_ext *
+prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
+{
+	return NULL;
+}
+
+static inline void
+alloc_tagging_slab_free_hook(struct kmem_cache *s, struct slab *slab, void **p,
+			     int objects)
+{
+}
+
 #endif /* CONFIG_SLAB_OBJ_EXT */
 
 #ifdef CONFIG_MEMCG_KMEM
@@ -2370,7 +2449,7 @@ static __always_inline void account_slab(struct slab *slab, int order,
 static __always_inline void unaccount_slab(struct slab *slab, int order,
 					   struct kmem_cache *s)
 {
-	if (memcg_kmem_online())
+	if (memcg_kmem_online() || need_slab_obj_ext())
 		free_slab_obj_exts(slab);
 
 	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
@@ -3823,6 +3902,7 @@ void slab_post_alloc_hook(struct kmem_cache *s,	struct obj_cgroup *objcg,
 			  unsigned int orig_size)
 {
 	unsigned int zero_size = s->object_size;
+	struct slabobj_ext *obj_exts;
 	bool kasan_init = init;
 	size_t i;
 	gfp_t init_flags = flags & gfp_allowed_mask;
@@ -3865,6 +3945,18 @@ void slab_post_alloc_hook(struct kmem_cache *s,	struct obj_cgroup *objcg,
 		kmemleak_alloc_recursive(p[i], s->object_size, 1,
 					 s->flags, init_flags);
 		kmsan_slab_alloc(s, p[i], init_flags);
+		if (need_slab_obj_ext()) {
+			obj_exts = prepare_slab_obj_exts_hook(s, flags, p[i]);
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+			/*
+			 * Currently obj_exts is used only for allocation profiling.
+			 * If other users appear then mem_alloc_profiling_enabled()
+			 * check should be added before alloc_tag_add().
+			 */
+			if (likely(obj_exts))
+				alloc_tag_add(&obj_exts->ref, current->alloc_tag, s->size);
+#endif
+		}
 	}
 
 	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
@@ -4339,6 +4431,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 	       unsigned long addr)
 {
 	memcg_slab_free_hook(s, slab, &object, 1);
+	alloc_tagging_slab_free_hook(s, slab, &object, 1);
 
 	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
 		do_slab_free(s, slab, object, object, 1, addr);
@@ -4349,6 +4442,7 @@ void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
 		    void *tail, void **p, int cnt, unsigned long addr)
 {
 	memcg_slab_free_hook(s, slab, p, cnt);
+	alloc_tagging_slab_free_hook(s, slab, p, cnt);
 	/*
 	 * With KASAN enabled slab_free_freelist_hook modifies the freelist
 	 * to remove objects, whose reuse must be delayed.
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-24-surenb%40google.com.
