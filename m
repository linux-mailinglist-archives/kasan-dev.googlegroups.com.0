Return-Path: <kasan-dev+bncBC7OD3FKWUERBAMMXKMAMGQEJ2BSKTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id D64865A6F8D
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:49:54 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-11f01b0a51asf2247221fac.19
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:49:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896193; cv=pass;
        d=google.com; s=arc-20160816;
        b=VQSaaTLaM8dFkLZ3L234PXjTDh6HQyH6AZC1YzQJW/YciwOXUnONhAyrGjr/C2SPlf
         0OPof2QTg+wbSTOmsF6bj5ba1mAfD9v2DtzIRn+i+jAoqgX5qbtveTlQt9Cgs5ZO4J5G
         mY+sa/v+5V37mU1fDzdCVedRvQBWwcW4anhSGV7iXI+4+LdwaFR+QHgfWeZN0BZMLEk+
         g05FGeLTfnU4NAKy2/iitgOqkxS8c34fjHMxs6T5iIZlsi097kFeuBh/kDWS5jWEWtJW
         rbQ+xlInmbBUNiIbl19VX7G3IAvi14P8W7iIWg4vktnC82AsEhnm5jG6eF/tB4ZPSpV4
         jRrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=SO13EuI33nMTJ/ILRbVdTwNIf7Wy+saMzHo/PbY5cXg=;
        b=XC6RYLbjxdd7joQ6rBahlXZMW5bahMqrFkWf5/P7RWZF+eNdheeTsOTa1Tv9AXw6PA
         RzKRT0YSmwNmvgNB3477bZCauGwiBLhmW1jZsL7Q+520VLh9l9NhmHbWKnEuBH6cQONX
         1QsB2MggAx+iw6ovxgUHXseK0jKWUheig0Y3uaFLgh3j61BbYs5hG1bWFyPe9AFdDPXb
         UsrexVJ4A18dtm1Wu2GfxxH7vKESI0y4g/qlZ8Dyq3gxEqPOqhZv3izIsYczutYbkJxh
         ixpxNbfJiR/m05bs/F+m3S16xb9RGrm3toE6XsoMitEAEMFBzWuUOqs+W0zpYZVTR1aP
         Z9Dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q6gqHWNQ;
       spf=pass (google.com: domain of 3aiyoywykcwuvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3AIYOYwYKCWUVXUHQEJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=SO13EuI33nMTJ/ILRbVdTwNIf7Wy+saMzHo/PbY5cXg=;
        b=UVbFZCIggLTgbJeTz9yTBJSVVjzp/q6SJP1sp9G7r9+KDjVt6R09kGdNUhxb4EtYxn
         B8iG3zuA3oz2Br8pjEP9PgW6+wCsT6emJVD6I0eZJgGgetaSQ6QSh+ZF4HOepdyREXXf
         nrVMWhDHPXXPktbRnobzyGrDFvNN1T3SC1kTV0D3sNpKRri9LXj9MOGzJcvRZRXS+0/V
         Qcc22/KMsiHFq1d5SCh4SDGfMF9P09y8koi7zVt5RxSv/Pr+C6ryeYVejok6fr8oxAIV
         T7Qb+R3hSF3n4MyQsPrEgiB3xmWPykELeWJggsD/FrGOhL75Rr2op+M6pVcSis50cNWn
         YOYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=SO13EuI33nMTJ/ILRbVdTwNIf7Wy+saMzHo/PbY5cXg=;
        b=OuGpvv5dM/529XIBPk37BFlCH54E1pwl2G8WE2Yc23vECvX5woQtsjAM4yVUx5KKPp
         L+5fqY5jFmpgk4Qv+PSmOFPoY3YHFanWnn80/ULPNzBMyKzJgBxl8LgFQk0Gx5gb3OwT
         Au2MF3JhO6p7O4C8k/mJlYAibWJoHVTUmowH8FUp1ANSqkRJH/+2u3D+T9zihrQqAotX
         /bMKnpLkxY8mBuqe8HBaNNsgjlgGbnxxe5J+9cOn+oLl/O9CWfvW9o8eKypiW+YXcci1
         pd1AIj0uXtXAowtdQLQ2Boc3Ou6/7bXc03fJSJ8OP0vkzGesmj77xA0x+XgRwMOwmYu6
         fE4g==
X-Gm-Message-State: ACgBeo3X6kXwnx+UmSYFKExWGDyVAYRu/hLpAtL5kSyba2YdNS+iJr9N
	gS8Fs5u1rmd0vINvaH+qKwE=
X-Google-Smtp-Source: AA6agR7hiFYqGDF3iH2F4SJYNj57o6UhnTxrSBcAc7WH3xN1kq0pll3EOA93MHZe2OhcYk6Gets25w==
X-Received: by 2002:a05:6808:1389:b0:345:fde:79eb with SMTP id c9-20020a056808138900b003450fde79ebmr23499oiw.21.1661896193638;
        Tue, 30 Aug 2022 14:49:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4d8f:0:b0:335:3a6d:57e6 with SMTP id y15-20020a544d8f000000b003353a6d57e6ls3859963oix.6.-pod-prod-gmail;
 Tue, 30 Aug 2022 14:49:53 -0700 (PDT)
X-Received: by 2002:a05:6808:14cb:b0:344:cc0b:a567 with SMTP id f11-20020a05680814cb00b00344cc0ba567mr29359oiw.204.1661896193258;
        Tue, 30 Aug 2022 14:49:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896193; cv=none;
        d=google.com; s=arc-20160816;
        b=BMnRhJgEyugVcvy93K3YRVeZOrAoAgLkF5VX9zdnmarHVuOxm7SDNfumip6OWS5tlk
         86PjwGkJEYqyQM+PJk0rxgChRLFBvUTl3cogO53abwFqYheikOJIz/5a4rN+ibVWb4T6
         EvZUdmlsilCLFxkPSz9vpgqJ/8kjXy8k2Z+nBRxg0x2cWQ7a4+o0CyYz4R2MxJ2VVOH+
         WOls1uOGozdMMaJKlb0o2/MS53JsdHXm4uFa5nKAmTBLGf/OyEMPel0Sfuo0eZqeKYuS
         +dd5eAO1MGdVtsxIDDxj/FEjBUy7CGL+PjPHnpseyuHEmW1djNWsx+aFuBlYFK36o2Du
         OQRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=QL3vDW0G0EAkws93GOiItwEQTSZQKKs2lme2XWPOm88=;
        b=olfXo9V36uLGl2TuNfOn/VNIJjjXnxO7RfDVbhtzUldesq0wddmClXavNjExhCvhGy
         GMqLfpsfUVNj8+zUKCrBqo29BzVxDAqlgMVIjfRbWeGvKJIjOVpmImnQge8y4ZXoUPif
         MxfVdfwRASjCKgTEhmYgL3EoSjg/n+mLWjuP+wTvYdWmiRZ93OoG7cttHfA6055PgVP8
         OH6NgmT5GxEdOLglOV9WQs0emu6gxCcLKyAt+Ln4Rtr0EeH4t30QMJjasVWTwrYY39jd
         gxPg6pbDgStywnjtys4KAdlrGSLLlKRBgKLbmvEJec8roE5khcmAxx1gpwM7dQsA+CuC
         adWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q6gqHWNQ;
       spf=pass (google.com: domain of 3aiyoywykcwuvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3AIYOYwYKCWUVXUHQEJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id o17-20020a056870969100b0010c5005e1c8si604507oaq.3.2022.08.30.14.49.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:49:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3aiyoywykcwuvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id x27-20020a25ac9b000000b0069140cfbbd9so713392ybi.8
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:49:53 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a25:8402:0:b0:696:42c8:c561 with SMTP id
 u2-20020a258402000000b0069642c8c561mr13648632ybk.435.1661896192809; Tue, 30
 Aug 2022 14:49:52 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:49:00 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-12-surenb@google.com>
Subject: [RFC PATCH 11/30] mm: introduce slabobj_ext to support slab object extensions
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=q6gqHWNQ;       spf=pass
 (google.com: domain of 3aiyoywykcwuvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3AIYOYwYKCWUVXUHQEJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--surenb.bounces.google.com;
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

Currently slab pages can store only vectors of obj_cgroup pointers in
page->memcg_data. Introduce slabobj_ext structure to allow more data
to be stored for each slab object. Wraps obj_cgroup into slabobj_ext
to support current functionality while allowing to extend slabobj_ext
in the future.

Note: ideally the config dependency should be turned the other way around:
MEMCG should depend on SLAB_OBJ_EXT and {page|slab|folio}.memcg_data would
be renamed to something like {page|slab|folio}.objext_data. However doing
this in RFC would introduce considerable churn unrelated to the overall
idea, so avoiding this until v1.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/memcontrol.h |  18 ++++--
 init/Kconfig               |   5 ++
 mm/kfence/core.c           |   2 +-
 mm/memcontrol.c            |  60 ++++++++++---------
 mm/page_owner.c            |   2 +-
 mm/slab.h                  | 119 +++++++++++++++++++++++++------------
 6 files changed, 131 insertions(+), 75 deletions(-)

diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index 6257867fbf95..315399f77173 100644
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -227,6 +227,14 @@ struct obj_cgroup {
 	};
 };
 
+/*
+ * Extended information for slab objects stored as an array in page->memcg_data
+ * if MEMCG_DATA_OBJEXTS is set.
+ */
+struct slabobj_ext {
+	struct obj_cgroup *objcg;
+} __aligned(8);
+
 /*
  * The memory controller data structure. The memory controller controls both
  * page cache and RSS per cgroup. We would eventually like to provide
@@ -363,7 +371,7 @@ extern struct mem_cgroup *root_mem_cgroup;
 
 enum page_memcg_data_flags {
 	/* page->memcg_data is a pointer to an objcgs vector */
-	MEMCG_DATA_OBJCGS = (1UL << 0),
+	MEMCG_DATA_OBJEXTS = (1UL << 0),
 	/* page has been accounted as a non-slab kernel page */
 	MEMCG_DATA_KMEM = (1UL << 1),
 	/* the next bit after the last actual flag */
@@ -401,7 +409,7 @@ static inline struct mem_cgroup *__folio_memcg(struct folio *folio)
 	unsigned long memcg_data = folio->memcg_data;
 
 	VM_BUG_ON_FOLIO(folio_test_slab(folio), folio);
-	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJCGS, folio);
+	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJEXTS, folio);
 	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_KMEM, folio);
 
 	return (struct mem_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
@@ -422,7 +430,7 @@ static inline struct obj_cgroup *__folio_objcg(struct folio *folio)
 	unsigned long memcg_data = folio->memcg_data;
 
 	VM_BUG_ON_FOLIO(folio_test_slab(folio), folio);
-	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJCGS, folio);
+	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJEXTS, folio);
 	VM_BUG_ON_FOLIO(!(memcg_data & MEMCG_DATA_KMEM), folio);
 
 	return (struct obj_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
@@ -517,7 +525,7 @@ static inline struct mem_cgroup *page_memcg_check(struct page *page)
 	 */
 	unsigned long memcg_data = READ_ONCE(page->memcg_data);
 
-	if (memcg_data & MEMCG_DATA_OBJCGS)
+	if (memcg_data & MEMCG_DATA_OBJEXTS)
 		return NULL;
 
 	if (memcg_data & MEMCG_DATA_KMEM) {
@@ -556,7 +564,7 @@ static inline struct mem_cgroup *get_mem_cgroup_from_objcg(struct obj_cgroup *ob
 static inline bool folio_memcg_kmem(struct folio *folio)
 {
 	VM_BUG_ON_PGFLAGS(PageTail(&folio->page), &folio->page);
-	VM_BUG_ON_FOLIO(folio->memcg_data & MEMCG_DATA_OBJCGS, folio);
+	VM_BUG_ON_FOLIO(folio->memcg_data & MEMCG_DATA_OBJEXTS, folio);
 	return folio->memcg_data & MEMCG_DATA_KMEM;
 }
 
diff --git a/init/Kconfig b/init/Kconfig
index 532362fcfe31..82396d7a2717 100644
--- a/init/Kconfig
+++ b/init/Kconfig
@@ -958,6 +958,10 @@ config MEMCG
 	help
 	  Provides control over the memory footprint of tasks in a cgroup.
 
+config SLAB_OBJ_EXT
+	bool
+	depends on MEMCG
+
 config MEMCG_SWAP
 	bool
 	depends on MEMCG && SWAP
@@ -966,6 +970,7 @@ config MEMCG_SWAP
 config MEMCG_KMEM
 	bool
 	depends on MEMCG && !SLOB
+	select SLAB_OBJ_EXT
 	default y
 
 config BLK_CGROUP
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index c252081b11df..c0958e4a32e2 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -569,7 +569,7 @@ static unsigned long kfence_init_pool(void)
 		__folio_set_slab(slab_folio(slab));
 #ifdef CONFIG_MEMCG
 		slab->memcg_data = (unsigned long)&kfence_metadata[i / 2 - 1].objcg |
-				   MEMCG_DATA_OBJCGS;
+				   MEMCG_DATA_OBJEXTS;
 #endif
 	}
 
diff --git a/mm/memcontrol.c b/mm/memcontrol.c
index b69979c9ced5..3f407ef2f3f1 100644
--- a/mm/memcontrol.c
+++ b/mm/memcontrol.c
@@ -2793,7 +2793,7 @@ static void commit_charge(struct folio *folio, struct mem_cgroup *memcg)
 	folio->memcg_data = (unsigned long)memcg;
 }
 
-#ifdef CONFIG_MEMCG_KMEM
+#ifdef CONFIG_SLAB_OBJ_EXT
 /*
  * The allocated objcg pointers array is not accounted directly.
  * Moreover, it should not come from DMA buffer and is not readily
@@ -2801,38 +2801,20 @@ static void commit_charge(struct folio *folio, struct mem_cgroup *memcg)
  */
 #define OBJCGS_CLEAR_MASK	(__GFP_DMA | __GFP_RECLAIMABLE | __GFP_ACCOUNT)
 
-/*
- * mod_objcg_mlstate() may be called with irq enabled, so
- * mod_memcg_lruvec_state() should be used.
- */
-static inline void mod_objcg_mlstate(struct obj_cgroup *objcg,
-				     struct pglist_data *pgdat,
-				     enum node_stat_item idx, int nr)
-{
-	struct mem_cgroup *memcg;
-	struct lruvec *lruvec;
-
-	rcu_read_lock();
-	memcg = obj_cgroup_memcg(objcg);
-	lruvec = mem_cgroup_lruvec(memcg, pgdat);
-	mod_memcg_lruvec_state(lruvec, idx, nr);
-	rcu_read_unlock();
-}
-
-int memcg_alloc_slab_cgroups(struct slab *slab, struct kmem_cache *s,
-				 gfp_t gfp, bool new_slab)
+int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
+			gfp_t gfp, bool new_slab)
 {
 	unsigned int objects = objs_per_slab(s, slab);
 	unsigned long memcg_data;
 	void *vec;
 
 	gfp &= ~OBJCGS_CLEAR_MASK;
-	vec = kcalloc_node(objects, sizeof(struct obj_cgroup *), gfp,
+	vec = kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
 			   slab_nid(slab));
 	if (!vec)
 		return -ENOMEM;
 
-	memcg_data = (unsigned long) vec | MEMCG_DATA_OBJCGS;
+	memcg_data = (unsigned long) vec | MEMCG_DATA_OBJEXTS;
 	if (new_slab) {
 		/*
 		 * If the slab is brand new and nobody can yet access its
@@ -2843,7 +2825,7 @@ int memcg_alloc_slab_cgroups(struct slab *slab, struct kmem_cache *s,
 	} else if (cmpxchg(&slab->memcg_data, 0, memcg_data)) {
 		/*
 		 * If the slab is already in use, somebody can allocate and
-		 * assign obj_cgroups in parallel. In this case the existing
+		 * assign slabobj_exts in parallel. In this case the existing
 		 * objcg vector should be reused.
 		 */
 		kfree(vec);
@@ -2853,6 +2835,26 @@ int memcg_alloc_slab_cgroups(struct slab *slab, struct kmem_cache *s,
 	kmemleak_not_leak(vec);
 	return 0;
 }
+#endif /* CONFIG_SLAB_OBJ_EXT */
+
+#ifdef CONFIG_MEMCG_KMEM
+/*
+ * mod_objcg_mlstate() may be called with irq enabled, so
+ * mod_memcg_lruvec_state() should be used.
+ */
+static inline void mod_objcg_mlstate(struct obj_cgroup *objcg,
+				     struct pglist_data *pgdat,
+				     enum node_stat_item idx, int nr)
+{
+	struct mem_cgroup *memcg;
+	struct lruvec *lruvec;
+
+	rcu_read_lock();
+	memcg = obj_cgroup_memcg(objcg);
+	lruvec = mem_cgroup_lruvec(memcg, pgdat);
+	mod_memcg_lruvec_state(lruvec, idx, nr);
+	rcu_read_unlock();
+}
 
 static __always_inline
 struct mem_cgroup *mem_cgroup_from_obj_folio(struct folio *folio, void *p)
@@ -2863,18 +2865,18 @@ struct mem_cgroup *mem_cgroup_from_obj_folio(struct folio *folio, void *p)
 	 * slab->memcg_data.
 	 */
 	if (folio_test_slab(folio)) {
-		struct obj_cgroup **objcgs;
+		struct slabobj_ext *obj_exts;
 		struct slab *slab;
 		unsigned int off;
 
 		slab = folio_slab(folio);
-		objcgs = slab_objcgs(slab);
-		if (!objcgs)
+		obj_exts = slab_obj_exts(slab);
+		if (!obj_exts)
 			return NULL;
 
 		off = obj_to_index(slab->slab_cache, slab, p);
-		if (objcgs[off])
-			return obj_cgroup_memcg(objcgs[off]);
+		if (obj_exts[off].objcg)
+			return obj_cgroup_memcg(obj_exts[off].objcg);
 
 		return NULL;
 	}
diff --git a/mm/page_owner.c b/mm/page_owner.c
index e4c6f3f1695b..fd4af1ad34b8 100644
--- a/mm/page_owner.c
+++ b/mm/page_owner.c
@@ -353,7 +353,7 @@ static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
 	if (!memcg_data)
 		goto out_unlock;
 
-	if (memcg_data & MEMCG_DATA_OBJCGS)
+	if (memcg_data & MEMCG_DATA_OBJEXTS)
 		ret += scnprintf(kbuf + ret, count - ret,
 				"Slab cache page\n");
 
diff --git a/mm/slab.h b/mm/slab.h
index 4ec82bec15ec..c767ce3f0fe2 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -422,36 +422,94 @@ static inline bool kmem_cache_debug_flags(struct kmem_cache *s, slab_flags_t fla
 	return false;
 }
 
+#ifdef CONFIG_SLAB_OBJ_EXT
+
+static inline bool is_kmem_only_obj_ext(void)
+{
 #ifdef CONFIG_MEMCG_KMEM
+	return sizeof(struct slabobj_ext) == sizeof(struct obj_cgroup *);
+#else
+	return false;
+#endif
+}
+
 /*
- * slab_objcgs - get the object cgroups vector associated with a slab
+ * slab_obj_exts - get the pointer to the slab object extension vector
+ * associated with a slab.
  * @slab: a pointer to the slab struct
  *
- * Returns a pointer to the object cgroups vector associated with the slab,
+ * Returns a pointer to the object extension vector associated with the slab,
  * or NULL if no such vector has been associated yet.
  */
-static inline struct obj_cgroup **slab_objcgs(struct slab *slab)
+static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
 {
 	unsigned long memcg_data = READ_ONCE(slab->memcg_data);
 
-	VM_BUG_ON_PAGE(memcg_data && !(memcg_data & MEMCG_DATA_OBJCGS),
+	VM_BUG_ON_PAGE(memcg_data && !(memcg_data & MEMCG_DATA_OBJEXTS),
 							slab_page(slab));
 	VM_BUG_ON_PAGE(memcg_data & MEMCG_DATA_KMEM, slab_page(slab));
 
-	return (struct obj_cgroup **)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct slabobj_ext *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
 }
 
-int memcg_alloc_slab_cgroups(struct slab *slab, struct kmem_cache *s,
-				 gfp_t gfp, bool new_slab);
-void mod_objcg_state(struct obj_cgroup *objcg, struct pglist_data *pgdat,
-		     enum node_stat_item idx, int nr);
+int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
+			gfp_t gfp, bool new_slab);
 
-static inline void memcg_free_slab_cgroups(struct slab *slab)
+static inline void free_slab_obj_exts(struct slab *slab)
 {
-	kfree(slab_objcgs(slab));
+	struct slabobj_ext *obj_exts;
+
+	if (!memcg_kmem_enabled() && is_kmem_only_obj_ext())
+		return;
+
+	obj_exts = slab_obj_exts(slab);
+	kfree(obj_exts);
 	slab->memcg_data = 0;
 }
 
+static inline void prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
+{
+	struct slab *slab;
+
+	/* If kmem is the only extension then the vector will be created conditionally */
+	if (is_kmem_only_obj_ext())
+		return;
+
+	slab = virt_to_slab(p);
+	if (!slab_obj_exts(slab))
+		WARN(alloc_slab_obj_exts(slab, s, flags, false),
+			"%s, %s: Failed to create slab extension vector!\n",
+			__func__, s->name);
+}
+
+#else /* CONFIG_SLAB_OBJ_EXT */
+
+static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
+{
+	return NULL;
+}
+
+static inline int alloc_slab_obj_exts(struct slab *slab,
+				      struct kmem_cache *s, gfp_t gfp,
+				      bool new_slab)
+{
+	return 0;
+}
+
+static inline void free_slab_obj_exts(struct slab *slab)
+{
+}
+
+static inline void prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
+{
+}
+
+#endif /* CONFIG_SLAB_OBJ_EXT */
+
+#ifdef CONFIG_MEMCG_KMEM
+void mod_objcg_state(struct obj_cgroup *objcg, struct pglist_data *pgdat,
+		     enum node_stat_item idx, int nr);
+
 static inline size_t obj_full_size(struct kmem_cache *s)
 {
 	/*
@@ -519,16 +577,15 @@ static inline void memcg_slab_post_alloc_hook(struct kmem_cache *s,
 		if (likely(p[i])) {
 			slab = virt_to_slab(p[i]);
 
-			if (!slab_objcgs(slab) &&
-			    memcg_alloc_slab_cgroups(slab, s, flags,
-							 false)) {
+			if (!slab_obj_exts(slab) &&
+			    alloc_slab_obj_exts(slab, s, flags, false)) {
 				obj_cgroup_uncharge(objcg, obj_full_size(s));
 				continue;
 			}
 
 			off = obj_to_index(s, slab, p[i]);
 			obj_cgroup_get(objcg);
-			slab_objcgs(slab)[off] = objcg;
+			slab_obj_exts(slab)[off].objcg = objcg;
 			mod_objcg_state(objcg, slab_pgdat(slab),
 					cache_vmstat_idx(s), obj_full_size(s));
 		} else {
@@ -541,14 +598,14 @@ static inline void memcg_slab_post_alloc_hook(struct kmem_cache *s,
 static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
 					void **p, int objects)
 {
-	struct obj_cgroup **objcgs;
+	struct slabobj_ext *obj_exts;
 	int i;
 
 	if (!memcg_kmem_enabled())
 		return;
 
-	objcgs = slab_objcgs(slab);
-	if (!objcgs)
+	obj_exts = slab_obj_exts(slab);
+	if (!obj_exts)
 		return;
 
 	for (i = 0; i < objects; i++) {
@@ -556,11 +613,11 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
 		unsigned int off;
 
 		off = obj_to_index(s, slab, p[i]);
-		objcg = objcgs[off];
+		objcg = obj_exts[off].objcg;
 		if (!objcg)
 			continue;
 
-		objcgs[off] = NULL;
+		obj_exts[off].objcg = NULL;
 		obj_cgroup_uncharge(objcg, obj_full_size(s));
 		mod_objcg_state(objcg, slab_pgdat(slab), cache_vmstat_idx(s),
 				-obj_full_size(s));
@@ -569,27 +626,11 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
 }
 
 #else /* CONFIG_MEMCG_KMEM */
-static inline struct obj_cgroup **slab_objcgs(struct slab *slab)
-{
-	return NULL;
-}
-
 static inline struct mem_cgroup *memcg_from_slab_obj(void *ptr)
 {
 	return NULL;
 }
 
-static inline int memcg_alloc_slab_cgroups(struct slab *slab,
-					       struct kmem_cache *s, gfp_t gfp,
-					       bool new_slab)
-{
-	return 0;
-}
-
-static inline void memcg_free_slab_cgroups(struct slab *slab)
-{
-}
-
 static inline bool memcg_slab_pre_alloc_hook(struct kmem_cache *s,
 					     struct list_lru *lru,
 					     struct obj_cgroup **objcgp,
@@ -627,7 +668,7 @@ static __always_inline void account_slab(struct slab *slab, int order,
 					 struct kmem_cache *s, gfp_t gfp)
 {
 	if (memcg_kmem_enabled() && (s->flags & SLAB_ACCOUNT))
-		memcg_alloc_slab_cgroups(slab, s, gfp, true);
+		alloc_slab_obj_exts(slab, s, gfp, true);
 
 	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
 			    PAGE_SIZE << order);
@@ -636,8 +677,7 @@ static __always_inline void account_slab(struct slab *slab, int order,
 static __always_inline void unaccount_slab(struct slab *slab, int order,
 					   struct kmem_cache *s)
 {
-	if (memcg_kmem_enabled())
-		memcg_free_slab_cgroups(slab);
+	free_slab_obj_exts(slab);
 
 	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
 			    -(PAGE_SIZE << order));
@@ -729,6 +769,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
 			memset(p[i], 0, s->object_size);
 		kmemleak_alloc_recursive(p[i], s->object_size, 1,
 					 s->flags, flags);
+		prepare_slab_obj_exts_hook(s, flags, p[i]);
 	}
 
 	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-12-surenb%40google.com.
