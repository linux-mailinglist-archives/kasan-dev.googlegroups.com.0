Return-Path: <kasan-dev+bncBC7OD3FKWUERBDUW36UQMGQE2ORUD7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B74E7D527B
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:59 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3574a84ef27sf50300045ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155278; cv=pass;
        d=google.com; s=arc-20160816;
        b=bJy0S1wPzPYfC6LTvLuEAMAZxpLT+/9Dq/wUYDanwV20tTYd4XqaQ2JUi32ioYhC/v
         qRxHb/sgQCJyPI0u0qVmV6W2gA6ofcgWqTO7Fj7v91Ip9xtztFLyYPZYgjtLjhpu59JY
         KpaRV4WYUhBSGjT70n6xpa7YSbfT2eBGOualI6rkfs9aK8d8xN2SC06GaoFgo6Sp/MHq
         utebdz+Shp9xHFTPRZ5MZ7YGg+SmFUHjzby1d2BvLOCrL+oVsU/+pxRzI2Yj6cSF5WK7
         a2GkjUe9dnd8AEYu4JiGO9bAkYWvUQuou9SAEj9kFTqlf/CcZu8E6nN7z2dp2DnOJCVM
         CnuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=dTw98nyrp5r6/7N1n6nVDvA3zE6BEJV6seubYWW3Ekc=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=gXIRddhDb/qD4KJbX1/3l0+LYSAZwP3Rn+DnpkbJfyazjfw/hm2k0GRJQnMxpAfHr/
         76A+MrtJc6iOh7ikWgTtCnckmGBDwLuO+55vhN9fr+DJzT64QuzE5MA6P0lvb2pjkFU6
         z4NHkDTGt7xBwrEy9ChYqrqTyZEYypgjQo1fyBEAxYaBCmKWR3+pS0vaXJiIZrfgmTT6
         w1wlwrFkjp5rpnUGRe4oCJes57vR6QzBRdGyEYO38QchxR9jWxdVa4vR/odj0oZ+7pHl
         Wju1Qvoq2CdScCXdzDf6X7DVXfsMhJ+jxwfUB1y2DIaP2tXMcF61kA5z0/TiMlUjXE4z
         ApLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MY26pPoY;
       spf=pass (google.com: domain of 3dcs3zqykcbikmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Dcs3ZQYKCbIkmjWfTYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155278; x=1698760078; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dTw98nyrp5r6/7N1n6nVDvA3zE6BEJV6seubYWW3Ekc=;
        b=DCiCFdcfgHVN6Ljz42PacMiZKp5VUQG7XCxQYWSHDCSn6D15yay9grcn9LvJWh1cAT
         7VjGvzJc6+sOMLGPdWbKgj5yzdFQEVkVuDlOHaHFCzySamsODuniaIqo7MMXO1z8Piky
         gjjMjthIRk5j/C9LWVkNVEV2/lfzgagWhS5OY979HvQlcwCFjMgO3YK7XK421kIQUL3D
         FNTbTmknaCsWCL00ip4tbXEP+bEEIpLReYHoZ3ZpCU9VSQGVr5V9UdC+s8DICTGOc/aa
         L5VfekPqxBzFOcMbmKOI36hzg1JzvjPO50IWSUlGsXyqA26OTxshwy9/ZxPECh3GXj+5
         +Dyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155278; x=1698760078;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dTw98nyrp5r6/7N1n6nVDvA3zE6BEJV6seubYWW3Ekc=;
        b=vPA2Z15FlZVVTar7No9TvwhjjCFuoD4AFKB/HLNP/Y5mLTGa7BmvtpjkSYfeEDaC7I
         k+ZZ7UkPXss1WB0tdV/AwhAYsVN8gX+9/4nR9mz6qWisLpvwOgjA8Ku7BNil+wDuvbMH
         QdWqsejJSePe8+2mFfmp6w5cAo6bpSMb1+fS1X06RJxJkMYvS1hNT/3fgpsKowaxpr67
         xM/9qGF9DaJI86UAYgqSiJkEVHBqOnkyvFAq84ZeWMHBhZAHZq97xzupWKHhj0icsAoN
         ojtIzesy/AicoQOj7pzz4/+4pk0CjjWqPwvf800lhwBcCJnbncq+ob/7TV9YQnrO+V0T
         ZLxg==
X-Gm-Message-State: AOJu0YwuzF1+rMks/IC0sUSblhfouhb/isw01JurhmqswDXhvzIELEdn
	dcLcURrw/DX4X4VJLDRXN6pb0A==
X-Google-Smtp-Source: AGHT+IHBOhGa695AYUOQWYpT+lRhXg5SuULbxg/uUsfbhXgKivFsPiSpkN02sZhS5L2lO98m5GCuNg==
X-Received: by 2002:a92:ce8d:0:b0:357:a1cd:a16 with SMTP id r13-20020a92ce8d000000b00357a1cd0a16mr12677465ilo.6.1698155278522;
        Tue, 24 Oct 2023 06:47:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:168d:b0:352:5324:8348 with SMTP id
 f13-20020a056e02168d00b0035253248348ls2728383ila.2.-pod-prod-09-us; Tue, 24
 Oct 2023 06:47:57 -0700 (PDT)
X-Received: by 2002:a6b:c84d:0:b0:79f:cdb4:3f87 with SMTP id y74-20020a6bc84d000000b0079fcdb43f87mr15426228iof.4.1698155277722;
        Tue, 24 Oct 2023 06:47:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155277; cv=none;
        d=google.com; s=arc-20160816;
        b=Kc4h5fRUQh4wXdey8Lb312KpAK2+8tvrj9MvNYjKdn5zj8W/fuaKSsXXiMTiGoZ1Gv
         GCKzegUcvAowhvAbRSNHIMgTh2NXPHicfXL9ALgQdFBHbSKe8czml4rjOIS09ArwwScC
         bMDEfdNP9VytzXJmNFCbjQedp5XLiGrLUMVkL5DE5ngLXerVhhRYXRvZdiNtacCGbi/y
         Sxs8rvk8wUb9oUiSfwiLO2GUtnEWLnObYrJv1afLtSye8NlCK20c2SiJo7AfaBvxhhgW
         DlmdU6tVFUXhciu3WrKbZqJm1LGC26LotnMllNJX5hJswZlAfRV8eLvYHIv2TXZJ58PR
         X8qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=YqQmkpquk/zEN/BrXUtfRL7OAs/mhY9q/VQlYA3NCSg=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=lUrowSciVDZrnwPndsxxo5QbEvQOKwHm4z3ioQNbkh/6j0e64tUH1PDM5XKzeyuuxI
         wAB/AsnZ/UiIM5hOAkBmcr8DacZVqHN8FbirexM304VwBbEyVxForN8n1zkbTYA1T128
         PF1cYHYLdyMcSz+WsBZ2JdNd8f7MZpUJN8yoQ3vbLpPmMZNrdrwblTRhfV48XvvNGwin
         LO0U7hZSqk+Z1vU5+LDsHiHvpq560v9Tb3I4IPlqkDTMmRakDu3Vc4eBhnGA12SJL7s5
         g/S23SR+Habau/URx/o1GbZnimr7mKHaZhGFLsH0LElDWsx8zAzkBeTZ+RPsiXc3A0V5
         uy0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MY26pPoY;
       spf=pass (google.com: domain of 3dcs3zqykcbikmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Dcs3ZQYKCbIkmjWfTYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id f10-20020a05660215ca00b0079f9c4f99absi735863iow.2.2023.10.24.06.47.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dcs3zqykcbikmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-5a7be940fe1so59933937b3.2
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:57 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a81:4853:0:b0:5a8:3f07:ddd6 with SMTP id
 v80-20020a814853000000b005a83f07ddd6mr266393ywa.6.1698155277184; Tue, 24 Oct
 2023 06:47:57 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:31 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-35-surenb@google.com>
Subject: [PATCH v2 34/39] rhashtable: Plumb through alloc tag
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
 header.i=@google.com header.s=20230601 header.b=MY26pPoY;       spf=pass
 (google.com: domain of 3dcs3zqykcbikmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Dcs3ZQYKCbIkmjWfTYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--surenb.bounces.google.com;
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

This gives better memory allocation profiling results; rhashtable
allocations will be accounted to the code that initialized the
rhashtable.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/rhashtable-types.h | 11 +++++--
 lib/rhashtable.c                 | 52 +++++++++++++++++++++++++-------
 2 files changed, 50 insertions(+), 13 deletions(-)

diff --git a/include/linux/rhashtable-types.h b/include/linux/rhashtable-types.h
index 57467cbf4c5b..aac2984c2ef0 100644
--- a/include/linux/rhashtable-types.h
+++ b/include/linux/rhashtable-types.h
@@ -9,6 +9,7 @@
 #ifndef _LINUX_RHASHTABLE_TYPES_H
 #define _LINUX_RHASHTABLE_TYPES_H
 
+#include <linux/alloc_tag.h>
 #include <linux/atomic.h>
 #include <linux/compiler.h>
 #include <linux/mutex.h>
@@ -88,6 +89,9 @@ struct rhashtable {
 	struct mutex                    mutex;
 	spinlock_t			lock;
 	atomic_t			nelems;
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	struct alloc_tag		*alloc_tag;
+#endif
 };
 
 /**
@@ -127,9 +131,12 @@ struct rhashtable_iter {
 	bool end_of_table;
 };
 
-int rhashtable_init(struct rhashtable *ht,
+int rhashtable_init_noprof(struct rhashtable *ht,
 		    const struct rhashtable_params *params);
-int rhltable_init(struct rhltable *hlt,
+#define rhashtable_init(...)	alloc_hooks(rhashtable_init_noprof(__VA_ARGS__))
+
+int rhltable_init_noprof(struct rhltable *hlt,
 		  const struct rhashtable_params *params);
+#define rhltable_init(...)	alloc_hooks(rhltable_init_noprof(__VA_ARGS__))
 
 #endif /* _LINUX_RHASHTABLE_TYPES_H */
diff --git a/lib/rhashtable.c b/lib/rhashtable.c
index 6ae2ba8e06a2..b62116f332b8 100644
--- a/lib/rhashtable.c
+++ b/lib/rhashtable.c
@@ -63,6 +63,27 @@ EXPORT_SYMBOL_GPL(lockdep_rht_bucket_is_held);
 #define ASSERT_RHT_MUTEX(HT)
 #endif
 
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+static inline void rhashtable_alloc_tag_init(struct rhashtable *ht)
+{
+	ht->alloc_tag = current->alloc_tag;
+}
+
+static inline struct alloc_tag *rhashtable_alloc_tag_save(struct rhashtable *ht)
+{
+	return alloc_tag_save(ht->alloc_tag);
+}
+
+static inline void rhashtable_alloc_tag_restore(struct rhashtable *ht, struct alloc_tag *old)
+{
+	alloc_tag_restore(ht->alloc_tag, old);
+}
+#else
+#define rhashtable_alloc_tag_init(ht)
+static inline struct alloc_tag *rhashtable_alloc_tag_save(struct rhashtable *ht) { return NULL; }
+#define rhashtable_alloc_tag_restore(ht, old)
+#endif
+
 static inline union nested_table *nested_table_top(
 	const struct bucket_table *tbl)
 {
@@ -130,7 +151,7 @@ static union nested_table *nested_table_alloc(struct rhashtable *ht,
 	if (ntbl)
 		return ntbl;
 
-	ntbl = kzalloc(PAGE_SIZE, GFP_ATOMIC);
+	ntbl = kmalloc_noprof(PAGE_SIZE, GFP_ATOMIC|__GFP_ZERO);
 
 	if (ntbl && leaf) {
 		for (i = 0; i < PAGE_SIZE / sizeof(ntbl[0]); i++)
@@ -157,7 +178,7 @@ static struct bucket_table *nested_bucket_table_alloc(struct rhashtable *ht,
 
 	size = sizeof(*tbl) + sizeof(tbl->buckets[0]);
 
-	tbl = kzalloc(size, gfp);
+	tbl = kmalloc_noprof(size, gfp|__GFP_ZERO);
 	if (!tbl)
 		return NULL;
 
@@ -180,8 +201,10 @@ static struct bucket_table *bucket_table_alloc(struct rhashtable *ht,
 	size_t size;
 	int i;
 	static struct lock_class_key __key;
+	struct alloc_tag * __maybe_unused old = rhashtable_alloc_tag_save(ht);
 
-	tbl = kvzalloc(struct_size(tbl, buckets, nbuckets), gfp);
+	tbl = kvmalloc_node_noprof(struct_size(tbl, buckets, nbuckets),
+				   gfp|__GFP_ZERO, NUMA_NO_NODE);
 
 	size = nbuckets;
 
@@ -190,6 +213,8 @@ static struct bucket_table *bucket_table_alloc(struct rhashtable *ht,
 		nbuckets = 0;
 	}
 
+	rhashtable_alloc_tag_restore(ht, old);
+
 	if (tbl == NULL)
 		return NULL;
 
@@ -975,7 +1000,7 @@ static u32 rhashtable_jhash2(const void *key, u32 length, u32 seed)
 }
 
 /**
- * rhashtable_init - initialize a new hash table
+ * rhashtable_init_noprof - initialize a new hash table
  * @ht:		hash table to be initialized
  * @params:	configuration parameters
  *
@@ -1016,7 +1041,7 @@ static u32 rhashtable_jhash2(const void *key, u32 length, u32 seed)
  *	.obj_hashfn = my_hash_fn,
  * };
  */
-int rhashtable_init(struct rhashtable *ht,
+int rhashtable_init_noprof(struct rhashtable *ht,
 		    const struct rhashtable_params *params)
 {
 	struct bucket_table *tbl;
@@ -1031,6 +1056,8 @@ int rhashtable_init(struct rhashtable *ht,
 	spin_lock_init(&ht->lock);
 	memcpy(&ht->p, params, sizeof(*params));
 
+	rhashtable_alloc_tag_init(ht);
+
 	if (params->min_size)
 		ht->p.min_size = roundup_pow_of_two(params->min_size);
 
@@ -1076,26 +1103,26 @@ int rhashtable_init(struct rhashtable *ht,
 
 	return 0;
 }
-EXPORT_SYMBOL_GPL(rhashtable_init);
+EXPORT_SYMBOL_GPL(rhashtable_init_noprof);
 
 /**
- * rhltable_init - initialize a new hash list table
+ * rhltable_init_noprof - initialize a new hash list table
  * @hlt:	hash list table to be initialized
  * @params:	configuration parameters
  *
  * Initializes a new hash list table.
  *
- * See documentation for rhashtable_init.
+ * See documentation for rhashtable_init_noprof.
  */
-int rhltable_init(struct rhltable *hlt, const struct rhashtable_params *params)
+int rhltable_init_noprof(struct rhltable *hlt, const struct rhashtable_params *params)
 {
 	int err;
 
-	err = rhashtable_init(&hlt->ht, params);
+	err = rhashtable_init_noprof(&hlt->ht, params);
 	hlt->ht.rhlist = true;
 	return err;
 }
-EXPORT_SYMBOL_GPL(rhltable_init);
+EXPORT_SYMBOL_GPL(rhltable_init_noprof);
 
 static void rhashtable_free_one(struct rhashtable *ht, struct rhash_head *obj,
 				void (*free_fn)(void *ptr, void *arg),
@@ -1222,6 +1249,7 @@ struct rhash_lock_head __rcu **rht_bucket_nested_insert(
 	unsigned int index = hash & ((1 << tbl->nest) - 1);
 	unsigned int size = tbl->size >> tbl->nest;
 	union nested_table *ntbl;
+	struct alloc_tag * __maybe_unused old = rhashtable_alloc_tag_save(ht);
 
 	ntbl = nested_table_top(tbl);
 	hash >>= tbl->nest;
@@ -1236,6 +1264,8 @@ struct rhash_lock_head __rcu **rht_bucket_nested_insert(
 					  size <= (1 << shift));
 	}
 
+	rhashtable_alloc_tag_restore(ht, old);
+
 	if (!ntbl)
 		return NULL;
 
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-35-surenb%40google.com.
