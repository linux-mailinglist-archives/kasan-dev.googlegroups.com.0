Return-Path: <kasan-dev+bncBC7OD3FKWUERBVVAVKXAMGQE46OARYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FD07851FEF
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:40 +0100 (CET)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-218e3197761sf360161fac.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774039; cv=pass;
        d=google.com; s=arc-20160816;
        b=LN2+vE2hqDJCps/SLK0T8poNDwzgyJt1SINcghQLlm05Pq7g+U3axVuETOmYiNGY1d
         ITGsD3URguAe7DRRYPOUilsdR69x5Ret0GHPVsVVc4uNAVQHPpbWqSlb/1jJ7nPOK8ol
         KytCNfROJJxDtsoxAhS46qKPobT9vpokkjyMaBNLS7IxB5DymKq7qb6/OhpUyhzsXD0d
         +jYe8V7ItenF4qInbAvpqb5TeaAB0BVqW/O6oL2bV1buKfP2vCwBUicFaPs81JXvwDCe
         H8WEk5lRBqTHxBQ6CtezN+7NiIUYgNvD9BINVYUc5NYF6kPkMk2/BsHFsRw0Of6tN7an
         D1mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Rejs46CXwu+Vgx+U8PMW8vXfmh30JQ8uS/6lYdmWvxk=;
        fh=Dfb6kYg3tXdMfAQ3fCkfPK+XaLCqBauBXp0euaq8154=;
        b=ZEcPqfXIFBWvkduHAC3HbCGnBJbtCA6j+SSdDzA7ikcMU8DKlGZfaE4KFEp8csRFdl
         1XMIlNpNaWxZvQLfv4Lql5C8vmra2vqe59wq70yGWlQoxngByDVZ5pt493s4+Ngaw9UX
         3nCi3D3YgjrKLElNQI4GS6SS6/hkzPFComz4VmKw74ZTe3Xzz3KaV/EvYhYp8qJw98BE
         u9GzTK/pb0a6zEz9Y32yRj51XHPeh4NVUqZXn2ThbYKGEW306gh2PP/DobYMA6x3rP39
         oiQUoDCTG2DCv2zE6SC8vp/yldP+ZY1hXmchZiENY1ZazaiFhUoXfcdhyqWYNeyTh//W
         fOTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CBLcmjll;
       spf=pass (google.com: domain of 3vzdkzqykcdqikh4d16ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3VZDKZQYKCdQIKH4D16EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774039; x=1708378839; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Rejs46CXwu+Vgx+U8PMW8vXfmh30JQ8uS/6lYdmWvxk=;
        b=ArId0ORhDa/6DgX1vtg8CN/mOmvu8kgv3uZ0z+6T0cW0bYHea+p8JGm5SnvtQxzEnh
         6zSnDpCQ1euTcbgJPnyI65n2CdzcqSPGsZlqmAitk3rWw/a8QBVYtTFP1IHuevg3zJCu
         YIPOGoae+9oeV8ZkdN75nOpavQCPe+a9xsid8jbiCTuNnjJah8lmiaJGuPNL2HRp644A
         PvHe3yQ0BbIM545cDFK6CsGrnDRAePnE0JUf1WHBwqh1PwgbW8Ayy4cxM45t1NO4FrYx
         W/C43+O2UpjV9QhZgmep1B4TxcErSFHicKymgc+HBT2ZKrljEgQY5xrL5IAsFFTVW5EA
         IXLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774039; x=1708378839;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Rejs46CXwu+Vgx+U8PMW8vXfmh30JQ8uS/6lYdmWvxk=;
        b=eznAAdzYAcWmUkOsZaCSr9d8h6qSVsEJt8GkKUUM4ILQZiYeeUJMekHs+Po1iM7RZg
         NuUMLCRou12ANB1qCVRjFbKU0mS4mr8SkMo7EQEhBYzT1X9At5bDiB4Yef2+RF91a/WQ
         rcQMBiaiygx35jI/LYxUUnlfT5KiIbdy10zY/V/vK0tMnq7O0TkZKhqDpOsKZ8AryA+M
         t9O0F7qWaxGrOcoeqbZ8nGNE2n2MYR3x9Jhs4R0SkOhzTHo4ryjz2iqyPyi46Yx0jl7K
         dqwxFK1ZA9L6fj1FxBbM07iLi6tdUK/fMxRip+JP6VfMLMwwKV2DZHuNx80c9TAqtl1J
         hrig==
X-Forwarded-Encrypted: i=2; AJvYcCWveMVfzLGwOZZT5KUT64nK2evG7B2W6dP/ITrguuiCl+QAVb1SUfu7G08iPCHJ7tuD7Bzpe6EuQqKuTUf2U8+Yrx5zocRfmQ==
X-Gm-Message-State: AOJu0YyS3hD8pFMEeG9pL6wYdJYrbUGNl4C4SRqvepEIoLI5lf20rnmO
	FdrspwqK9OApT0BVHCKwJqZOzFxzuLBABYOz9vPyFVevx5QsZ11y
X-Google-Smtp-Source: AGHT+IEmmm1v5PZMq7AsAlCTgITNHVzAJkbTOcNqS+MawBVYvmgL+sbYfxPMbZtTwMElb1Q9SRzqtg==
X-Received: by 2002:a05:6870:c8e:b0:210:a9ce:30d1 with SMTP id mn14-20020a0568700c8e00b00210a9ce30d1mr10575016oab.40.1707774038941;
        Mon, 12 Feb 2024 13:40:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:6586:b0:219:d5ab:fb3d with SMTP id
 fp6-20020a056870658600b00219d5abfb3dls1029426oab.1.-pod-prod-02-us; Mon, 12
 Feb 2024 13:40:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVs1wNEQSRecRu8UaeAzLa61SRypvOOBLTZUcoujM7l44D8fCrwZ/0Djf8ABUEGEejjeL7wAV23q0cCPxWJW6Kf6pWyYzaiI9eb/Q==
X-Received: by 2002:a05:6870:828c:b0:21a:3290:9f97 with SMTP id q12-20020a056870828c00b0021a32909f97mr8504273oae.44.1707774037909;
        Mon, 12 Feb 2024 13:40:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774037; cv=none;
        d=google.com; s=arc-20160816;
        b=ume6pe7kOWVKOFe+SVFQBl+1QIbdnTgKqQNM9Hidp/f8nllHspXmK3rZTi6g2dqivh
         SDYxh1hXejiIgn8dYfGkkzsweghsGAbrCmsblI9pKqdLYOHpJgY4lztcXCgI03qGhT9G
         CxQnMv9knnn4Ae9FtqODBDGPfokWSIZhDSIpyfbZyTZoy6XqqpbbZZYEZyHO6+4EFPO4
         vbjmBN2GftYgvABhCGEgHlTff9m1n4f10q9mI8OnXShTS72zs6izVcU6hJP6lUzk5Gnw
         iyX7JMqb3cEseZDRh4tf9KMrNd4Vhu28IQ1dyjqG+t827I6kaFVcLuOmIxlcKO9Qokph
         eZrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=IGO51nbRXLBlE7dZyNty79pnfUUWZlGfdlbPBWriSco=;
        fh=qEx4gtZIZP2MVpGuQd3tupTc3Sohi/ZGH9gwXXNYTDk=;
        b=KA9v2T6M79X6XQN9NK1uinkGvgh/8zj+fYYBFi4Kc/OIrvg0xxwCfgi2rDjAgCISK7
         TyZ//xDEPQ6JhvsyPwXNXQZ8rrvMjb7J1PVuEdsyl3UxzFXK3dfTPslL3Qahr7jm8e2Z
         uAPsLQ7aBTpshoEYAUWxXFhQtXyKsPyV5LwuGJVpZDGH/oa6njOtC2x5Ap7szc+j6cif
         wZkWbXitmumKfAlEKtQLggnRY8O6n4ZeKWpPYU2r5UMy57bzwskENYToEg19KcA6E7NF
         lxTFrTflTgEwsdtH8NB8qDF3qPezYa8vzvHjn/TgV5vGVZT+q1lnLT7QriF3RCkEdWky
         fcvw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CBLcmjll;
       spf=pass (google.com: domain of 3vzdkzqykcdqikh4d16ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3VZDKZQYKCdQIKH4D16EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCWuYKMEyn/60GqDhBFEcdByBHJrIbKkmuW3eYm/efMFwBxygQ7QzYK3WinUxNCcO8g3gaNngRRe/Pe6PVjuWHs4JV3DJxncR87jwA==
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id he22-20020a056870799600b0021a0d307f23si717044oab.3.2024.02.12.13.40.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vzdkzqykcdqikh4d16ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-604a247b168so67698657b3.3
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV3oxnHcbKLo/f307cQIkOAHDsEYJASJrtnc+WOOakAka7/p8wC3Gvw93HminUMLm6TXjVYDJ3YK9vqAK8EQ0HYFf2na4PhQ2rHYQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a25:9c08:0:b0:dc6:f21f:64ac with SMTP id
 c8-20020a259c08000000b00dc6f21f64acmr2107909ybo.12.1707774037425; Mon, 12 Feb
 2024 13:40:37 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:16 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-31-surenb@google.com>
Subject: [PATCH v3 30/35] rhashtable: Plumb through alloc tag
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
 header.i=@google.com header.s=20230601 header.b=CBLcmjll;       spf=pass
 (google.com: domain of 3vzdkzqykcdqikh4d16ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3VZDKZQYKCdQIKH4D16EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--surenb.bounces.google.com;
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
index b6f3797277ff..015c8298bebc 100644
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
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-31-surenb%40google.com.
