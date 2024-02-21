Return-Path: <kasan-dev+bncBC7OD3FKWUERBC5E3GXAMGQEA6XW6II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 12F8B85E798
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:42:05 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-dc74ac7d015sf8974543276.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:42:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544524; cv=pass;
        d=google.com; s=arc-20160816;
        b=zUmz4YotDmNBmVfU3NiH7ZFP30uP51g0DWt+/iCtaaKHodZGaumw9Sv9wminfZNy7B
         jtYYmoX6Hw64DfacJE51/ZcLuQhIQHmr3gDPulJtZhH8Q+idUA1bsC1Zr5CDsnHHQkk3
         lxyPUKPOY1u5lSPb7Pt2Wv1Wmb1zha4EttzE+lVC++cjWAxgKoEQf6cE0L+kFxqG0K9x
         bSPbjKsGM7d0A176mTA1ER064g2WzNam5gOYMOgRX+wIB/Ru7noY8zeHEdhQJh2YhMYR
         d8e5L6MfPDoRmmCyu+DNq+Un6wWP3Z7NocPsnrxj48XVyQMW/cX5+m6V/mt3NFAjqiXm
         C01A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=vf9ossNV0R6BUmrLwpIG1w7AQKcwZNdgFEyxqQnHuz4=;
        fh=DJ4Xc5x1STqpDgJCJF0p3XeoTSLBjrNj8RGxa9UOt+E=;
        b=GFWOIy3LxmUx38jdbL7yhIwBNGKHJ2rSS1WyKF2Ik8tcZv0Rtg6xrwLYFE1KTFt8BO
         nE2qaMJ3r2PHzbOf0t34bURGv8D5nrHu1xX4BIbQOJDV08B+vd9Yqs0TVN+LXehmMOWi
         IJmXECXVLaiVvj20B+KGAfKIy7K935up7awhujE9Mu3gKHy1aJeo2VHwyDxFCjz0EEhJ
         /yt5UHR7Dd6IOCBGF5vYZEpD4VYwX2mzzWmqoFYzi9waRa7CwlpxmmFGxqHCiFRHjW1T
         m6blpvbTsZ3xfrp7uXz9ZgPtZ1TGyZYqSedsAOoeFp3L2vUAjM9X3c7/RDd1B3Nrl0XQ
         kDkA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kQ6av+CD;
       spf=pass (google.com: domain of 3cllwzqykct0rtqdmafnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3ClLWZQYKCT0rtqdmafnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544524; x=1709149324; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=vf9ossNV0R6BUmrLwpIG1w7AQKcwZNdgFEyxqQnHuz4=;
        b=SPSxrY46cNavzlApPnwHa67WZ76gXJDGG3fglJ+vvj0HQBRblzEXtq/wMnJm5U/0c/
         93MZM8R+5sxUFwWFAK3LDRvBkAquvtVFgQQnqYKvnZPf/Iurb4Srl3YMwUDAUxTsCg8Y
         Z1qlNtWNrNUoRMCFtby8pWnGXDDrcmHqCMn2mCJKHq4LLvSd1AVIxSiuYtkfr0RnG5bt
         4ipnytmCNyVd8sBsyZQ3l68zodB1NOovsq5tm8Nu2zl3v761uHCwh/kAGid/F5cdgZXm
         TA7LzRhjMYv3/v4dHYNuZ75DJqIH65PI1bS4GS5h2/o5g5CMExE2OF2HetIvdE6rTrC1
         EA+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544524; x=1709149324;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vf9ossNV0R6BUmrLwpIG1w7AQKcwZNdgFEyxqQnHuz4=;
        b=ZPkAh8hvRFMLf4lWL9WC60Oxrkb5i6dG2s7tk6RbPSYHtVZkj1LhV/7uLKoSTS7RqP
         0PklfqUZmfZcp3GcPWTblOx1RZxjhEtPCBYVP/zIwjtdqZ95HCAjkCEPDRashyR7Yrjh
         8bJsrjUbAfFSZF5kdgrwF1K2mCzOhQkKvJ/fs12wRl9LUhjXc/izkn+GVgMTRF3D45IJ
         ayQLDx5JolYGjjucG0MXUDyw1tdiFTf4PiIi2y4IHMLV6ZeeI73httn+cMVq8qi8F3ig
         4LvCsb8Jy6Vn4IaTbCUaj6F/C88p35xVr4ckUiGj5M3ffoE5k1o73B1SadzcM6xuAzbn
         ocAQ==
X-Forwarded-Encrypted: i=2; AJvYcCX4VsS94m2FFxwAgAUXujikFwcfubkEUNi93Y75tCUWFY1o673dKFL+zBIJbRrmkSQfGU7wkU7Gy1gYsWRtzs3pqZ1DsxLSyw==
X-Gm-Message-State: AOJu0YxFz7jlpui3/wQP4//1OuH9nnOEZToakw6Kj28B9hwaUHzRrWQG
	W0w51uhkpiOHl7ypHXSj8V+kqUGS4r5Le1kna4nB13CoB1QDY3ax
X-Google-Smtp-Source: AGHT+IEcmiCwgf2J86PHjD94QoVA07kKEKX//p7RNyvNnf0AIzPMC1Z2yNNkNMXecylbjTpZYyiFXw==
X-Received: by 2002:a25:ae5d:0:b0:dcb:ccf3:b69 with SMTP id g29-20020a25ae5d000000b00dcbccf30b69mr314795ybe.35.1708544524044;
        Wed, 21 Feb 2024 11:42:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:e092:0:b0:dcc:279c:e5c9 with SMTP id x140-20020a25e092000000b00dcc279ce5c9ls1258125ybg.1.-pod-prod-01-us;
 Wed, 21 Feb 2024 11:42:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCURKmcS18PFY814F5XxlXTqISW8SoQnvswpuAYTIs8otfNYt0wCAf3ZQZiEFEMHMSqZV0MWsUYGvEHWBa8fyjgjnSjPIVzWfJK1WQ==
X-Received: by 2002:a25:d846:0:b0:dc7:594b:f72b with SMTP id p67-20020a25d846000000b00dc7594bf72bmr281040ybg.39.1708544523320;
        Wed, 21 Feb 2024 11:42:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544523; cv=none;
        d=google.com; s=arc-20160816;
        b=wKr850jKaUI8wSdylCFFZwGggQJW/oCaD83gylk7WzpYiJJc4oevlzdroyCxHPNAtK
         xdOA7ID7KYwq6lNSzOrgwP9INLBLVVmESMKdRvkIUYnGx/RQL+6yZsJuVCscK83sy7ov
         uwsRJA/+dFtLb05TedR04XzSGKSobj+YzD85d7yc54cEdKEk+eT7rE0NdvKnR+IXH028
         UK+kJvfGTlQ/wMsRx23Ld589oiXp6D10D3TlMRKIU9PWWKnGEDZlja5fcC4v+PFvVn90
         YRArQg8fI2pE94fBysuYnwH2I/YumtHImdS6v1co5el8RBKuGAq4bW7ec0zWmOI1Vsi6
         yq4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=4ca2CRMzgUqo30S53DRYHeCmPf8DAT9MnFsYZ/BDy7I=;
        fh=4J745A3famUR378MAQmmn+htm3DeSFoSgDr2u8Igsx8=;
        b=g38GGTGsp/mbl9bU/h9+XP9pgk3Lf6eq8SQx60+9F+BBQlE3Q/qFUZt7roHHC3mxac
         s5EdY22B/SB/8osmemCk61qoi1xWzjderfEpY6BulWUEnnegnHbUoFv3KgA4HXGmmrzu
         l1ko/cP4K7uCDNhmCMOT+8nqlANmbp/TPqus/Dlt0AKBUfdLe11vTCq48wHtpb3VPszy
         djXJ9THGjeUf5HpLyksvOQp1y6WhgnPqSqQiCem4jDAfYbkVnhJIA+IOAlNr+SH0rKtr
         fCweGgBdr0LaTAwQjjS3nhQlEvudnKj3+VOMK75uo3CO6aYzWKcAcM+EVDnG1gznpQrt
         kHLQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kQ6av+CD;
       spf=pass (google.com: domain of 3cllwzqykct0rtqdmafnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3ClLWZQYKCT0rtqdmafnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id j7-20020a05620a0a4700b0078758a6738csi438854qka.6.2024.02.21.11.42.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:42:03 -0800 (PST)
Received-SPF: pass (google.com: domain of 3cllwzqykct0rtqdmafnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-60895686ddbso3475017b3.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:42:03 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVesOMpGj69gziOAr3+nMVzNcGjyJQVsPFUGMXRUzstbizKuMxr8YK9j4pM72ZVBa8pbcxcQUCvOJgiI74HJWr+4GTol5mlstmf5A==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a81:fe07:0:b0:608:22c7:1269 with SMTP id
 j7-20020a81fe07000000b0060822c71269mr2041757ywn.0.1708544522852; Wed, 21 Feb
 2024 11:42:02 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:43 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-31-surenb@google.com>
Subject: [PATCH v4 30/36] rhashtable: Plumb through alloc tag
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
 header.i=@google.com header.s=20230601 header.b=kQ6av+CD;       spf=pass
 (google.com: domain of 3cllwzqykct0rtqdmafnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3ClLWZQYKCT0rtqdmafnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com;
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
 include/linux/alloc_tag.h        |  3 +++
 include/linux/rhashtable-types.h | 11 +++++++++--
 lib/rhashtable.c                 | 28 +++++++++++++++++-----------
 3 files changed, 29 insertions(+), 13 deletions(-)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index 86ed5d24a030..29636719b276 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -130,6 +130,8 @@ static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
 	this_cpu_add(tag->counters->bytes, bytes);
 }
 
+#define alloc_tag_record(p)	((p) = current->alloc_tag)
+
 #else /* CONFIG_MEM_ALLOC_PROFILING */
 
 #define DEFINE_ALLOC_TAG(_alloc_tag)
@@ -138,6 +140,7 @@ static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes) {}
 static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_t bytes) {}
 static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
 				 size_t bytes) {}
+#define alloc_tag_record(p)	do {} while (0)
 
 #endif /* CONFIG_MEM_ALLOC_PROFILING */
 
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
index 6ae2ba8e06a2..35d841cf2b43 100644
--- a/lib/rhashtable.c
+++ b/lib/rhashtable.c
@@ -130,7 +130,8 @@ static union nested_table *nested_table_alloc(struct rhashtable *ht,
 	if (ntbl)
 		return ntbl;
 
-	ntbl = kzalloc(PAGE_SIZE, GFP_ATOMIC);
+	ntbl = alloc_hooks_tag(ht->alloc_tag,
+			kmalloc_noprof(PAGE_SIZE, GFP_ATOMIC|__GFP_ZERO));
 
 	if (ntbl && leaf) {
 		for (i = 0; i < PAGE_SIZE / sizeof(ntbl[0]); i++)
@@ -157,7 +158,8 @@ static struct bucket_table *nested_bucket_table_alloc(struct rhashtable *ht,
 
 	size = sizeof(*tbl) + sizeof(tbl->buckets[0]);
 
-	tbl = kzalloc(size, gfp);
+	tbl = alloc_hooks_tag(ht->alloc_tag,
+			kmalloc_noprof(size, gfp|__GFP_ZERO));
 	if (!tbl)
 		return NULL;
 
@@ -181,7 +183,9 @@ static struct bucket_table *bucket_table_alloc(struct rhashtable *ht,
 	int i;
 	static struct lock_class_key __key;
 
-	tbl = kvzalloc(struct_size(tbl, buckets, nbuckets), gfp);
+	tbl = alloc_hooks_tag(ht->alloc_tag,
+			kvmalloc_node_noprof(struct_size(tbl, buckets, nbuckets),
+					     gfp|__GFP_ZERO, NUMA_NO_NODE));
 
 	size = nbuckets;
 
@@ -975,7 +979,7 @@ static u32 rhashtable_jhash2(const void *key, u32 length, u32 seed)
 }
 
 /**
- * rhashtable_init - initialize a new hash table
+ * rhashtable_init_noprof - initialize a new hash table
  * @ht:		hash table to be initialized
  * @params:	configuration parameters
  *
@@ -1016,7 +1020,7 @@ static u32 rhashtable_jhash2(const void *key, u32 length, u32 seed)
  *	.obj_hashfn = my_hash_fn,
  * };
  */
-int rhashtable_init(struct rhashtable *ht,
+int rhashtable_init_noprof(struct rhashtable *ht,
 		    const struct rhashtable_params *params)
 {
 	struct bucket_table *tbl;
@@ -1031,6 +1035,8 @@ int rhashtable_init(struct rhashtable *ht,
 	spin_lock_init(&ht->lock);
 	memcpy(&ht->p, params, sizeof(*params));
 
+	alloc_tag_record(ht->alloc_tag);
+
 	if (params->min_size)
 		ht->p.min_size = roundup_pow_of_two(params->min_size);
 
@@ -1076,26 +1082,26 @@ int rhashtable_init(struct rhashtable *ht,
 
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
-- 
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-31-surenb%40google.com.
