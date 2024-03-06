Return-Path: <kasan-dev+bncBC7OD3FKWUERBMHKUKXQMGQEQMEPAOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id 37AEB873EA1
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:54 +0100 (CET)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-607c9677a91sf181027b3.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749553; cv=pass;
        d=google.com; s=arc-20160816;
        b=XpUEb4y9Mi37A+vcA6LIFSd3wEXKzhPiYi7lLtTR9kQiF7pw4OGTIg8CHQbokSL4xk
         qtSXw4m4bg7pwOq3hD41oeo1blKJM1q4q/bRIEAHN4if6F2w3sNcpWzRKJ4Zfu6BTIQI
         K3DOi7C5+YIa5Z1H/7VGenxe0uEjykZLKCjbibssdGkaH9N2DfXLLYpgc1MYWHMSi3DZ
         NHSKHNDgDgldH7ZD36pyluUlA5wstGXA052e30kX8SmTthYpemAwB0+v17WD+IPrVt5P
         Kav4jhfcKkKrlTwx/mjyp3/ZxQnUKL8Rl2d/vHozxi5EB3qX4d0y6O/ebruw+IPe0gNJ
         DBbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=9MWMSc6zwddqPEmNUzEDtDT64gv/91jpPOJRwU8HqWE=;
        fh=jhZTiZMPDomlvIBtQmqAXrpke3s/iNiBQtEpUDGMwIk=;
        b=L+mKSMDnwerFtMOOOW9hxLoFmvkKkgML7tEmZit+y8/5ELGBvbGcErxrW74FjgGsgE
         21GtKVPhCVlUwEj5/0zWCiCUNmt4ZJik4PK8Z0zvdWufxo3vUiSDijU9P8ZUk7kBrhpK
         Xj8jTf9b5CX3BOfHgJPfjqFeYXVGqd4nC8J5r1P19CwP1tsHV08kQHJF2wfq7zRw2Nu5
         iIQNIw7CUqi/4WohhrTSPBW24m1ZIogSLkPeENpcMPsCPh2B90GV/QIg5VRVhDVRjTHX
         3Qr5FWvTMsPdlJDfu7YF2kFUNBSJhi5ea7xr3fz4Pb0cvmXgwnLiaFC6WNbdQLoMZeG3
         xp7w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dQjIEFH1;
       spf=pass (google.com: domain of 3l7xozqykcxiikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3L7XoZQYKCXIikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749553; x=1710354353; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=9MWMSc6zwddqPEmNUzEDtDT64gv/91jpPOJRwU8HqWE=;
        b=A/96dHiuoqbteBOj7sim5DIXb0VCFpqSIeR+cSC7wbQ4K0NLKGKQrQwlQ0j2XrVHoA
         ROfwpvaAVUuLXE9RTM452GY6+I6X7q9/oUHH1xJaSeSMQ5Sn9k+H5MKb3R0uUGkRqzGz
         vjyXUBtN4wqMm0GlZ1WYsoh/Xs0/0+8ZTnbKYriBDclZ10+H5pIFlrJyOjw28aed3jNs
         95VguB5kgkFmRh9Zah2QBARw2EKcPAepg4ptZjAS/aUXk6L992TsCSvCHtvQxqCSDQuZ
         u9eXEXE3Het9iBkbB8JgssGSngUywob2LWl+TmAFx+hOeRNDkwhJ0Wd6ZoxohXpzjS7G
         FEzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749553; x=1710354353;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9MWMSc6zwddqPEmNUzEDtDT64gv/91jpPOJRwU8HqWE=;
        b=r/qpFGOjScyel0uHJ/c0kBrPHdcejHXZcW3kwcPIg5wEkZt5+Nf3CRlBPZvrSYfhep
         +51O/t3tsI73fHL0WFYzDTUX/qoyoZGpaxhjcJJ997zViWJlJbHky7+YHFEAHW2mZpO8
         KdgXWw3ZbaJMs2W1b62hhmopA7Z7/y4sKADZyJLmvTqcgV4H2RzE0IABiFXmbSgcTwra
         4YYZt89rflyz41uwbmMSBc1UVbjqk/DECdvGtjrY5VP0KdGyrk+WiS0dMx2eyCzoDp9u
         j3KHtb7P5DI8/r9WkbWuofrfTH3uoDUC9LO/LeSMbfmJoFzuMMTPRrGIJ+EONmmYPmWg
         SBkw==
X-Forwarded-Encrypted: i=2; AJvYcCUvcuHl2DG8V19LtASB8Na+o0Li9m+hb3CXD17BVPf55ap4MmTSGn9kFJifs3sRIeuY0c8YB3xipUjZ2r3OZ0m8by4JWXZfJA==
X-Gm-Message-State: AOJu0YzcaToKil1dTNJqYtDqC2UMH5L0JaZMBYiKg5WEnxqPW78jM9wo
	DvoAvaWDqumowC8x+lzVkVa4oLFrOAHcVe+rl3FnCk6f4zDoSToi
X-Google-Smtp-Source: AGHT+IE4xnC/rZzTIzJLiV+QJ8tPE/zvk02n/EcwhHZOD8aWgMMYf3sKpqtCUsOVx1kj+JOBvopt4Q==
X-Received: by 2002:a25:5806:0:b0:dc2:3f75:1f79 with SMTP id m6-20020a255806000000b00dc23f751f79mr12839543ybb.23.1709749552993;
        Wed, 06 Mar 2024 10:25:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:69cd:0:b0:dcd:a08f:c83a with SMTP id e196-20020a2569cd000000b00dcda08fc83als101095ybc.2.-pod-prod-05-us;
 Wed, 06 Mar 2024 10:25:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXig/6M7eReHWW6D1DdVEbJ5UmMeY8y+D6VgJTrBFM1ixktJokkSaIK0u3djpfmjt3frBbwa3fa0KQZk9G2FUuBKNonXwp8y6flWg==
X-Received: by 2002:a25:b21a:0:b0:dcd:98bd:7cc8 with SMTP id i26-20020a25b21a000000b00dcd98bd7cc8mr13329042ybj.48.1709749552101;
        Wed, 06 Mar 2024 10:25:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749552; cv=none;
        d=google.com; s=arc-20160816;
        b=0/XYU8Xn+vJt9PHPX0lPt2UZyzxbufbJEFe5qWOUbhagX64vAIDL2VEyXOVQrwhGfR
         y6cy5NzNgvIZinoJThIdBo4GMSWWReAwRGDwz73HNBJAN4yMg90j59YYOuCTWTMRDvWU
         V6VSxQOwpA9rEQYb7Vmpev7D97RMjNDSBW4imPzzHxXQQHu/MHP8kDxYq/h6MPKO+rPT
         etpGhKnRE91t6UvJVeFymxb3PGQJQCiX9ix5vZkw4azE/SoRaue6Wh+vmW623E/3Omb0
         21s644qeO4COsYVTh4FgzdcXKtqinxguLzqa5qG2xk/LG0y5S+/9+k3FOY/sGqDtbgV8
         BN7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Fu+QokTCwH9vHgRIOuSmN9iHLTBbRC7AqqeSJz2bhTE=;
        fh=emgqE8PCl5QXd6G715Nlk8vaourOZToBlZnHqpZLepE=;
        b=d7LcW/YjLBTs6cOwM3o0wCEsxY5j9WGmY+f1Qsk8yU5Da7W6VK8mnR8PfKh2GChVha
         r6KcnWzuOoFWufCPRXoZdVX+MmlR9q1D/J2XQx4QqoAohYmifqGnvkvUKdIWe2gyKhUh
         3iTw8YdLffjgo3UiLBBHYdfzsoY7c0vkhS/QvVfWdfNkNi5gA+7h6MpCCbglucJTVXqc
         EBwzu+JMmGyyz0sHOxIE67TEP4jib9oBpF2UQRQ+RXvhpLNtab9WOTb+5KgfmKZpKJcr
         0vhapkrHUXAwiQBeksTbkKkqKB0LK+9jX9SHcYJ/PVocJp5KPLSYQM6/7Sq1VPPlFeXo
         EtfA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dQjIEFH1;
       spf=pass (google.com: domain of 3l7xozqykcxiikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3L7XoZQYKCXIikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id x132-20020a25ce8a000000b00dc657e7de95si1332026ybe.0.2024.03.06.10.25.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:52 -0800 (PST)
Received-SPF: pass (google.com: domain of 3l7xozqykcxiikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-609dc04bff0so209437b3.2
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:52 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWIatbrG1+HZLIRv3BPzwy3krqLV8Iobv/vPwk4u3OPDEJA53+97EA+MV0SME+ddiDy/l0lQEhZga5OtCGZ+oplGvIfw/wd5TgoBQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:690c:c02:b0:608:66be:2f71 with SMTP id
 cl2-20020a05690c0c0200b0060866be2f71mr3512997ywb.9.1709749551693; Wed, 06 Mar
 2024 10:25:51 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:29 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-32-surenb@google.com>
Subject: [PATCH v5 31/37] rhashtable: Plumb through alloc tag
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
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=dQjIEFH1;       spf=pass
 (google.com: domain of 3l7xozqykcxiikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3L7XoZQYKCXIikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
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
index bc9b1b99a55b..cf69e037f645 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -141,6 +141,8 @@ static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes)
 	ref->ct = NULL;
 }
 
+#define alloc_tag_record(p)	((p) = current->alloc_tag)
+
 #else /* CONFIG_MEM_ALLOC_PROFILING */
 
 #define DEFINE_ALLOC_TAG(_alloc_tag)
@@ -148,6 +150,7 @@ static inline bool mem_alloc_profiling_enabled(void) { return false; }
 static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
 				 size_t bytes) {}
 static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes) {}
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
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-32-surenb%40google.com.
