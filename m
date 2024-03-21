Return-Path: <kasan-dev+bncBC7OD3FKWUERB7GE6GXQMGQEL4QZQAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 919FC885DCE
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:38:22 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-1e00e11cfdcsf10978445ad.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:38:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039101; cv=pass;
        d=google.com; s=arc-20160816;
        b=FmrGLgd+r/T8wyl2ww/lqTRQdlnKuPTR8+vP86fAVD9XXMhfSqGMVlLvpHIA76PJ1n
         ANRNn/QQ6dDj89//IpEw4Txki+S+IuXWGOGAz3gFfcoMIPijlNClCpgGkP1aSAAa035l
         JDWy7mpoRkYLK4zLqcFKhWpo9S12J6pj+AyAU7VZSEUyatH50+avUjqhnAafB0bn/Hv3
         cFzo+NUecP8AyuAofQcXMlshFE0hpNuB6ZzxWzwRsiFWeV8y32zqcbcNT+Hfr0pJAWt+
         KLuDgGSGegp1d4HICtb45AmgRgTkpp05rrIyAX6s5MEHTTNqcbnkKMulJTisSLX5o6ko
         K04g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=8ohNUsfokX+6Ap03t013xhMQ4xiOHHegRoaSILnPtGM=;
        fh=ZM4KBGiKJlJTP4E2M4CP6piP2ji1mYBmp4UsyhgCuaM=;
        b=YaFjcrNuQCLkhuO8ty9EREhFO3ye5wiZtM0M1LZBHKNzzrvVo1ZrEcffyflbQjJcgH
         8il/BqLC7mkAzwhE8OfMvv77oBsU7/ko01wOPNaIjALdSgMqT3KLD97QUP6yX25Q6JwY
         /z7KJbKW7LVySkX1mXCSRDYxeollY8eFxQvLdzKAdPbk/QWU0eEiRiicydGemvTCsqv3
         nWsi/hdMoQdu0h5iq2iF1ekwx9YVwJfx2WWWDivybbEdwbk/ojXPC7bkeO8pT6KBm69w
         1mJvHWBnbbehVnraTbZgQKzak5GWfvehox99AtdTTf/CrFvjEfAPW91F/Omfv0WzjhMc
         fVDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WgyMPdyT;
       spf=pass (google.com: domain of 3ewl8zqykcwywyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3eWL8ZQYKCWYWYVIRFKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039101; x=1711643901; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=8ohNUsfokX+6Ap03t013xhMQ4xiOHHegRoaSILnPtGM=;
        b=aLZpXuqkjbhAqxGjAz24mvPGQu41i9cxdiqySOjspT8xyS+0B1/wQgGpVbWq3IaITt
         t/DlOccsnguA+Ps+CKsVp3StdoxsbKk8mvIDKSSZ46CHc5MGtB+Szm9Rz/PiMSwtUp5d
         9CUPr1Nkzdah6wJ+imrhbh2rWIykuv5UYfth+eyFAQaWnTojoNlwtHu9i+AZM3HllAbr
         CMkSJVSQZ7q67xgL2g8TjkLCfR8DoH++BAq2qb7Fd3OQHJusILI6YoIv8Bx/+mwdq8OI
         sX10Bg0PD7GG7jM4RsO9ZtXsf/g8WJCxxnhQFUCWZKh55Re4LxXIH0CoX/VlkIYZ2sLg
         XSBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039101; x=1711643901;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8ohNUsfokX+6Ap03t013xhMQ4xiOHHegRoaSILnPtGM=;
        b=Gki6bd4ZN5g8n4B3OIki0B0433gZwUQW5ykNIbM+Df3OuvleUJRCKKNT4WhT2/wjhc
         0DrTvddQPoN8m7gZcqDsOKFV3csAFYBcEJbY7oSHqGGXx7YaXWinq5b9xc6f6E5XveiY
         naz3X8ZppfWoio2G3NZl0E+0mW0byObaXCmU3L6DUPRLmLYhSGz7g0ooXfQKDIeV9/ax
         0NjGfTtY+lE6p+9ph5q6PLCdB9ecypi4RH8bqBNwD3N4aKGS4HXbRiS7CGuoraaN7VDh
         5QPYWWgZO3nb1HRLZcsDqkZpkmiCFQUhOQ5pExoKSvpbXYBTI5TfF/MYyH5oawDOUEgR
         XzYA==
X-Forwarded-Encrypted: i=2; AJvYcCX+KrOwpTkwZlcCYm792A+OLLalZv6Mvf2FRv2Kmj41IB+miSqMwkbfjegXG7PAuPqeH7+4nYZoVsWfb0DX6TBLgxJXK0HUxA==
X-Gm-Message-State: AOJu0Yw6tX+I2JOgbXZYR6sqBSVdxPLxM0dcp+ummirQSvMz0kqst8G4
	DKW800FSCbOrYvW2CeiCAkPaQLFKT+fiCJIFs/0f6adiRTY24C7U
X-Google-Smtp-Source: AGHT+IHcDWZ4P2Ed7qpV0yDgR2b+AWLydhQtAXR3zqSNqrALV2AkM9nBL/+90+LRTbC61uWrKrIvpQ==
X-Received: by 2002:a17:902:d2c2:b0:1db:5ee2:a772 with SMTP id n2-20020a170902d2c200b001db5ee2a772mr6995523plc.11.1711039101100;
        Thu, 21 Mar 2024 09:38:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ced0:b0:1db:2ca9:b5b8 with SMTP id
 d16-20020a170902ced000b001db2ca9b5b8ls858957plg.1.-pod-prod-07-us; Thu, 21
 Mar 2024 09:38:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXdnNmZeP76FrFnNsAHYQr+rQtqmuLCQ31r54v5nrIoKixjAEVZjx5szhOkiNaM1D0GtBSHE/EsaMaX7fHaXugB+1ph2c9gfoc1Hg==
X-Received: by 2002:a05:6a21:6da1:b0:1a3:5386:f28f with SMTP id wl33-20020a056a216da100b001a35386f28fmr59377pzb.5.1711039098513;
        Thu, 21 Mar 2024 09:38:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039098; cv=none;
        d=google.com; s=arc-20160816;
        b=jTqWBSfGLSvm5YWiHZBJrJ/eBWFHwbsQLeimALla49zIEtO46f9l8RKf2liRRaE3E+
         yeYS7UHLoX/aUsgOdq44gcdX8vVj1XarTdsnMycUVbbMN3n+FUFW1Sys4ev+5NpHVCSt
         RDc/4tRE53YXY/nSeVBANpiD6LyM4sF+IsX6oH4+5HTLkyMRj70hbp+lXA2/OpYADWMv
         vZi0kV83TOcr9NUfaEi4zIF95rUayw27svSHQM+i2ra0kcYNMAnl8Ro85MG6fyoGH28S
         YLpHqhPC6d/9KumtjEEgYmAQBfNpa7IqyGighVfne3m58e7DjP2EcXXhSKTwmuBCNB3M
         4UUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=XaC6gpRUGM+qkcKqV2c0VBwhZNh1AuaCpOBKo907lO0=;
        fh=PUJoR9i3aRHrRYCwH/HfXYAu3Drc18VTSPe1jkL5m60=;
        b=hA8SKvO/tYJ5rwJnLgfMeP72d7Jc2SOa8EhEcXfCHL2rkl45cUBvPkrxdbApQyBMm1
         2RKjRQyk5u3D657Bja++O7T2/pTr0TnyJ+c1xIppPanmCjicJa66MCBgpFpZY2vPgm/f
         iMmW8Q1VQXRyINdbFOFJ5rJQwd8+m5x3F7E/Ks04ZF52z+Z8s3YrgDZtmtO8C82ujSZV
         BlKJathfPyc/Hm9BF4s9xBQHYsuKENkGzxaU4quhTq/WagD0ZHKUzRwTLs1h66EReGRh
         CFSCQuLD8gQ24Afzsp9L/+hbWyIYqfORMVSa1OQD4KoB3zzmwoiubLG5AGVFnMxMb5zn
         Cc/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WgyMPdyT;
       spf=pass (google.com: domain of 3ewl8zqykcwywyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3eWL8ZQYKCWYWYVIRFKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id fd38-20020a056a002ea600b006e72023cb7bsi3465pfb.3.2024.03.21.09.38.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:38:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ewl8zqykcwywyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dccc49ef73eso1590605276.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:38:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW9js84JVHAcBjjGdSa0E09ira+sdxle0fotogdX9ji4Y6/I8K0zqdWV4i/jwLrJe5sRU/19ehyS6AfjnKeVIS2E3bOKCJ3lbNqqA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:1502:b0:dc6:e823:9edb with SMTP id
 q2-20020a056902150200b00dc6e8239edbmr1143317ybu.12.1711039097346; Thu, 21 Mar
 2024 09:38:17 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:53 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-32-surenb@google.com>
Subject: [PATCH v6 31/37] rhashtable: Plumb through alloc tag
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
 header.i=@google.com header.s=20230601 header.b=WgyMPdyT;       spf=pass
 (google.com: domain of 3ewl8zqykcwywyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3eWL8ZQYKCWYWYVIRFKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--surenb.bounces.google.com;
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
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-32-surenb%40google.com.
