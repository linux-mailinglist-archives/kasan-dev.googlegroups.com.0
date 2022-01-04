Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBE5BZ2HAMGQEW6V77UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F08C483969
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Jan 2022 01:11:00 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id i16-20020a056512319000b00425efb1c65esf7068649lfe.5
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Jan 2022 16:11:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1641255060; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZtS/EBvZYsYSTEKbKCbGEGwaN1keHyaDsKN2vgn0VcH7d3/Scodz50VSlE/Zs7Sn5a
         Yk4q/neEX+xgVfhpae1ANGTOn8/QMRe5AYeYoalJRVk/76H4at1Mph5vzFSfhVFdL0qD
         u5jXbdUpLrU85WMUJw9pumNYsT28srzkC9v5rfaVUgZy1BLpznUoW57/qlGsNmrOn1aN
         PhmXjw0XtQGL8s/1oSAzl57LJwv4Do6htJHvbXurQhMIiKfr4y04Y6/FlbXIOn3/u/mh
         5TcNJxV6ba2+p+xViy3bQWABYVh0wD6T4zEmaQU3zfd10fGFeg+I+TqjcGkCoga07hcq
         ZlzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/ey+Khyzu30XbwV8p7QHkjAs+iegFvVa/Q62NM1/9kQ=;
        b=ftE5zzE02+QcrjTSUtSj5Ft8QQjYWQT6enU6uXc8znl8Kgr570Yoo2LzR2vm4sNUke
         zsCqcdTSrHuacfvWNRKwQFDbVQkj21qAqb5DOahIcnw7tJYbXdxd9wgGRul96MnEYGXZ
         Teavr965qISZI650k9o9CFDmQzF2AWJ1w2Yuc6eZt4y9Xoy5moqpOWpMgQhLqrXk/V+D
         Ec6N+rCb6FTHVnz4ld5ziW1rjg3N5/r+6FMshf/N6hha3DN1EItFZzdRGXaLRVyF2FSI
         b5SNS61oE5xV8NrXrQBKK/9fnLTwhiQ+NvoGZXk8XxEmZzWLadF5qz249IDrT1Uq6tad
         Myew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=AUkRrizX;
       dkim=neutral (no key) header.i=@suse.cz header.b=O1wL2eL5;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/ey+Khyzu30XbwV8p7QHkjAs+iegFvVa/Q62NM1/9kQ=;
        b=pmSfd1UzcSCu/dW29zodkkduaMZ582ysQv0oNWRT0q16g51ZqUGz4OcJKz44pRkx9r
         UTEpDBBgNlK2FSHHy+QDKI0bkAeiPL1fn1jKl/WkMc8rsE754TysQkE5pCV509JuVcbJ
         IeyIYUWAUPOtLIHBAZyr2iJ5O8secAeVa7uQTFR2EAkan545vkFoGCtRabr6Kn+tb65G
         nXhN/KEhy3hksfalwDWjLL292lT8LFqMXbJAE7tYJxe1TXwV/iN57RmzbeizBDcnn4oe
         FGycFtOB1dYyLtJfEuYcSxuX1wdEleVw5aDV+iKkIvw49paMc7xzOVZGvtMxGaBARB04
         kXjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/ey+Khyzu30XbwV8p7QHkjAs+iegFvVa/Q62NM1/9kQ=;
        b=CYiDRj4zrxnKI33CWktnNV5J+zKGtQxvacp5UBH4BpnyG9jfHCMrSNCnpXOrzhKgmh
         tXZrHZwXl49uT5n9xO+xWQot5ePLDD56pfz8eSVFfSGotEnDhenY4XVrDKz6kshRe2Mo
         M6yuhGTqBDEsXFQsSnG3VPdO98yZiPqwQc06P9CQn/rNuwcKuT0aE+oITAKN/t4lmHI+
         PObBfW7JRmFjaSpxQK3aswL9qQHNmaKbO8PteVrS3LRb+IcQpzIS/KahqY/WGvZWu7gd
         muK4mZbus7RLfQlStxOo7sQY2XtIzgnCBtWLq/GHGhLy68r6CmlO7QEVhya9U3Os/79C
         b84w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531dqbXr77HrNv4SxXO7lkzTMJJ8IXmUfj/A4FN0J24B128eS1FJ
	/1qa+w5Up1cSVZUZWlBnHAY=
X-Google-Smtp-Source: ABdhPJyQKeNwnSw6+L7n1foT6B94IQ54CGfDwKiHzlT9gVt4w8geUNM8x2oUrtrcW2Cu5wjpGE8dqQ==
X-Received: by 2002:a05:651c:12c6:: with SMTP id 6mr11518888lje.64.1641255060026;
        Mon, 03 Jan 2022 16:11:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d2a:: with SMTP id d42ls3758466lfv.0.gmail; Mon,
 03 Jan 2022 16:10:59 -0800 (PST)
X-Received: by 2002:a05:6512:1320:: with SMTP id x32mr42413464lfu.597.1641255058976;
        Mon, 03 Jan 2022 16:10:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1641255058; cv=none;
        d=google.com; s=arc-20160816;
        b=WG+l7vHEs+tAVC8cTTp9vH0P511uSaynOimcT4sjZbjXj81XvS7KLip7yRUmnXNSCR
         H61sGEzaiUvCn6trftTjwKbcQbIDGuh2EI4LiMIfoI1xIHWSpN2CmLH7yNIJWSDq4dgK
         blbGF18zNnuYc87kn9yIWTqeZfe6ucl+amT1yQzhjucCTMsbPsRM1I+lD81T8cfz5Nxx
         aZbZU5CopMUPZpJzXXtegJ1QT10Bb9GEas5xAOptQ5XdcJPRGhEowg/6IxcqwtZGc4tc
         heQ9iMbpQHlkppk2YYyUjvryO1qnahvr01wCNpWRWEa0FLaHc4/gRzR5rWjtnt/S0h83
         xmDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=k1aP1H3gZub0Fj1TB2XSfEIIHHSvF+Is3iFZ5RrJTgo=;
        b=goPK72qO9ftLDCo7tt7kGcBUN0O6vwezrYuIA4NE8N9Wb04LwM48ZerxphEG8RwQO0
         un/e7XEYHWEChgyEE8Bw6UQW4cx/dVV5Q7aYRpECGrDY6uYt1NYc9LdA1SFoVz2yZyyy
         jfcHk5EKLN96XvA+X36MH1vpbumKehbmwiUgIbPbFHPettyIfK0iHQWx8ROBF88ypRco
         Qhwd9SaOy8j5hugZeeUfAtUHYX9rKR7ORg0Da0tOAr6FRMxMFfnlSUmlsxq62RcP4RVA
         A3jVHbiJEQsYasKyoRR3zwtzC1+qWVHY8Gb77W2onqfq1LYIjPmPo/smecGoCzpqHKwJ
         Ay8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=AUkRrizX;
       dkim=neutral (no key) header.i=@suse.cz header.b=O1wL2eL5;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id m9si946667ljb.2.2022.01.03.16.10.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 Jan 2022 16:10:58 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 697021F3A0;
	Tue,  4 Jan 2022 00:10:58 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 2729B139EE;
	Tue,  4 Jan 2022 00:10:58 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id yPvnCJKQ02FEQwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 04 Jan 2022 00:10:58 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Matthew Wilcox <willy@infradead.org>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>
Cc: linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Roman Gushchin <guro@fb.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	patches@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: [PATCH v4 27/32] mm/sl*b: Differentiate struct slab fields by sl*b implementations
Date: Tue,  4 Jan 2022 01:10:41 +0100
Message-Id: <20220104001046.12263-28-vbabka@suse.cz>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220104001046.12263-1-vbabka@suse.cz>
References: <20220104001046.12263-1-vbabka@suse.cz>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=4766; h=from:subject; bh=tzoD5++2YRy16vDKaIssaQ11l6KE3UqozYmvo9wnsUo=; b=owEBbQGS/pANAwAIAeAhynPxiakQAcsmYgBh05CBUaOSgvHFSWfYNQ4OVMfEVJdV8pJr0zGLPgk3 fR6keFaJATMEAAEIAB0WIQSNS5MBqTXjGL5IXszgIcpz8YmpEAUCYdOQgQAKCRDgIcpz8YmpEBBuCA Cw7EXv/xlgmv/hcrOed+zE/fI/RI/FRRCDSDuMmcfvoYzDeKIjNV9sqyZWHgV865oHL3Fe7AbdSYZ+ BXrHvt3HfRuVnJproPRjZObTtCpxjGWFLxxyYQoLtcx02sMBejWxH4wdGSpyZzk2tZQS4lu/xjvOWs Un2Dd0ytGhdC2mdgM1iftxK03tsxDZdV26h64VQl8SYKQGilonMTDAyTas1f2bUfeRMhWowysCg1T5 bcbYbbCk51RDM9muuUPhjls+OSTLImgbKgaUj9YHClM4+Ltc33ZZHZcuc6Oqs55uZa8Tsl1wnc9sZ5 2GkVgj3yETuHGit/M8HQ3BbV8eLHMw
X-Developer-Key: i=vbabka@suse.cz; a=openpgp; fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=AUkRrizX;       dkim=neutral
 (no key) header.i=@suse.cz header.b=O1wL2eL5;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Content-Type: text/plain; charset="UTF-8"
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

With a struct slab definition separate from struct page, we can go
further and define only fields that the chosen sl*b implementation uses.
This means everything between __page_flags and __page_refcount
placeholders now depends on the chosen CONFIG_SL*B. Some fields exist in
all implementations (slab_list) but can be part of a union in some, so
it's simpler to repeat them than complicate the definition with ifdefs
even more.

The patch doesn't change physical offsets of the fields, although it
could be done later - for example it's now clear that tighter packing in
SLOB could be possible.

This should also prevent accidental use of fields that don't exist in
given implementation. Before this patch virt_to_cache() and
cache_from_obj() were visible for SLOB (albeit not used), although they
rely on the slab_cache field that isn't set by SLOB. With this patch
it's now a compile error, so these functions are now hidden behind
an #ifndef CONFIG_SLOB.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
Tested-by: Marco Elver <elver@google.com> # kfence
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: <kasan-dev@googlegroups.com>
---
 mm/kfence/core.c |  9 +++++----
 mm/slab.h        | 48 ++++++++++++++++++++++++++++++++++++++----------
 2 files changed, 43 insertions(+), 14 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 4eb60cf5ff8b..267dfde43b91 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -427,10 +427,11 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	/* Set required slab fields. */
 	slab = virt_to_slab((void *)meta->addr);
 	slab->slab_cache = cache;
-	if (IS_ENABLED(CONFIG_SLUB))
-		slab->objects = 1;
-	if (IS_ENABLED(CONFIG_SLAB))
-		slab->s_mem = addr;
+#if defined(CONFIG_SLUB)
+	slab->objects = 1;
+#elif defined(CONFIG_SLAB)
+	slab->s_mem = addr;
+#endif
 
 	/* Memory initialization. */
 	for_each_canary(meta, set_canary_byte);
diff --git a/mm/slab.h b/mm/slab.h
index 36e0022d8267..b8da249f44f9 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -8,9 +8,24 @@
 /* Reuses the bits in struct page */
 struct slab {
 	unsigned long __page_flags;
+
+#if defined(CONFIG_SLAB)
+
 	union {
 		struct list_head slab_list;
-		struct {	/* Partial pages */
+		struct rcu_head rcu_head;
+	};
+	struct kmem_cache *slab_cache;
+	void *freelist;	/* array of free object indexes */
+	void *s_mem;	/* first object */
+	unsigned int active;
+
+#elif defined(CONFIG_SLUB)
+
+	union {
+		struct list_head slab_list;
+		struct rcu_head rcu_head;
+		struct {
 			struct slab *next;
 #ifdef CONFIG_64BIT
 			int slabs;	/* Nr of slabs left */
@@ -18,25 +33,32 @@ struct slab {
 			short int slabs;
 #endif
 		};
-		struct rcu_head rcu_head;
 	};
-	struct kmem_cache *slab_cache; /* not slob */
+	struct kmem_cache *slab_cache;
 	/* Double-word boundary */
 	void *freelist;		/* first free object */
 	union {
-		void *s_mem;	/* slab: first object */
-		unsigned long counters;		/* SLUB */
-		struct {			/* SLUB */
+		unsigned long counters;
+		struct {
 			unsigned inuse:16;
 			unsigned objects:15;
 			unsigned frozen:1;
 		};
 	};
+	unsigned int __unused;
+
+#elif defined(CONFIG_SLOB)
+
+	struct list_head slab_list;
+	void *__unused_1;
+	void *freelist;		/* first free block */
+	void *__unused_2;
+	int units;
+
+#else
+#error "Unexpected slab allocator configured"
+#endif
 
-	union {
-		unsigned int active;		/* SLAB */
-		int units;			/* SLOB */
-	};
 	atomic_t __page_refcount;
 #ifdef CONFIG_MEMCG
 	unsigned long memcg_data;
@@ -48,10 +70,14 @@ struct slab {
 SLAB_MATCH(flags, __page_flags);
 SLAB_MATCH(compound_head, slab_list);	/* Ensure bit 0 is clear */
 SLAB_MATCH(slab_list, slab_list);
+#ifndef CONFIG_SLOB
 SLAB_MATCH(rcu_head, rcu_head);
 SLAB_MATCH(slab_cache, slab_cache);
+#endif
+#ifdef CONFIG_SLAB
 SLAB_MATCH(s_mem, s_mem);
 SLAB_MATCH(active, active);
+#endif
 SLAB_MATCH(_refcount, __page_refcount);
 #ifdef CONFIG_MEMCG
 SLAB_MATCH(memcg_data, memcg_data);
@@ -602,6 +628,7 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s,
 }
 #endif /* CONFIG_MEMCG_KMEM */
 
+#ifndef CONFIG_SLOB
 static inline struct kmem_cache *virt_to_cache(const void *obj)
 {
 	struct slab *slab;
@@ -648,6 +675,7 @@ static inline struct kmem_cache *cache_from_obj(struct kmem_cache *s, void *x)
 		print_tracking(cachep, x);
 	return cachep;
 }
+#endif /* CONFIG_SLOB */
 
 static inline size_t slab_ksize(const struct kmem_cache *s)
 {
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220104001046.12263-28-vbabka%40suse.cz.
