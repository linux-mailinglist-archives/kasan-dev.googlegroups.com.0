Return-Path: <kasan-dev+bncBDTMJ55N44FBBSNQ3GPQMGQE527QFKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id AAB7A69FAA3
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Feb 2023 19:00:42 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id a9-20020a05651c210900b0028b97d2c493sf2418966ljq.2
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Feb 2023 10:00:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677088842; cv=pass;
        d=google.com; s=arc-20160816;
        b=C7JU977YNCSkReo1Od3kzLigYj1y+mkC48kq4dvC41HRfdEPaMpxFoxxX33z51BrhZ
         BJ2u7rtKw1PGbW5J882DpwyTlcXIyAjjUKEnbHga/ZdGBVVSZonKJOacJtrJoQKLIJJI
         eIx1m6/qN5qOZ7dqiDV2MEEZcKHyLYN7yJ+OsiRi4KlLgewy0VDmO9m4JISKKTT2deRr
         bbGKSpYOlGkmJUbp6+VSBk1rcULoa0RGBNFDSbkbT0YHbIUnPJ3eWR62j7cMZB/g+pm0
         XBFZnmOefCqhs6Jzi06CsnmH3HCShSoZh1UNgC0uYEOAsvQaGnHqqHukjjfXR11XCj6i
         74BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=aI6fKOhvAOJOlFbJBv5qCPqYx2TDfryFtTjDpGjCsZ4=;
        b=cZ8ZzOf/iFj5Ye26OuxP1QoRjwoYTlKsYrw34L0Xcunkx2ORisvoaZsQKqGF/hx9iq
         CNNOT7+R8bImNsXSlMcKjUVNFR44lydq4A0tlyykS2kmacrmozVHfuSEZVJURnvD4dVG
         hACHoPMENRu6XilfAVkHmOW5o9Je34QsHeYqFkCVQk++faRc4Vx2w/QQheuI2pPm0awV
         ga8o+KRUys6qLEZFL2t3G9Sbldnwcn+JyAZvMAfSm5RyGT7O/RSslc1mrh5Q6Wcv0hEA
         FFbi6ic3qARGVCq7Zu+83XO2HRb8SuPEFIxsQiqQ0CwS/dkG8hehG3zRNpB+rG4DiAvC
         YIvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.128.46 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aI6fKOhvAOJOlFbJBv5qCPqYx2TDfryFtTjDpGjCsZ4=;
        b=NMzJfYiuyKovo6lFLhx6hz91/1w9U/waJ6CIHz7X/IkMRwY0XP1llCJ5jWWt3JUrMP
         +AtO+P78lu9uN3frHbIDeNFSdfeQKAsNVWl5Elj0+toQj4+0OGmy6rPkI/2FeOLgWjub
         AHVO5WNjtqBJkLG62qaC2YT+C0LUkYWuGREYGeJ/NXPS75iPjOAqwpxCGdS9zJzE9iDl
         6ua346rBTvKyxeQDSvV7XkaRNKp+MP2LlfKt43EcOQZw9qdVLbjKZZCqQuRBOZDFGfxk
         VWs4+N6SRjRjFuXf5nZsAxFPcM7UF9WjwjmjkSFV+YYcEnXROLQFUJFYWdDexDHt1qc4
         4D8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aI6fKOhvAOJOlFbJBv5qCPqYx2TDfryFtTjDpGjCsZ4=;
        b=yEhaYd4Zu9vde1lRL8YmtzXSr66GGc9MtRiUuYoVkEkCpOmpD68qWbQQBBL/ds79VY
         erV5TYGnMFym/kXplDToOyLkjorVWX+9QHOASQnyks6ivfhlD4Ssh+cGy1QxVlD4l3bT
         XrTjSYJCu9zunjip9+EwutChPhnByXLhTjvYDGDkceZKT5IuVp4PExMnykldA9haY34p
         90yI018hOOMBHXQoeL2JuzqCkl7njEgZR6+8mb0nxHYXiwEPwh+hU8nuv16CBGe42j0N
         IScj5uyDxg8u0aUqgz7Dm6lEKn/PL7RyxBRCBbVq4f5LzIFAC8vZD2u5s0XINTfvWLc1
         16Mw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXr3Sgc6DvMF8rit9ExdvSCJl850oEGyQjw073JG278sJF1IVHE
	OT/UDyOBiXgfSIZG3MoSrQs=
X-Google-Smtp-Source: AK7set9lr2p6kSVGG9bISUHYcSqvq8Cp17QXHSk10XcC4biIS2D02JvFYd/A9qbijjFEsOGIg7x3GA==
X-Received: by 2002:ac2:5462:0:b0:4db:f0a:d574 with SMTP id e2-20020ac25462000000b004db0f0ad574mr3002916lfn.7.1677088841762;
        Wed, 22 Feb 2023 10:00:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:904:b0:294:5f5a:a482 with SMTP id
 e4-20020a05651c090400b002945f5aa482ls1505658ljq.4.-pod-prod-gmail; Wed, 22
 Feb 2023 10:00:40 -0800 (PST)
X-Received: by 2002:a2e:be14:0:b0:295:965e:8506 with SMTP id z20-20020a2ebe14000000b00295965e8506mr1775462ljq.41.1677088840002;
        Wed, 22 Feb 2023 10:00:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677088839; cv=none;
        d=google.com; s=arc-20160816;
        b=wwci2sDXF3ndrTKbkjm4igBzCkcK9zYVqPOWu1TmHqSGgMdSpaH7pxmBDdrTwaDvql
         N3q7ZC2yNH28bg+SnZh9AbqFYm1MT/6omM0hHd+dlKQCXKBSwFkpfZIgZwe5+yfjbtKg
         P3UgfRIwHzKKWzJIwZlWO4c31SXc7Y/9b77pxVBZdT/icwEMj/WdtBiL97k90HseT4ME
         1pMNQGwwz0cInoJhxj6LusYCz2mt8MY7AnktmJ/b5a6ylYPdzBD/FmICTrgCGhazZBA5
         rO2R6JQms4i4XQxeMG3KzGfbI6Y6/TfCHs95EHcxZ9oz5OK7yZkJ9HYQ/gfaOmw0V16H
         D5dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=3tEj3MEVlOpJ71FbGuEdO9VoX/sQZcmpHXDBJnglnR8=;
        b=oHcCVh5uV6ZXYCCYBEOi78RI6H/SmfyJZfIzCWcovbCB3SzOf35v2M8v7lXLVr/QLK
         wGAvqb+BIB2pC8FZAQV0j7kJdYIwVh+o290oChuZcsU5iiVnAV977ulFrZ9nQULrGA63
         DY3zU4p/En0m5G6zrf9eDqJi4shlieN9L39EtqxyakllqdIH+WUP4jB9ItppYH2xM93R
         +rsBIECk7MIDCXP/LrP5pGd+fkBY/PmmPcsuYAoaxzrCVwLNHvWDBV1UTwTrRli65oku
         eQbfeR4+XA1A9KdJYupNTydpb2Sc1/qK2txv59Kt5s+H/DA6wWAOhXwgN3qzr4FHbPrx
         aZVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.128.46 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-wm1-f46.google.com (mail-wm1-f46.google.com. [209.85.128.46])
        by gmr-mx.google.com with ESMTPS id b26-20020a2ebc1a000000b002905672e241si322229ljf.5.2023.02.22.10.00.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Feb 2023 10:00:39 -0800 (PST)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.128.46 as permitted sender) client-ip=209.85.128.46;
Received: by mail-wm1-f46.google.com with SMTP id j19-20020a05600c1c1300b003e9b564fae9so1292114wms.2
        for <kasan-dev@googlegroups.com>; Wed, 22 Feb 2023 10:00:39 -0800 (PST)
X-Received: by 2002:a05:600c:16c5:b0:3dc:37d0:e9df with SMTP id l5-20020a05600c16c500b003dc37d0e9dfmr1606404wmn.14.1677088839316;
        Wed, 22 Feb 2023 10:00:39 -0800 (PST)
Received: from localhost (fwdproxy-cln-002.fbsv.net. [2a03:2880:31ff:2::face:b00c])
        by smtp.gmail.com with ESMTPSA id r1-20020adfdc81000000b002c5503a8d21sm5901528wrj.70.2023.02.22.10.00.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 22 Feb 2023 10:00:38 -0800 (PST)
From: Breno Leitao <leitao@debian.org>
To: axboe@kernel.dk,
	asml.silence@gmail.com,
	io-uring@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	gustavold@meta.com,
	leit@meta.com,
	kasan-dev@googlegroups.com,
	Breno Leitao <leit@fb.com>
Subject: [PATCH v2 1/2] io_uring: Move from hlist to io_wq_work_node
Date: Wed, 22 Feb 2023 10:00:34 -0800
Message-Id: <20230222180035.3226075-2-leitao@debian.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20230222180035.3226075-1-leitao@debian.org>
References: <20230222180035.3226075-1-leitao@debian.org>
MIME-Version: 1.0
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.128.46 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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

From: Breno Leitao <leit@fb.com>

Having cache entries linked using the hlist format brings no benefit, and
also requires an unnecessary extra pointer address per cache entry.

Use the internal io_wq_work_node single-linked list for the internal
alloc caches (async_msghdr and async_poll)

This is required to be able to use KASAN on cache entries, since we do
not need to touch unused (and poisoned) cache entries when adding more
entries to the list.

Suggested-by: Pavel Begunkov <asml.silence@gmail.com>
Signed-off-by: Breno Leitao <leitao@debian.org>
---
 include/linux/io_uring_types.h |  2 +-
 io_uring/alloc_cache.h         | 26 +++++++++++++-------------
 2 files changed, 14 insertions(+), 14 deletions(-)

diff --git a/include/linux/io_uring_types.h b/include/linux/io_uring_types.h
index 0efe4d784358..efa66b6c32c9 100644
--- a/include/linux/io_uring_types.h
+++ b/include/linux/io_uring_types.h
@@ -188,7 +188,7 @@ struct io_ev_fd {
 };
 
 struct io_alloc_cache {
-	struct hlist_head	list;
+	struct io_wq_work_node	list;
 	unsigned int		nr_cached;
 };
 
diff --git a/io_uring/alloc_cache.h b/io_uring/alloc_cache.h
index 729793ae9712..ae61eb383cae 100644
--- a/io_uring/alloc_cache.h
+++ b/io_uring/alloc_cache.h
@@ -7,7 +7,7 @@
 #define IO_ALLOC_CACHE_MAX	512
 
 struct io_cache_entry {
-	struct hlist_node	node;
+	struct io_wq_work_node node;
 };
 
 static inline bool io_alloc_cache_put(struct io_alloc_cache *cache,
@@ -15,7 +15,7 @@ static inline bool io_alloc_cache_put(struct io_alloc_cache *cache,
 {
 	if (cache->nr_cached < IO_ALLOC_CACHE_MAX) {
 		cache->nr_cached++;
-		hlist_add_head(&entry->node, &cache->list);
+		wq_stack_add_head(&entry->node, &cache->list);
 		return true;
 	}
 	return false;
@@ -23,11 +23,11 @@ static inline bool io_alloc_cache_put(struct io_alloc_cache *cache,
 
 static inline struct io_cache_entry *io_alloc_cache_get(struct io_alloc_cache *cache)
 {
-	if (!hlist_empty(&cache->list)) {
-		struct hlist_node *node = cache->list.first;
-
-		hlist_del(node);
-		return container_of(node, struct io_cache_entry, node);
+	if (cache->list.next) {
+		struct io_cache_entry *entry;
+		entry = container_of(cache->list.next, struct io_cache_entry, node);
+		cache->list.next = cache->list.next->next;
+		return entry;
 	}
 
 	return NULL;
@@ -35,18 +35,18 @@ static inline struct io_cache_entry *io_alloc_cache_get(struct io_alloc_cache *c
 
 static inline void io_alloc_cache_init(struct io_alloc_cache *cache)
 {
-	INIT_HLIST_HEAD(&cache->list);
+	cache->list.next = NULL;
 	cache->nr_cached = 0;
 }
 
 static inline void io_alloc_cache_free(struct io_alloc_cache *cache,
 					void (*free)(struct io_cache_entry *))
 {
-	while (!hlist_empty(&cache->list)) {
-		struct hlist_node *node = cache->list.first;
-
-		hlist_del(node);
-		free(container_of(node, struct io_cache_entry, node));
+	while (1) {
+		struct io_cache_entry *entry = io_alloc_cache_get(cache);
+		if (!entry)
+			break;
+		free(entry);
 	}
 	cache->nr_cached = 0;
 }
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230222180035.3226075-2-leitao%40debian.org.
