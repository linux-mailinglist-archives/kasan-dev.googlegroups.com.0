Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBOHXT2GQMGQEZPG43ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id B14FE4654EC
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Dec 2021 19:15:20 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id j193-20020a1c23ca000000b003306ae8bfb7sf12643775wmj.7
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Dec 2021 10:15:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638382520; cv=pass;
        d=google.com; s=arc-20160816;
        b=oi5czcUVh70YYHA7+Fn2Ju/DT8yuIlYyRyIexwf02jjdBSjMW5VobVaWuLufNfXvho
         PTEeAW/uDb1/yNijEljM2DKHuVFFSlouXTpouz0CHeSsUcjN4EKh2+Ft4iu8UI51hrJJ
         t3e+Va9/t0TXKo0q6iMLZneEIIzYVyza4qJoagN5VEectOWvaVum6ix6/b6Ns9Vb4A46
         gRfaYAiAqgqrUk2/rkUER64LtfUytxeGP87oKHyKSvd14HtnkBDflpz4aCAJ5qBEsYol
         JHubyhbVnc09jxwyYJ8sjqPoHvm53zPj5bFDNFevXBB++hx2xHATmzj4thg1CcSs2oJK
         N+GA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=BWVr3gzQjJHiND4akAMJ+TKvjwpCZPnnrDKqF+6dmWU=;
        b=Jol6sUMR8cbzWrThY2cyRDigrdx5i0wXfLMDpDQ12S4AwsB3+sNYgzv2rECAvNioEb
         F62HJ1IGKdT6Z89PK2SQAiQo16m6NQmF1YtXoYtMzrckFHoAQNMRm895pLvr1r363EJX
         R/xEcPIVY6/hB567f7C/0Fvj3wGx+nZxzToAhhFSo0I6FvS2Hd9N0CrVz3bSeqYlVTWV
         0j3aSSX/PIrHpeIxxsTH+YnkijGjx4ovbjahlkYo0cDB/QtKE1vjse7iuaA3PdXGDqa8
         gCv1qk7inMIw29j240jqJ8UfneuvVq/Ng7EBpnGX7QcYFvWuxxABthuaHBcaRTd1YVgY
         7M8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=z170mukV;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BWVr3gzQjJHiND4akAMJ+TKvjwpCZPnnrDKqF+6dmWU=;
        b=hKMb3DLrnMDaKe1xVBq89n7Xh0QJTPhOgqDy0iKwxvr747b22Reph+vuls7lDdRuch
         xYjQ7EqeQ0IkcuXHYWomBcnCIixdb2Vh6zARF5kWAB+2upFIiTCe8pfaPVhrkFi9tMEg
         KpTK2m46ZqUaGwGq59SUM7OlihlhHm84Pk42ZCBZPSM+FhMcLLo6J3YUftb+x1UCw+ku
         nO7up6PBbxxYGBLtD7hhxa6c3N3QzGjWDd8f6Pragf37LFJb2Rf6duueZ6o2JCRaz3cz
         9Uhnjvv2V7/hvQRAAxDgdkB4fKhbkIfbJRvreqzqVJpvhAaMu2iqHsGklhbvzJ9q6e6s
         n+oA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BWVr3gzQjJHiND4akAMJ+TKvjwpCZPnnrDKqF+6dmWU=;
        b=CBDzs7Uc+hsq8g2GWKWjwxvYxXLbQtJnHXN5I9NCFzIrcGTy4NkxqvFDCnKKqyqdpg
         dKdPDT/z6uXgilZfIIaX9d+CNixylBRrrM4kyxEwNqvNhD286t31RkZCcF6BQ2Id95SA
         83aF7irHu4eOCKmPh/Pth4pH/48otS4jaTBARaSeLEWmvu/29BXJTDKT9p7GcaUp58Aq
         gzouGw2eewBP7QvQ9KYP+fsFOMXwhxDuDYwYpBdKvXZYnA+Tdvr7qtmicun7PpJFtJC5
         9lJtbVyV072hLvy1koSayDsKHdwHRc1BCEkWOkFFCsnn0WYJHKtHD1l/hKYfr/SmNe7S
         D5qA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530iEJsJJ6yyTr3WKWRptpUwDvjMgMS59agPPun5nm5TSBYf7Sow
	bOHNd0od1cB3QIJNxzObM9U=
X-Google-Smtp-Source: ABdhPJwWRLdBb7yLgtixolO86347HBDX7TQU/IKq+zpFASjq0Jkd3jFeVHHImCqz79v4zVnxnUn5WA==
X-Received: by 2002:adf:8091:: with SMTP id 17mr8586055wrl.457.1638382520464;
        Wed, 01 Dec 2021 10:15:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls251024wrp.1.gmail; Wed, 01 Dec
 2021 10:15:19 -0800 (PST)
X-Received: by 2002:adf:ef84:: with SMTP id d4mr8342984wro.175.1638382519519;
        Wed, 01 Dec 2021 10:15:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638382519; cv=none;
        d=google.com; s=arc-20160816;
        b=LnJAS53UHI/4AbEj24JP0d7SH5ep/zVuG8e6D73Hdw9eM0U7r+j/xolCIA/1GyFweG
         eT9rlgQlalRASyObYuq/7Zk0XJzl0r2UfFN7YQoRAogipqNDaMlvBByxfzUjZotc19cF
         oAa/Zl3av2rFfQeq4+dsMtD/b+DtroiVALRV6lODz9dYPGU6gbgshz0ufEcoOlc4FsqB
         dy1eaB2MWC0qj4hZ7dg4yNBrlm7aXuXjEnhr7rrIZ4PgqpPzoCkOE0E4tdvme1yu4gre
         sRFJ1lvFbVpadMyfHOtWa9/Id2yWUc0e06LEsMkzvvNZ76D9Zlk0uchd2Rr5rgXUU5A0
         Iu5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=0hE0fFmqoiNZ5hGJ3u4gMJGlq9TtEyRvQ+tV3jhQOoQ=;
        b=TZnKAvivAo567n5c7HBWjj0mZGlGowu1DetOrG98xOnHdsnqbK5ve7wqxw9ddobONE
         X+O7dQcy7aNhxeQwpk9X8AwENjCrJ3UsmmZdW4+3zoaQbSYv5Kohqm5MowktlSQXtmb4
         uGKvbxP9ldL2MVYubwSDKC/FViBiDmcMoktxvzMhQwX1bzLhT8OLepxGLMyflrMyRoXr
         0dKX5i36Vruv7baLS5M/0FKCZ9KEsRE2iH3mq/Rzq6PRnlUa+7eSjiRkkxDp3VD23GyF
         AL67k6vw1wmVR6YeNGfwMU1Kl3vpC9OXMp2nLPX/FWGbBo/14qt/whoJ0r8GLbtX6T5X
         ENIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=z170mukV;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id p5si26999wru.1.2021.12.01.10.15.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 01 Dec 2021 10:15:19 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 46216218D6;
	Wed,  1 Dec 2021 18:15:19 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id F344713D9D;
	Wed,  1 Dec 2021 18:15:18 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id qAKTOra7p2HPSAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 01 Dec 2021 18:15:18 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Matthew Wilcox <willy@infradead.org>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>
Cc: linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>,
	patches@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	Julia Lawall <julia.lawall@inria.fr>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Vladimir Davydov <vdavydov.dev@gmail.com>,
	kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: [PATCH v2 22/33] mm: Convert struct page to struct slab in functions used by other subsystems
Date: Wed,  1 Dec 2021 19:14:59 +0100
Message-Id: <20211201181510.18784-23-vbabka@suse.cz>
X-Mailer: git-send-email 2.33.1
In-Reply-To: <20211201181510.18784-1-vbabka@suse.cz>
References: <20211201181510.18784-1-vbabka@suse.cz>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=12792; h=from:subject; bh=4aC1m/tIrV4f6A5tkcUR9hSbFwicVFxxUNwxtFuHz/M=; b=owEBbQGS/pANAwAIAeAhynPxiakQAcsmYgBhp7uQyjTM0RJhg4ccVNFUdyJhAwEXyRJTcz2A4Bws HDG/JZ6JATMEAAEIAB0WIQSNS5MBqTXjGL5IXszgIcpz8YmpEAUCYae7kAAKCRDgIcpz8YmpEBwHCA CV52ZgS8UXOsnBBdrE53Gl6hG4swDw+A5JfmgHoqHu4rUV/Tz3WPV+nTXk71knhMXKKsCm/4i3EYKK GWVge1l2dvBcnhjpD+BbCTPOcz1o3HfQi2aIclyf14+n7WuS3sI/fxSKyZCOevsOa7FB/d5dTuSleZ XxaBG+9au8ZW0MUX8oGEtY45J1XEKbYSf/iHIsCiDR3j6oH/lon+dSvJPKRFWt2oTaovTUXfZQMnBJ yWKAjskRJMfrL4/TSqYvOAre8YMDwGzZ52KS7Pf3x+mVP8TDARN/5StCCkyamZ5SXwfpdNPzJuerUk ViQTe1/XyDC56z5cZNeqEf4FFAjMFa
X-Developer-Key: i=vbabka@suse.cz; a=openpgp; fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=z170mukV;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

KASAN, KFENCE and memcg interact with SLAB or SLUB internals through functions
nearest_obj(), obj_to_index() and objs_per_slab() that use struct page as
parameter. This patch converts it to struct slab including all callers, through
a coccinelle semantic patch.

// Options: --include-headers --no-includes --smpl-spacing include/linux/slab_def.h include/linux/slub_def.h mm/slab.h mm/kasan/*.c mm/kfence/kfence_test.c mm/memcontrol.c mm/slab.c mm/slub.c
// Note: needs coccinelle 1.1.1 to avoid breaking whitespace

@@
@@

-objs_per_slab_page(
+objs_per_slab(
 ...
 )
 { ... }

@@
@@

-objs_per_slab_page(
+objs_per_slab(
 ...
 )

@@
identifier fn =~ "obj_to_index|objs_per_slab";
@@

 fn(...,
-   const struct page *page
+   const struct slab *slab
    ,...)
 {
<...
(
- page_address(page)
+ slab_address(slab)
|
- page
+ slab
)
...>
 }

@@
identifier fn =~ "nearest_obj";
@@

 fn(...,
-   struct page *page
+   const struct slab *slab
    ,...)
 {
<...
(
- page_address(page)
+ slab_address(slab)
|
- page
+ slab
)
...>
 }

@@
identifier fn =~ "nearest_obj|obj_to_index|objs_per_slab";
expression E;
@@

 fn(...,
(
- slab_page(E)
+ E
|
- virt_to_page(E)
+ virt_to_slab(E)
|
- virt_to_head_page(E)
+ virt_to_slab(E)
|
- page
+ page_slab(page)
)
  ,...)

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
Cc: Julia Lawall <julia.lawall@inria.fr>
Cc: Luis Chamberlain <mcgrof@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Johannes Weiner <hannes@cmpxchg.org>
Cc: Michal Hocko <mhocko@kernel.org>
Cc: Vladimir Davydov <vdavydov.dev@gmail.com>
Cc: <kasan-dev@googlegroups.com>
Cc: <cgroups@vger.kernel.org>
---
 include/linux/slab_def.h | 16 ++++++++--------
 include/linux/slub_def.h | 18 +++++++++---------
 mm/kasan/common.c        |  4 ++--
 mm/kasan/generic.c       |  2 +-
 mm/kasan/report.c        |  2 +-
 mm/kasan/report_tags.c   |  2 +-
 mm/kfence/kfence_test.c  |  4 ++--
 mm/memcontrol.c          |  4 ++--
 mm/slab.c                | 10 +++++-----
 mm/slab.h                |  4 ++--
 mm/slub.c                |  2 +-
 11 files changed, 34 insertions(+), 34 deletions(-)

diff --git a/include/linux/slab_def.h b/include/linux/slab_def.h
index 3aa5e1e73ab6..e24c9aff6fed 100644
--- a/include/linux/slab_def.h
+++ b/include/linux/slab_def.h
@@ -87,11 +87,11 @@ struct kmem_cache {
 	struct kmem_cache_node *node[MAX_NUMNODES];
 };
 
-static inline void *nearest_obj(struct kmem_cache *cache, struct page *page,
+static inline void *nearest_obj(struct kmem_cache *cache, const struct slab *slab,
 				void *x)
 {
-	void *object = x - (x - page->s_mem) % cache->size;
-	void *last_object = page->s_mem + (cache->num - 1) * cache->size;
+	void *object = x - (x - slab->s_mem) % cache->size;
+	void *last_object = slab->s_mem + (cache->num - 1) * cache->size;
 
 	if (unlikely(object > last_object))
 		return last_object;
@@ -106,16 +106,16 @@ static inline void *nearest_obj(struct kmem_cache *cache, struct page *page,
  *   reciprocal_divide(offset, cache->reciprocal_buffer_size)
  */
 static inline unsigned int obj_to_index(const struct kmem_cache *cache,
-					const struct page *page, void *obj)
+					const struct slab *slab, void *obj)
 {
-	u32 offset = (obj - page->s_mem);
+	u32 offset = (obj - slab->s_mem);
 	return reciprocal_divide(offset, cache->reciprocal_buffer_size);
 }
 
-static inline int objs_per_slab_page(const struct kmem_cache *cache,
-				     const struct page *page)
+static inline int objs_per_slab(const struct kmem_cache *cache,
+				     const struct slab *slab)
 {
-	if (is_kfence_address(page_address(page)))
+	if (is_kfence_address(slab_address(slab)))
 		return 1;
 	return cache->num;
 }
diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
index 8a9c2876ca89..33c5c0e3bd8d 100644
--- a/include/linux/slub_def.h
+++ b/include/linux/slub_def.h
@@ -158,11 +158,11 @@ static inline void sysfs_slab_release(struct kmem_cache *s)
 
 void *fixup_red_left(struct kmem_cache *s, void *p);
 
-static inline void *nearest_obj(struct kmem_cache *cache, struct page *page,
+static inline void *nearest_obj(struct kmem_cache *cache, const struct slab *slab,
 				void *x) {
-	void *object = x - (x - page_address(page)) % cache->size;
-	void *last_object = page_address(page) +
-		(page->objects - 1) * cache->size;
+	void *object = x - (x - slab_address(slab)) % cache->size;
+	void *last_object = slab_address(slab) +
+		(slab->objects - 1) * cache->size;
 	void *result = (unlikely(object > last_object)) ? last_object : object;
 
 	result = fixup_red_left(cache, result);
@@ -178,16 +178,16 @@ static inline unsigned int __obj_to_index(const struct kmem_cache *cache,
 }
 
 static inline unsigned int obj_to_index(const struct kmem_cache *cache,
-					const struct page *page, void *obj)
+					const struct slab *slab, void *obj)
 {
 	if (is_kfence_address(obj))
 		return 0;
-	return __obj_to_index(cache, page_address(page), obj);
+	return __obj_to_index(cache, slab_address(slab), obj);
 }
 
-static inline int objs_per_slab_page(const struct kmem_cache *cache,
-				     const struct page *page)
+static inline int objs_per_slab(const struct kmem_cache *cache,
+				     const struct slab *slab)
 {
-	return page->objects;
+	return slab->objects;
 }
 #endif /* _LINUX_SLUB_DEF_H */
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 8428da2aaf17..6a1cd2d38bff 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -298,7 +298,7 @@ static inline u8 assign_tag(struct kmem_cache *cache,
 	/* For caches that either have a constructor or SLAB_TYPESAFE_BY_RCU: */
 #ifdef CONFIG_SLAB
 	/* For SLAB assign tags based on the object index in the freelist. */
-	return (u8)obj_to_index(cache, virt_to_head_page(object), (void *)object);
+	return (u8)obj_to_index(cache, virt_to_slab(object), (void *)object);
 #else
 	/*
 	 * For SLUB assign a random tag during slab creation, otherwise reuse
@@ -341,7 +341,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 	if (is_kfence_address(object))
 		return false;
 
-	if (unlikely(nearest_obj(cache, virt_to_head_page(object), object) !=
+	if (unlikely(nearest_obj(cache, virt_to_slab(object), object) !=
 	    object)) {
 		kasan_report_invalid_free(tagged_object, ip);
 		return true;
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 84a038b07c6f..5d0b79416c4e 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -339,7 +339,7 @@ static void __kasan_record_aux_stack(void *addr, bool can_alloc)
 		return;
 
 	cache = page->slab_cache;
-	object = nearest_obj(cache, page, addr);
+	object = nearest_obj(cache, page_slab(page), addr);
 	alloc_meta = kasan_get_alloc_meta(cache, object);
 	if (!alloc_meta)
 		return;
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 0bc10f452f7e..e00999dc6499 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -249,7 +249,7 @@ static void print_address_description(void *addr, u8 tag)
 
 	if (page && PageSlab(page)) {
 		struct kmem_cache *cache = page->slab_cache;
-		void *object = nearest_obj(cache, page,	addr);
+		void *object = nearest_obj(cache, page_slab(page),	addr);
 
 		describe_object(cache, object, addr, tag);
 	}
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 8a319fc16dab..06c21dd77493 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -23,7 +23,7 @@ const char *kasan_get_bug_type(struct kasan_access_info *info)
 	page = kasan_addr_to_page(addr);
 	if (page && PageSlab(page)) {
 		cache = page->slab_cache;
-		object = nearest_obj(cache, page, (void *)addr);
+		object = nearest_obj(cache, page_slab(page), (void *)addr);
 		alloc_meta = kasan_get_alloc_meta(cache, object);
 
 		if (alloc_meta) {
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 695030c1fff8..f7276711d7b9 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -291,8 +291,8 @@ static void *test_alloc(struct kunit *test, size_t size, gfp_t gfp, enum allocat
 			 * even for KFENCE objects; these are required so that
 			 * memcg accounting works correctly.
 			 */
-			KUNIT_EXPECT_EQ(test, obj_to_index(s, page, alloc), 0U);
-			KUNIT_EXPECT_EQ(test, objs_per_slab_page(s, page), 1);
+			KUNIT_EXPECT_EQ(test, obj_to_index(s, page_slab(page), alloc), 0U);
+			KUNIT_EXPECT_EQ(test, objs_per_slab(s, page_slab(page)), 1);
 
 			if (policy == ALLOCATE_ANY)
 				return alloc;
diff --git a/mm/memcontrol.c b/mm/memcontrol.c
index 6863a834ed42..906edbd92436 100644
--- a/mm/memcontrol.c
+++ b/mm/memcontrol.c
@@ -2819,7 +2819,7 @@ static struct mem_cgroup *get_mem_cgroup_from_objcg(struct obj_cgroup *objcg)
 int memcg_alloc_page_obj_cgroups(struct page *page, struct kmem_cache *s,
 				 gfp_t gfp, bool new_page)
 {
-	unsigned int objects = objs_per_slab_page(s, page);
+	unsigned int objects = objs_per_slab(s, page_slab(page));
 	unsigned long memcg_data;
 	void *vec;
 
@@ -2881,7 +2881,7 @@ struct mem_cgroup *mem_cgroup_from_obj(void *p)
 		struct obj_cgroup *objcg;
 		unsigned int off;
 
-		off = obj_to_index(page->slab_cache, page, p);
+		off = obj_to_index(page->slab_cache, page_slab(page), p);
 		objcg = page_objcgs(page)[off];
 		if (objcg)
 			return obj_cgroup_memcg(objcg);
diff --git a/mm/slab.c b/mm/slab.c
index f0447b087d02..785fffd527fe 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -1560,7 +1560,7 @@ static void check_poison_obj(struct kmem_cache *cachep, void *objp)
 		struct slab *slab = virt_to_slab(objp);
 		unsigned int objnr;
 
-		objnr = obj_to_index(cachep, slab_page(slab), objp);
+		objnr = obj_to_index(cachep, slab, objp);
 		if (objnr) {
 			objp = index_to_obj(cachep, slab, objnr - 1);
 			realobj = (char *)objp + obj_offset(cachep);
@@ -2530,7 +2530,7 @@ static void *slab_get_obj(struct kmem_cache *cachep, struct slab *slab)
 static void slab_put_obj(struct kmem_cache *cachep,
 			struct slab *slab, void *objp)
 {
-	unsigned int objnr = obj_to_index(cachep, slab_page(slab), objp);
+	unsigned int objnr = obj_to_index(cachep, slab, objp);
 #if DEBUG
 	unsigned int i;
 
@@ -2717,7 +2717,7 @@ static void *cache_free_debugcheck(struct kmem_cache *cachep, void *objp,
 	if (cachep->flags & SLAB_STORE_USER)
 		*dbg_userword(cachep, objp) = (void *)caller;
 
-	objnr = obj_to_index(cachep, slab_page(slab), objp);
+	objnr = obj_to_index(cachep, slab, objp);
 
 	BUG_ON(objnr >= cachep->num);
 	BUG_ON(objp != index_to_obj(cachep, slab, objnr));
@@ -3663,7 +3663,7 @@ void kmem_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab)
 	objp = object - obj_offset(cachep);
 	kpp->kp_data_offset = obj_offset(cachep);
 	slab = virt_to_slab(objp);
-	objnr = obj_to_index(cachep, slab_page(slab), objp);
+	objnr = obj_to_index(cachep, slab, objp);
 	objp = index_to_obj(cachep, slab, objnr);
 	kpp->kp_objp = objp;
 	if (DEBUG && cachep->flags & SLAB_STORE_USER)
@@ -4181,7 +4181,7 @@ void __check_heap_object(const void *ptr, unsigned long n,
 
 	/* Find and validate object. */
 	cachep = slab->slab_cache;
-	objnr = obj_to_index(cachep, slab_page(slab), (void *)ptr);
+	objnr = obj_to_index(cachep, slab, (void *)ptr);
 	BUG_ON(objnr >= cachep->num);
 
 	/* Find offset within object. */
diff --git a/mm/slab.h b/mm/slab.h
index 7376c9d8aa2b..15d109d8ec89 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -483,7 +483,7 @@ static inline void memcg_slab_post_alloc_hook(struct kmem_cache *s,
 				continue;
 			}
 
-			off = obj_to_index(s, page, p[i]);
+			off = obj_to_index(s, page_slab(page), p[i]);
 			obj_cgroup_get(objcg);
 			page_objcgs(page)[off] = objcg;
 			mod_objcg_state(objcg, page_pgdat(page),
@@ -522,7 +522,7 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s_orig,
 		else
 			s = s_orig;
 
-		off = obj_to_index(s, page, p[i]);
+		off = obj_to_index(s, page_slab(page), p[i]);
 		objcg = objcgs[off];
 		if (!objcg)
 			continue;
diff --git a/mm/slub.c b/mm/slub.c
index f5344211d8cc..61aaaa662c5e 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -4342,7 +4342,7 @@ void kmem_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab)
 #else
 	objp = objp0;
 #endif
-	objnr = obj_to_index(s, slab_page(slab), objp);
+	objnr = obj_to_index(s, slab, objp);
 	kpp->kp_data_offset = (unsigned long)((char *)objp0 - (char *)objp);
 	objp = base + s->size * objnr;
 	kpp->kp_objp = objp;
-- 
2.33.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211201181510.18784-23-vbabka%40suse.cz.
