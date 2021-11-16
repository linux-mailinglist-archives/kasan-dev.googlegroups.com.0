Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB2XQZOGAMGQESHKUKWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id B1FCA451C89
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 01:16:42 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id x17-20020a0565123f9100b003ff593b7c65sf7511210lfa.12
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 16:16:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637021802; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q770C4grFABmqV2Aoa/2u+KKWbvnITZ0joI1eAiGbXqtMPQqfiIeGlQErN5xeSrnxY
         qIeXnFnIkbp0qDeeRqPKjh1VNeUOVixGj4BpIDA6uWa55+CaPu2jYK+PHCjFBLZNrT7y
         2ZCLaUNPxweU6ZGMnUJOcYx7A37TPxf9AyuM3pSbFcabWEHH3mhVmEtYY3YHlzI07lqs
         ub2bDnTS1XJnIlKXzr2HJB/lMY+btYYS1CTGhD8GOKgD66jXC+1OBybMbRo+Jb9h2M8h
         bkCOYluFnZtLoTE5S1twJus6DSAcJIaLbbQqCaf3wz42+pOZPlhXFMpsIUP9p09Cxl04
         3Xyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IBKpNIfdg1/aOdF9whY9jjUd/ZVVbCJwxPQH/ynAUAA=;
        b=q0wUvnEzkPtoc7DM5mLw6jJtmlQMrxGJ1r9p1L9g7Jcl735aUNKIZlvC9h/1rcEo2E
         LRi86UXSjXbemZo3XZPTaqs3dKD1DMSAkUC51PyTjtuaIW1z9nnuxr+Q5ycDGmtaqsui
         OL/CR1xDqxLIvCT+1tBaDHiNcWF+EHCKSd90bgqIk0xipDCKKXcM7wbBJTRR8XbI+eAm
         rdxD0WqXC1Jw0ZnEfILYlTjptyVAiR18kw1FzQfJ957aYLgJ6mRfSOSGXz2dZRm7L/h1
         jvIj9RTi+oxEXgeKfdjFbZoqulCR5CYL8ldtcPew8VgbxGNcQcWTYABJ/BAU1W1ows20
         utNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=bdN7BbC7;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=YxbvWrpU;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IBKpNIfdg1/aOdF9whY9jjUd/ZVVbCJwxPQH/ynAUAA=;
        b=QQOXt8RvuBWju6ypEeKbTuIkm3YBlsR8Imlp+qLSxZQ6cXDLNbOeRR+1yknZGc401v
         KhLs6XWttO/e5YrUgs/UxUa04gFZPqswpK8xLpZ8fktBlCPND8kh/InzwCr2/UvgbvRq
         CL8RE6hSNVhLhx5LGWRD8S/XLG9Q33P9s+EU99oWLPuSpDVZJJig7AW9+9JQzSk98gj5
         zud7cExAQ1GCSvvZiPcR74JN5qQL0STLApc/gTkYXEIuIYvF60QAed0AyM1KEF6gnoR9
         BkVJTk1nTie6EPIuhkzH3TON/qEjjixBTY8hBxPx+NlQ8MpefmExrY8QXxqWIeM5eYV0
         DOpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IBKpNIfdg1/aOdF9whY9jjUd/ZVVbCJwxPQH/ynAUAA=;
        b=Wxo5Exk4aa3F6HN53xQUSU0G1F84Q1Aa9Gbm6vvXllntTGSdBgoImBdmUiMQ1vF3dn
         +Wtol6rpXIK94zNe0XJSYelar/JCkDIaOqlrsoplsqa4FbGzx4vPAoifdrOFminzdpjy
         canW9wSEp///2gJCzsBMYvFVPqsZ9tnGgJM9fQUtefJnbMzozRnnftLjry6FqWJFnQia
         6Eh1m3XWt7ocSOxubFxtRItqvTL6WEnIgjmZAI8OQpuTSQwY979mT/1AT/f+SYPY2eX7
         bMxRH/z+X46vI2aUSgq9t2hla7H7fOsXkbtly9OwrPUpTtVMP15CEFiyfDamUUGyMTYk
         mBHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531qP8+pHK9Mq/JQen86yF775EfcPfIWg3NFMPm/4ihsmBWgmsdh
	pUfSIrxcoob960soJHTE0pM=
X-Google-Smtp-Source: ABdhPJyIMHD/UJpsWaLYq9R8QWi0TxpLLmbFFLsKKOhUknrN/Sr9Vphg2ssfOquDvIo0xeZgtQQdZA==
X-Received: by 2002:a2e:9c91:: with SMTP id x17mr2629751lji.330.1637021802192;
        Mon, 15 Nov 2021 16:16:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2610:: with SMTP id bt16ls777362lfb.2.gmail; Mon,
 15 Nov 2021 16:16:41 -0800 (PST)
X-Received: by 2002:a19:e00b:: with SMTP id x11mr2554943lfg.217.1637021801086;
        Mon, 15 Nov 2021 16:16:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637021801; cv=none;
        d=google.com; s=arc-20160816;
        b=Gid/Q5b/QiwT8RZPzx9wB1rBunYoI5VYE9sL6kAGfGjWUh31ilPjthjZxnB4L4omuq
         SucKIBpPSSWIomLxxDxxry4iJLuIeS1NlqkWVCKJ3SBuOL46l6q5Iw+1IGLAV+cWPepu
         DFiqVw8A3wXsSYgXI3kaVDns+k98NiP84MlU91adQfd6qls4RgZxcMZ5Kv52TXv2DMI/
         BxHiSrKl5XMgmjyDt6bu2qKvEC1VIoHY0BqFj8cqn4Ls0+ZCGAAQnElGnyRMOEaCNlmB
         hUGqQUDAm1HyELd9awtXmkmUqPL3RyW7TsK1pFfZI/vqmBOWxB1flSdF1pc9IJovI1Kn
         IWVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=Q2s2rRolTi/tozAyHKufO2rJcy/F+r5lJEP1a0gCagE=;
        b=FAFUCDUzkW8j3b23Z7qQHswuY/u5XebfUOQGP3fChuWbYJSSuvQ4YrlOe0/dPOglQ/
         KzkXcJy171qsXqALSi47KQcev63zbP/Q/yi1790DFha0iS1SeCeX1peKcfjWtWguM+l8
         HBt/rfv1UHBMlawB9H8wksU23N7TrvNPNvhDzt/esvJzXt6el2jMb3U1nQYzb31J1yDj
         vSRQAD8Drdwyfx0G3O+QH14pxzdx9R8S6BU32Bju1RgmlmrGQeq0JmWhb9UFDCPJgpRa
         N+1H6KnkEoNgtlCnuk+JKgp5TcgT3U7rRTHEt0HJ51TXzeHymx8kyciVG4xeBh3cHaSv
         3uFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=bdN7BbC7;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=YxbvWrpU;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id t71si953615lff.6.2021.11.15.16.16.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Nov 2021 16:16:41 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 6C88721977;
	Tue, 16 Nov 2021 00:16:40 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 2C290139DB;
	Tue, 16 Nov 2021 00:16:40 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 0K46Cmj4kmFjXAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 16 Nov 2021 00:16:40 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Matthew Wilcox <willy@infradead.org>,
	linux-mm@kvack.org,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>
Cc: Vlastimil Babka <vbabka@suse.cz>,
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
Subject: [RFC PATCH 21/32] mm: Convert struct page to struct slab in functions used by other subsystems
Date: Tue, 16 Nov 2021 01:16:17 +0100
Message-Id: <20211116001628.24216-22-vbabka@suse.cz>
X-Mailer: git-send-email 2.33.1
In-Reply-To: <20211116001628.24216-1-vbabka@suse.cz>
References: <20211116001628.24216-1-vbabka@suse.cz>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=12792; h=from:subject; bh=IgVl3ZRPt4OrPRzJceHKtR5LaZyvmIn43n2yD1brefw=; b=owEBbQGS/pANAwAIAeAhynPxiakQAcsmYgBhkvhHhJKjpglH0ojEgRxJJDx/KZJk3rlhaI0b5mIL ALr4j4yJATMEAAEIAB0WIQSNS5MBqTXjGL5IXszgIcpz8YmpEAUCYZL4RwAKCRDgIcpz8YmpEP6sB/ oCbzd1mr3I+H1daz/zmxBLv3GvS9Ev24Mc5t2tuNU5BUeOVnT3lbzMl5l/mnKzuRX+uO+ocdTwpr2o V2qdhp5F8e3DRzKeYWSErLSGrcUA4CsaEFK36qE3A1hR5FT1j94SE0GWmwB3Blwt+pOH2qoCRcdftJ l1qAbxaUntM81yQkwmpNMYMFv/uoML3krqGB8TUkjlmQfhQZypgImrnVkVCifMV7v4rwCY/JVRVYYW d1cyv/xt95ILtpXD3b2uP3PXTc1NkTdX4o8zQZAxXFyzThAnLSVmuUykJlLj8CbI9ojT9G1U9YLP8m EJafmg+tn8BU5T3uuWqLUxxRLYBnex
X-Developer-Key: i=vbabka@suse.cz; a=openpgp; fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=bdN7BbC7;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=YxbvWrpU;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
index 781605e92015..c8b53ec074b4 100644
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
index 78ef4d94e3de..adf688d2da64 100644
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
@@ -4182,7 +4182,7 @@ void __check_heap_object(const void *ptr, unsigned long n,
 
 	/* Find and validate object. */
 	cachep = slab->slab_cache;
-	objnr = obj_to_index(cachep, slab_page(slab), (void *)ptr);
+	objnr = obj_to_index(cachep, slab, (void *)ptr);
 	BUG_ON(objnr >= cachep->num);
 
 	/* Find offset within object. */
diff --git a/mm/slab.h b/mm/slab.h
index d6c993894c02..b07e842b5cfc 100644
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
index 7759f3dde64b..981e40a88bab 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211116001628.24216-22-vbabka%40suse.cz.
