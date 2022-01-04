Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBEVBZ2HAMGQEXD7OXSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id CDBEE483964
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Jan 2022 01:10:58 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id v6-20020adfa1c6000000b001a26d0c3e32sf10844238wrv.14
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Jan 2022 16:10:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1641255058; cv=pass;
        d=google.com; s=arc-20160816;
        b=VJ+NI9CDXOm4b7z9q8+7jWK2TVzx5nc65NeVxYM0y8K9PUohRzPXzdBTCYbb3SjZro
         a/9q3khuJCA37j6Hpi8XecrVoJwtpaVxW1ZjKULXsGw/CCFJ2YJBERGsFGL8pBnRs1Et
         U631a0waiwZa5jzAyeE0H/dPt93X6U+uugVGKKUqP/Tu4eQxHjUPRc+HId7owq2MPJi5
         Tsvl5QPf5+BNysrRpE1qSYYJzFNCm2BS4vP+kvo7+JpW0fHAO5fJxDdy3zbyuokfb0RE
         y32RvN9Rn1UpfaUF8IBg3OYqfWWuappQRKVPZiUExn9tT50Xtz/PD+OvitG1IOgljq/D
         btOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Sf5wcjPWXNCzQuP6ssR0Vt43nwESxOXReqNVgPuiPJs=;
        b=r2zrZLRrBD/KQCN0hfi3qeqZt3Pu8yA7Nz/y8dG2uGhDgSzM/h8IjBxltdfwGg0Vhy
         IQSJ7JQziWLpgLmpVxk7/mHc0FcgI7Wbiy2egYN9/BGmJagns/Ket/7JwvQQIFlJ2AVL
         oL+pp/2ko1md5GcIVV0wVzJHZYUArU+BR2YNXoG4VWLOrCKhnspEVzXVJeqfLE32w3hX
         vKPLcXyAnYojAyNSsxKCl7OlmyZ76S4j3ei0FLnAGojYJFQ9anvqnNrPJ9N1YGqW6/t2
         otwVDMnuW2JcAyBrg7ho0XBrmisAzA2je79RzXpOGOHJ2anDwWt9lpnSP/ttJCnSjF/q
         c6PQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HbEdQg3m;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Sf5wcjPWXNCzQuP6ssR0Vt43nwESxOXReqNVgPuiPJs=;
        b=azIkb7pnF0dlcYdnBGqERXkqH2JsjOY9oyPrY/cVFlX0KUv6OaHLEJjZmstYjxafP+
         8F/42ZbsdkQlec9T4xT5BlzK3emxUYXsiStn3tz4KJQcnP53SD9Dcmrb+9Z+SZAmAc0X
         WHpdB04M84DQvWNfIfav7XXIvDp9Cx17msHZjf7HnWunzqx4k9XYbj54Z1mr9DEt6pRJ
         pQGgvdmO34AzVmglqX9kF0Ub6+Ktj72EbbJBj25axp81ZeAHmWay88z9JCwdk+EFvpqt
         eoZuNGsJEzb7AIpjbYlG0xf6zI1SoLbvvBtsmyh0/R9dHCyLaFb1adSlX7oHoMtLXXP5
         P6+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Sf5wcjPWXNCzQuP6ssR0Vt43nwESxOXReqNVgPuiPJs=;
        b=H3y8pq9BpmVdOU490xIlHr/itYpnWbKP92hwsV+E7e9jx61gwt0oKYmDS2Cxt306Jx
         5muAPU36p3WdcZ8CASxqDmgqDT6l+YkltjnpewBIgFe/gLaxX1e+UUU1zNEItxOLWoh7
         cmYagJglTHyWZsnma48Do8oLyI20qWLpxU4CWQfohbxdw0LfHl9BnB5Z33vTolgFh2WB
         vsbnhXFayJYU3ErsCT0qgMiOzIqh7bMITrtWeB+q2FWLnQFoEvio+k2vENQES+zD5pjr
         J8BJQDRMyc8cOdpOSWJp9719Oqwhr+K2zx1JPX0pJMF1iQYJnFIbU5Lyv+BTebfd7lJc
         6gTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530HlCGFNNdAjjhZiRYL9vg9jEOtuhFqXGBpyBtROXdUEpw9Y8RX
	W5wcfLXX2358SzXYIm/KK/o=
X-Google-Smtp-Source: ABdhPJyzsm3s/Q23SRdqT+4RIQf4eQVkti7GEg0c6MX+qXIB1SnpObflM+aILVE3OImhq89rXLrJ8g==
X-Received: by 2002:a05:600c:3d8c:: with SMTP id bi12mr40458149wmb.63.1641255058438;
        Mon, 03 Jan 2022 16:10:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:210c:: with SMTP id u12ls457899wml.2.canary-gmail;
 Mon, 03 Jan 2022 16:10:57 -0800 (PST)
X-Received: by 2002:a7b:cd19:: with SMTP id f25mr7845331wmj.105.1641255057503;
        Mon, 03 Jan 2022 16:10:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1641255057; cv=none;
        d=google.com; s=arc-20160816;
        b=p/XyYliVeJUuY48zhhRLYk/K25lo2XUEZxYPyqZNcXt2rG9SH3LtK3orDhYvcTY92g
         m4LbvU9BJFHVbwkC55nRmWhdr5iDpnXWJKnmZv2S5L95aXo5NO2Y5yYAy2c30J4IiRjP
         OzswzYW3ca0xcpK61FCueKYV3rMmEEEA7XfY1Ftu6ODarLWyvV7Sa4e+yhAQdjynbedT
         kZ3YJIP7EAi7/BLFJJDW8S8CnF/7sT3Ne3COizdWj6kcAM2Q4N7QW3HyZZntRYatE6vs
         BJkbNczJUxGoqw9oDFW26ANjv1jyohncyEPjph0mFzqT8CsF7lA8/cs33D4hvLlOoTDg
         ldSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=OO94tgerLHqSHk8p+4fCNTdH5if37Fdd6NHNZUiLFhQ=;
        b=UHGqOFEEehpReV46c/62yW9ECrLL6BuQXjuRFn6GoUtOpnQ/V2hb0kJJCukwwfPdtL
         fnnELu0xvf5dSD5BqlGbCehlhp8VHRulyGfLHuUxeDKKpUSNyc5sElXjBlAYVq6lr3av
         quaf4oBfakVPwwt1iUSn9ZGLXFF0pwlo1Rl/gGy5oKJc7XKjWL9QFngdnXls7wLkHfXh
         kCU0XatbZAIsKjjxEvUJymPlx29M6U44vjizvWzYeFd6zIQyJ0xLyWCfm/a3PbWLwdK/
         +hQqwNjBeaxUk0vUMIKHuZo3TgTAYav+Y7nLPqJ9FLnITcY1k13Y5/dQlbXMkIdbQK+m
         Y24Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HbEdQg3m;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id e9si1653482wru.1.2022.01.03.16.10.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 Jan 2022 16:10:57 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 3F86A1F397;
	Tue,  4 Jan 2022 00:10:57 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id E5F73139D1;
	Tue,  4 Jan 2022 00:10:56 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id GGKZN5CQ02FEQwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 04 Jan 2022 00:10:56 +0000
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
	Andrey Konovalov <andreyknvl@gmail.com>,
	Julia Lawall <julia.lawall@inria.fr>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Marco Elver <elver@google.com>,
	Michal Hocko <mhocko@kernel.org>,
	Vladimir Davydov <vdavydov.dev@gmail.com>,
	kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: [PATCH v4 22/32] mm: Convert struct page to struct slab in functions used by other subsystems
Date: Tue,  4 Jan 2022 01:10:36 +0100
Message-Id: <20220104001046.12263-23-vbabka@suse.cz>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220104001046.12263-1-vbabka@suse.cz>
References: <20220104001046.12263-1-vbabka@suse.cz>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=12879; h=from:subject; bh=0SOqoAvL52NDwphL7Y7hcL3a4D3hK2vQXIMf3akBzGo=; b=owEBbQGS/pANAwAIAeAhynPxiakQAcsmYgBh05B8oO13pNopOVPFK5qq/+AQMAV5vLQRmy2E6owa qQ5aKj2JATMEAAEIAB0WIQSNS5MBqTXjGL5IXszgIcpz8YmpEAUCYdOQfAAKCRDgIcpz8YmpEE3IB/ wKhLivEGWaEdsdExceq3i/OZj4VEbBiBCQrfCfV3VgmNwPUYKJKSFlBoOMttLL4ce17KYMivCIaEmh HTdJkGOF3REGdjwZ9NRrpRhl0be+xqaEQL4z70+8W30WhHPPVbhsnlal+86bZouq91XQ/WoOSIPigR JZ26d3x+D4hxD1chaAIX11n/jWY9wC0+ouHu7LL4avgBGZwRAKwe4ocW2OvlywqQFnaLMcyNLxNzz+ ZsgS0tbcsLz//G9aauEI96IbjV6AoB6PbWn9z1LpDr2YwFUhx3G8hJr4AZVI1GkPRd1ZRLjEr7rcpA zKRa27J3h83vZGFuoGOT/LOmeh9pUu
X-Developer-Key: i=vbabka@suse.cz; a=openpgp; fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=HbEdQg3m;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

KASAN, KFENCE and memcg interact with SLAB or SLUB internals through
functions nearest_obj(), obj_to_index() and objs_per_slab() that use
struct page as parameter. This patch converts it to struct slab
including all callers, through a coccinelle semantic patch.

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
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Acked-by: Johannes Weiner <hannes@cmpxchg.org>
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
index 2ed5f2a0879d..f7b789e692a0 100644
--- a/mm/memcontrol.c
+++ b/mm/memcontrol.c
@@ -2819,7 +2819,7 @@ static inline void mod_objcg_mlstate(struct obj_cgroup *objcg,
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
index 547ed068a569..c13258116791 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -1559,7 +1559,7 @@ static void check_poison_obj(struct kmem_cache *cachep, void *objp)
 		struct slab *slab = virt_to_slab(objp);
 		unsigned int objnr;
 
-		objnr = obj_to_index(cachep, slab_page(slab), objp);
+		objnr = obj_to_index(cachep, slab, objp);
 		if (objnr) {
 			objp = index_to_obj(cachep, slab, objnr - 1);
 			realobj = (char *)objp + obj_offset(cachep);
@@ -2529,7 +2529,7 @@ static void *slab_get_obj(struct kmem_cache *cachep, struct slab *slab)
 static void slab_put_obj(struct kmem_cache *cachep,
 			struct slab *slab, void *objp)
 {
-	unsigned int objnr = obj_to_index(cachep, slab_page(slab), objp);
+	unsigned int objnr = obj_to_index(cachep, slab, objp);
 #if DEBUG
 	unsigned int i;
 
@@ -2716,7 +2716,7 @@ static void *cache_free_debugcheck(struct kmem_cache *cachep, void *objp,
 	if (cachep->flags & SLAB_STORE_USER)
 		*dbg_userword(cachep, objp) = (void *)caller;
 
-	objnr = obj_to_index(cachep, slab_page(slab), objp);
+	objnr = obj_to_index(cachep, slab, objp);
 
 	BUG_ON(objnr >= cachep->num);
 	BUG_ON(objp != index_to_obj(cachep, slab, objnr));
@@ -3662,7 +3662,7 @@ void kmem_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab)
 	objp = object - obj_offset(cachep);
 	kpp->kp_data_offset = obj_offset(cachep);
 	slab = virt_to_slab(objp);
-	objnr = obj_to_index(cachep, slab_page(slab), objp);
+	objnr = obj_to_index(cachep, slab, objp);
 	objp = index_to_obj(cachep, slab, objnr);
 	kpp->kp_objp = objp;
 	if (DEBUG && cachep->flags & SLAB_STORE_USER)
@@ -4180,7 +4180,7 @@ void __check_heap_object(const void *ptr, unsigned long n,
 
 	/* Find and validate object. */
 	cachep = slab->slab_cache;
-	objnr = obj_to_index(cachep, slab_page(slab), (void *)ptr);
+	objnr = obj_to_index(cachep, slab, (void *)ptr);
 	BUG_ON(objnr >= cachep->num);
 
 	/* Find offset within object. */
diff --git a/mm/slab.h b/mm/slab.h
index 039babfde2fe..bca9181e96d7 100644
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
index cc64ba9d9963..ddf21c7a381a 100644
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
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220104001046.12263-23-vbabka%40suse.cz.
