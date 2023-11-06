Return-Path: <kasan-dev+bncBAABBAESUWVAMGQEYFKL7IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 893A37E2DFB
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:13:53 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-35768ae7ed0sf46483435ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:13:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301632; cv=pass;
        d=google.com; s=arc-20160816;
        b=J278yBvf+c4AWia5FQQyae+8LfnKHfsow/6nsQDa/MoJRKi1iDbdCJADwXxEglhR/8
         sJEA4LOq3bpJ0wngNUHHo7m/f6u6NfnxwkAcdFQh8Aho0d8iDoaC3bC/Oixbw1FBEtvd
         xqhP4VJLaQkHLaR4WzT6zeeDshDXx4ahevo2SOo13PK0GQT5EwNC1WfIpJcRI1UIXKFU
         h6qvOyXDpJGeg232Msa+YnKbKEIfya3Fted1q3R4lRuMXWYU+PAbSUfe9Z4xITGaama7
         9ugJMIw4Ims24NUAWbHEufCReHQwYXMukeRte0QszqqZKa0SgHbwh/8oawH6eBuvTvad
         GwBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PZaZOKXwrZzNXKpIExMyba1yOaU7SbMXKGK703wlOF4=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=ITHAZXb587iKZ1LxzpX0UtuPvOiaQvHNNpX8L0k7fTjmDCPBWGkTWTeoJT2x75l0Sx
         Zd3GfQuoRI8cGXDOa8CKQyfu/cy0a1ngms0F5Y3IPKf+4zkRbwnxOMivcp9lkF32kHSe
         xB+syTsl4hYkqmWhH9xJcx5XaYc3nrevDZpWh6mLfb7jSEUjbu20B/txdQh+tiHpWmqV
         cTbmRZKqTe3YJXovCOmPKb1HC7m4BRDD/rrAjNcTgOgGc6AFuLL+bxORbGrT6ThrECI9
         t0va+mVQTIXo/42dDHThRmOsp3Bfl+WlwjYUsNmDCt+SEqPX1Ziqa/PF/IFZo/VnAYL0
         nYJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="gW/TzhDf";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301632; x=1699906432; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PZaZOKXwrZzNXKpIExMyba1yOaU7SbMXKGK703wlOF4=;
        b=P0LbIGEHOVA1kTOMQQ1z06Kpz5ftAVRzAV9WyhW4x1JS0pGHuiW3L4gZSDrf59YZ9Y
         r/3ohCwgWO0YFD022FnLV7Cv8ECYr9pr5cjT9RmODlJinvU7OYcn3TECfGXf2SJDgvNW
         enog7+NAxEa3bXSPunQjMpwbbGBvIiVT5fYtqhcBBDccoZUYMnz/wdEWd1P8f79ObYuB
         BQFoAi5+OUluFE4pXxQ3Q43JJ6yrYPKUGe/XIh5SXN3pt1AzY32koWGwGntXPMUeHVue
         uMotFNBimTEnIX4rvPZt6spPyK/TXFH/t9wnjeg/TjKhi4GplSZHG+dDU6mOLAEkj621
         i1hQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301632; x=1699906432;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PZaZOKXwrZzNXKpIExMyba1yOaU7SbMXKGK703wlOF4=;
        b=Ard7GBH8kMYGSO8oh/iBvxCWfRh0IaS15piEWIYzErilzLID0YXnBnc/NZ94Cp29fc
         ZoBxnjM5OjEST6htDWhKWd4xzy3Zzc3Z9cjLtlqJMX2/b8adesFbJyj1ZmM+UkxQ+eVd
         Jw6Zhh/V2wt49mwAlM6/Zdt4N59rlSy6Wq8NMNGCXXW+W0xc378uqIiGruXVj3LHhk9o
         M66L38BNV45g56nAZupKF01IFykcOK8TSzlBRLFUAoBCsLlDRdWcJ5Hzp6Nehcw6vl1J
         xCgqLX7AICGA08KFPme9sElmi5+WbXS7P2gQtMiuCegMr6z0n25bywhJ7C2tU8ISPGlE
         SXsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzTATAetpmq92/+8tTpz/cbg6PDF3jmd6R98QYPmoF4tY6rF1ay
	2cl5srXLmTGwG/ohjf71Z74=
X-Google-Smtp-Source: AGHT+IG+UzAxf2ewqxzYaWgOoBCIsjrJ0fQkurc+Z+pO59Y/YpuC67xlKRjjq4peyUSo8mpLgclcDg==
X-Received: by 2002:a05:6e02:178c:b0:34f:7e1b:a7a2 with SMTP id y12-20020a056e02178c00b0034f7e1ba7a2mr1122136ilu.13.1699301632222;
        Mon, 06 Nov 2023 12:13:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ca05:0:b0:349:b8b:c2c6 with SMTP id j5-20020a92ca05000000b003490b8bc2c6ls2394362ils.2.-pod-prod-04-us;
 Mon, 06 Nov 2023 12:13:51 -0800 (PST)
X-Received: by 2002:a05:6e02:188f:b0:359:4726:9007 with SMTP id o15-20020a056e02188f00b0035947269007mr1054630ilu.26.1699301631240;
        Mon, 06 Nov 2023 12:13:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301631; cv=none;
        d=google.com; s=arc-20160816;
        b=p3IaX6QdC4OGPJWFV48UPIKsTHB4zHs0HcfGWPNJNb9pwgnnKbYZQxT3uv1CVmL90T
         Ok54Af2m2EIaGqtF648Y8eAXjyEYjH883xanntOfkOd8t1YSMyD38eETTqvykWGyoDAA
         DxKOI30ie7A9hgQO/+HrAERcuW56944QBLsA0mtmNqxHZLK3B2Hm+kX9AtTo+T9XTs6T
         mVhaYGcHmTK5k99enLluekzCgH2qXhBXipGfDzbQjflQNr2QssSEe0agasoK5EO2Gbh/
         81mgE+nqay8djVMA2BgzK34+tiZbO3Ow0X95WTqmwxw5SPjmnoPrPoVzcpyILqsmqsI7
         sb0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FAC2S7cvKWC0F44BA8JFK/nUEMkMZjl2M4MUzuWuDcc=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=IXmjDGzqdC6XWeCfq+LqRxvTiM75OvgVAz86fIcqxqN7NU0Xulx9a3xa8ooeLhE7Ys
         Xo2MrjZcRZgPHOGimKcOMZ/OI57T+6HdGCf7+FlCQYGIpKYS6QiRuVmiwO1xjc2ouY3s
         LqX1Sk5j4JtrbRIi6geQR4kXg01W9E9/qtfa8FvtFS9GD+iuiB8oL8G697bE9Sy3MEB5
         2sUUiQGb4uG4sflcTcr+H/fcowpi/JN17SFjX9OQ87Do+Ikph7XxSlTrZ0tGPWfS8zL5
         U8ud1A+sG7oagUnQQbiBiqInjqJv3hQ2WINuCveelZEnrW5fE/GOKXjG13OwJ43gc7gM
         KPvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="gW/TzhDf";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-179.mta0.migadu.com (out-179.mta0.migadu.com. [2001:41d0:1004:224b::b3])
        by gmr-mx.google.com with ESMTPS id z2-20020a056a001d8200b00690fb1968c4si477508pfw.2.2023.11.06.12.13.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:13:51 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) client-ip=2001:41d0:1004:224b::b3;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH RFC 18/20] kasan: rename and document kasan_(un)poison_object_data
Date: Mon,  6 Nov 2023 21:10:27 +0100
Message-Id: <1128fd5cf1051270bc7e5978479a983a918626f5.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="gW/TzhDf";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Rename kasan_unpoison_object_data to kasan_unpoison_new_object and add
a documentation comment. Do the same for kasan_poison_object_data.

The new names and the comments should suggest the users that these hooks
are intended for internal use by the slab allocator.

The following patch will remove non-slab-internal uses of these hooks.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 35 +++++++++++++++++++++++++++--------
 mm/kasan/common.c     |  4 ++--
 mm/slab.c             | 10 ++++------
 mm/slub.c             |  4 ++--
 net/core/skbuff.c     |  8 ++++----
 5 files changed, 39 insertions(+), 22 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 7392c5d89b92..d49e3d4c099e 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -129,20 +129,39 @@ static __always_inline void kasan_poison_slab(struct slab *slab)
 		__kasan_poison_slab(slab);
 }
 
-void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
-static __always_inline void kasan_unpoison_object_data(struct kmem_cache *cache,
+void __kasan_unpoison_new_object(struct kmem_cache *cache, void *object);
+/**
+ * kasan_unpoison_new_object - Temporarily unpoison a new slab object.
+ * @cache: Cache the object belong to.
+ * @object: Pointer to the object.
+ *
+ * This function is intended for the slab allocator's internal use. It
+ * temporarily unpoisons an object from a newly allocated slab without doing
+ * anything else. The object must later be repoisoned by
+ * kasan_poison_new_object().
+ */
+static __always_inline void kasan_unpoison_new_object(struct kmem_cache *cache,
 							void *object)
 {
 	if (kasan_enabled())
-		__kasan_unpoison_object_data(cache, object);
+		__kasan_unpoison_new_object(cache, object);
 }
 
-void __kasan_poison_object_data(struct kmem_cache *cache, void *object);
-static __always_inline void kasan_poison_object_data(struct kmem_cache *cache,
+void __kasan_poison_new_object(struct kmem_cache *cache, void *object);
+/**
+ * kasan_unpoison_new_object - Repoison a new slab object.
+ * @cache: Cache the object belong to.
+ * @object: Pointer to the object.
+ *
+ * This function is intended for the slab allocator's internal use. It
+ * repoisons an object that was previously unpoisoned by
+ * kasan_unpoison_new_object() without doing anything else.
+ */
+static __always_inline void kasan_poison_new_object(struct kmem_cache *cache,
 							void *object)
 {
 	if (kasan_enabled())
-		__kasan_poison_object_data(cache, object);
+		__kasan_poison_new_object(cache, object);
 }
 
 void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
@@ -342,9 +361,9 @@ static inline bool kasan_unpoison_pages(struct page *page, unsigned int order,
 	return false;
 }
 static inline void kasan_poison_slab(struct slab *slab) {}
-static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
+static inline void kasan_unpoison_new_object(struct kmem_cache *cache,
 					void *object) {}
-static inline void kasan_poison_object_data(struct kmem_cache *cache,
+static inline void kasan_poison_new_object(struct kmem_cache *cache,
 					void *object) {}
 static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
 				const void *object)
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 65850d37fd27..9f11be6b00a8 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -133,12 +133,12 @@ void __kasan_poison_slab(struct slab *slab)
 		     KASAN_SLAB_REDZONE, false);
 }
 
-void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
+void __kasan_unpoison_new_object(struct kmem_cache *cache, void *object)
 {
 	kasan_unpoison(object, cache->object_size, false);
 }
 
-void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
+void __kasan_poison_new_object(struct kmem_cache *cache, void *object)
 {
 	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
 			KASAN_SLAB_REDZONE, false);
diff --git a/mm/slab.c b/mm/slab.c
index 9ad3d0f2d1a5..773c79e153f3 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -2327,11 +2327,9 @@ static void cache_init_objs_debug(struct kmem_cache *cachep, struct slab *slab)
 		 * They must also be threaded.
 		 */
 		if (cachep->ctor && !(cachep->flags & SLAB_POISON)) {
-			kasan_unpoison_object_data(cachep,
-						   objp + obj_offset(cachep));
+			kasan_unpoison_new_object(cachep, objp + obj_offset(cachep));
 			cachep->ctor(objp + obj_offset(cachep));
-			kasan_poison_object_data(
-				cachep, objp + obj_offset(cachep));
+			kasan_poison_new_object(cachep, objp + obj_offset(cachep));
 		}
 
 		if (cachep->flags & SLAB_RED_ZONE) {
@@ -2472,9 +2470,9 @@ static void cache_init_objs(struct kmem_cache *cachep,
 
 		/* constructor could break poison info */
 		if (DEBUG == 0 && cachep->ctor) {
-			kasan_unpoison_object_data(cachep, objp);
+			kasan_unpoison_new_object(cachep, objp);
 			cachep->ctor(objp);
-			kasan_poison_object_data(cachep, objp);
+			kasan_poison_new_object(cachep, objp);
 		}
 
 		if (!shuffled)
diff --git a/mm/slub.c b/mm/slub.c
index 63d281dfacdb..973f091ec5d1 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1849,9 +1849,9 @@ static void *setup_object(struct kmem_cache *s, void *object)
 	setup_object_debug(s, object);
 	object = kasan_init_slab_obj(s, object);
 	if (unlikely(s->ctor)) {
-		kasan_unpoison_object_data(s, object);
+		kasan_unpoison_new_object(s, object);
 		s->ctor(object);
-		kasan_poison_object_data(s, object);
+		kasan_poison_new_object(s, object);
 	}
 	return object;
 }
diff --git a/net/core/skbuff.c b/net/core/skbuff.c
index b157efea5dea..63bb6526399d 100644
--- a/net/core/skbuff.c
+++ b/net/core/skbuff.c
@@ -337,7 +337,7 @@ static struct sk_buff *napi_skb_cache_get(void)
 	}
 
 	skb = nc->skb_cache[--nc->skb_count];
-	kasan_unpoison_object_data(skbuff_cache, skb);
+	kasan_unpoison_new_object(skbuff_cache, skb);
 
 	return skb;
 }
@@ -1309,13 +1309,13 @@ static void napi_skb_cache_put(struct sk_buff *skb)
 	struct napi_alloc_cache *nc = this_cpu_ptr(&napi_alloc_cache);
 	u32 i;
 
-	kasan_poison_object_data(skbuff_cache, skb);
+	kasan_poison_new_object(skbuff_cache, skb);
 	nc->skb_cache[nc->skb_count++] = skb;
 
 	if (unlikely(nc->skb_count == NAPI_SKB_CACHE_SIZE)) {
 		for (i = NAPI_SKB_CACHE_HALF; i < NAPI_SKB_CACHE_SIZE; i++)
-			kasan_unpoison_object_data(skbuff_cache,
-						   nc->skb_cache[i]);
+			kasan_unpoison_new_object(skbuff_cache,
+						  nc->skb_cache[i]);
 
 		kmem_cache_free_bulk(skbuff_cache, NAPI_SKB_CACHE_HALF,
 				     nc->skb_cache + NAPI_SKB_CACHE_HALF);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1128fd5cf1051270bc7e5978479a983a918626f5.1699297309.git.andreyknvl%40google.com.
