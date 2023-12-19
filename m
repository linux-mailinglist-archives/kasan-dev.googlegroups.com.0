Return-Path: <kasan-dev+bncBAABB75TRCWAMGQEVGQDCMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 24FA28193A0
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:32:32 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-333501e22casf3355136f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:32:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703025151; cv=pass;
        d=google.com; s=arc-20160816;
        b=CE6V/pROehI7rhGj+V3OWNIfP3ehbdn5pdVi+1TRVl4DeXFRSVPDNNREhZb/OVcoQx
         9CLYAMsoNgs3PaIbQdkwvm5NurZucSLj7vD4lS1SrKK95r6URdmNuNy3RT23QjkYRp4N
         l92J0hzkbZK30y5QkcA21j7uSNW6+SCURfql0DhfWPKS1lD2lo/QmC8MjZdR+kiQ+iGN
         Lq6HErVdSYoSHaTc7k0XZeL8T2OhRj21h0/xcvxJ1fUtQAHp4psHLDyDN42V3zQJVhJf
         AXvO0esZXaT8b8u5y8J0M9qKu0rTes0QT/V6IclZOa6khDmuoRUi50E/sOSkSHGi0PVr
         ynNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZxgD5TYLgFhdpVJpGTQVN/6q8GaSrFKiSLG4cuXNZDg=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=OfSSZ6CScZpLzsZAZziHFpOCy7uHP0JedA8jlvgUX3dlbBHkPwHXDzyPGorFkxTS+L
         RYbf8/rFFsBA4G76WRZNV4aO5XsVAloXdjC5Z9dpTXhtnczDo++GUnNuBwYFjR9yUpQ9
         SF3Dt1kEoQQ+dZ6QQ3fwV+YYjSvhzSWRrooMGJBNZoZj1NURptioALPuZ33Sk11Ro9Nr
         ZZc9vTsaeobLbj+asiiJLIH5mK0ClmA6e8eymzn/BwHBklFJ/0Ca4UnGHkmMwC7mM3xd
         XaZjfAFwtljS3QfrqB7+UrEQbETz9phkDEca2PAO7hFjIpm4ME9QTLndX4YORg0UseHg
         rGxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bmAVzIYf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703025151; x=1703629951; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZxgD5TYLgFhdpVJpGTQVN/6q8GaSrFKiSLG4cuXNZDg=;
        b=dYrlMIAcSKA2DDxr+lJmPdB0dmWLE4U/y+TyIUxLFt198VOXHlKIaB4+LJfswNjG8p
         baoJT8In1KnNdwW3lWjjkO3EG7B8PwBR/CtF3OuFyzosKp+/LcXkZ5AEaNthxNexK8z8
         ZbKoOLU2KAVPS4tYt/BKByP9kJyX/QzSQH02JM+R8Cb46gBejxaNDRVig8iFxIopLNRK
         owkfQHQe04BZtzEe4jJ784DP20AU6FvQLAOIvyhoCRI8y9z5gemlmwrGAT2IG7DiTPo6
         /0EYjP2KtMprvGDAVynsEBCibEAclwmQoMxi7PyPbUu5YxoJDfugsZwn8dLuieu5i80d
         jYgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703025151; x=1703629951;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZxgD5TYLgFhdpVJpGTQVN/6q8GaSrFKiSLG4cuXNZDg=;
        b=XjCiMfhoa/FInNheS4D5z97fyHltx73JNgDLMO0+p5q+c9KsckB0Mt9gnWByJQasue
         MiJpkipQygNFQ7suoYBeDSaK3fgwNejKyQxlbNlNdHjWlxLP2KVKqn+72gK/4B3ODRnX
         krCjalzkT2wZPY9sBmALpQmi2lq5tHeIUeClg5/6m6PmTJcnxbacVrgXGsmC0AdqGu2R
         BnHW239MRL37JMVeOU7xmjIvHdbwnD8lIC8JqfwsN5Fq36gii/97RBV7Ab8OyjptbJXR
         Fp4vvF9EMvd7mzl6iepM6WixD4lJU1jrJvlp7yPgZtqjxcG+qdvMfJx1THAIcKEQgfor
         Wngw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzI8HBrISZfX6qCKYSNyjTWrtdpr650yG0aJ9jXwlZkpsMvzIsW
	9NqDUbWmGPjCepGGA4yc7OI=
X-Google-Smtp-Source: AGHT+IEwLXXZ0Ks5gvsbw3n+BFRYnH530l4J1unpriOmwmGKapU4H0kw3yM0ho0Cjsl9EFG2UzK1HQ==
X-Received: by 2002:a5d:4592:0:b0:336:6dba:e092 with SMTP id p18-20020a5d4592000000b003366dbae092mr1842220wrq.3.1703025151565;
        Tue, 19 Dec 2023 14:32:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:2ca:b0:336:6089:7fb1 with SMTP id
 o10-20020a05600002ca00b0033660897fb1ls449168wry.2.-pod-prod-03-eu; Tue, 19
 Dec 2023 14:32:30 -0800 (PST)
X-Received: by 2002:a05:600c:4749:b0:40b:5e21:cc36 with SMTP id w9-20020a05600c474900b0040b5e21cc36mr9143784wmo.97.1703025149745;
        Tue, 19 Dec 2023 14:32:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703025149; cv=none;
        d=google.com; s=arc-20160816;
        b=sBIeA+HKi0Ka0lKCp6aSdAvGKxDhy7+zoXUflNK9ivbQqKYiBuPoXcGeIocNwdbc4n
         If3Kjo+Kv19focUC0nxD8x/0WGniW/46OXpW+ATLW4fsHVnUvKr6CK3Dl6mtphshJ/fz
         J8zg2aSnElGjQSjhEvqzp88l1I2Tsym9qF67iNYV+uFnEN1PmmDrlMAwV5S5ZCcB9ftK
         ppkezJHa+OYk5c2Ly4rhKopIjeHiW3srtX3rdQkavGIaQj81gxRvWhgEAkVH/aht1Onh
         tbsi/Cd30XDBgJPgGSF3BGMIJ96x/YJMnwEGXKEe9lT+rn6zctIvV6g+23iUsV3deQM2
         JeiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mlYQJh3Zrut4xXu3wLWLs7KGtUj3CeTDuDfdtjdzU7g=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=nYXt4la37PpgmCSjTkzQa1LsVuJzsFqUKWBmFj1oz6yjDGurzDNbDoYt43I8/Pf7N1
         825Fx95AQfZZoPyULzhSyBhncfsuOEVic8KBE+p+1VramEDcnXFbc4Y0hR32bZsGDUmu
         QIdNi4rCl63tyER5S4lBcfN/HgWB9iaUEaqq8Ut/i06meFxpIjgBxyF3myLOTS1WSMtX
         sfgKJBdDBIhfeu3zK4ip9OYqEZJutsj6YgcKtFpJ+5fqQMN1Jk/nToLTOlE3oGgkBLI4
         ll8S+4jGnppxDS/Euxx4VN+aVhANkUhPcyTOuJMNwG/0X+cRRyesJmDfX2ZNoF+bLHL2
         dUHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bmAVzIYf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-185.mta1.migadu.com (out-185.mta1.migadu.com. [95.215.58.185])
        by gmr-mx.google.com with ESMTPS id e16-20020a05600c4e5000b0040d24b04686si478wmq.1.2023.12.19.14.32.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:32:29 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as permitted sender) client-ip=95.215.58.185;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Breno Leitao <leitao@debian.org>,
	Alexander Lobakin <alobakin@pm.me>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 19/21] kasan: rename and document kasan_(un)poison_object_data
Date: Tue, 19 Dec 2023 23:29:03 +0100
Message-Id: <eab156ebbd635f9635ef67d1a4271f716994e628.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=bmAVzIYf;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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
index b8e7416f83af..ebb1b23d6480 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -143,12 +143,12 @@ void __kasan_poison_slab(struct slab *slab)
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
index 782bd8a6bd34..891742e5932a 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1860,9 +1860,9 @@ static void *setup_object(struct kmem_cache *s, void *object)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/eab156ebbd635f9635ef67d1a4271f716994e628.1703024586.git.andreyknvl%40google.com.
