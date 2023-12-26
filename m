Return-Path: <kasan-dev+bncBAABB5NRVWWAMGQEEH74ZQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5676881EA62
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Dec 2023 23:51:35 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2cccbd5201asf11392191fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Dec 2023 14:51:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703631094; cv=pass;
        d=google.com; s=arc-20160816;
        b=MT7hQu+/XfvfFxRgOGysjXP1kVt9xoOaosBC56asgnJZSBEDOC+08zkobein9G2NyS
         pH1+QqA5fEKZEDYZJ3pTfag53wnLb51bHNSXyRqx7g3SRUA13kmg2kbGMyES88pPrNzq
         lbIqNPTEbRdv63Fp0eb91Lngvywwg0b/w0IJ72Rr9/hgjvLpwwsZx2IhuIymrxXT/ewF
         QSZGnJU3Z5LPFepwB33losrHDK2TNmSxtVkBmwF9Yv5CvJZwCg7eJU9ASYsbXhJcAWlx
         6yt9QCNlwavUZvoG8mLRe38+g+DfuWQeCPTTHnc4JmX1lChSBvv/eP8txQAvuaKhHb0+
         rMDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=vQf8g/xf3eBEPqFYtpdY6j+1o4Gm0GfV1WyuW9trebY=;
        fh=sulfNaRLmIKl9mTxbTte4v+SlAbgVb4Hhi1Mpp+QlnA=;
        b=l7bF/7ip+n8azTTc65VVPHeOt7RSCrXhKjrfpvicGB/E+xfmjREOZPj3GJDDrowF/w
         FMHykPgUgaFJ2SY70teZV4NvQwyx4M4UNuphEWvJmfobnFytxzc54w6nDERw9ChI/7Lh
         xLE4A5ISi0urNVT9Y5dZHlHoktevy7AKYgujAoC4d2PMD7wI2TSU+ek9IlbCnqS0lIKj
         1FaW82FEBwJI1DrkGWLJkRJ5yklg/CY+YejMGtAbN0lDJewUrtmUPWNf8tVoJ+FZFFU2
         3vCDkcBS1abIvaTp2ohkjJNjWtFInofwE8XAAB0Bw6gsX5VCHpPCeOhGrRbXW93aQvMc
         Bm1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KsKHNPqD;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.177 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703631094; x=1704235894; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vQf8g/xf3eBEPqFYtpdY6j+1o4Gm0GfV1WyuW9trebY=;
        b=UqNoQOzTTs0pHGC1HekcCMH7r/kJH8kuz94VWGF50+AquzN/oYxhszFDf/rMBkDDU+
         lxlhN7GDyf97tDbSP/V2RGudGa+00RmpSUEcwIqqTpkv9krsfjZ7CXcYG0BzfjYt7euB
         wkrTbu6XryhAU+Ee9rhEEQZ59RbNSlVe48IJbmH1XZ4/DfQull9aT3yf2W8BAudP4id7
         n9lA4Tz1cx/GeHKMCA214LaDmVrl0/Xxh5+sOyNM0U+hhWDbdyUFE1nAbM1j0aO3d0MM
         Bh+i8Uf8Jj3EvqNoxJZwBrUTT6Y/7r2xmqmpu8VndYqcuuyqtk+Go9aedWV7O17kDpVu
         bYMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703631094; x=1704235894;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vQf8g/xf3eBEPqFYtpdY6j+1o4Gm0GfV1WyuW9trebY=;
        b=lW2pM2Btw49hiOM+VfeJx5/3YdrHhOMKR8yupgaG2YZmrvX+Rm4TJfMR1+a7KAG2vB
         kS4sDhGNkIiufCJpR6uNSfhar6GYUgKPuIW+ui43JcUaDPJFq440ywkh5n5KTmdJ6PuH
         VNw1IFbclqrs6NPwpVHvHr+2HxJfEIS6c264JKQxTjHpb3N7uvvhTByNyi1B6lDhx1Wo
         P5Co0lPRPVdvjfo3u6JEE+8Wr+0dXR5CazNsMkpt8kZI+p9WUeZpGrbH4Ld4GLh4UyTk
         tG0TRy3lj0kNf8L0HU+qQ8bz6QP+ovn6WSWGayfYyqlHzO1R1RolvH9cX7MnxHmBu7D/
         DIaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw01pBncZOvy00850UVjJbXu2cq/7XO72Z1jCW58hAUZC88Wwtz
	ezSuQHANexGiN6mBcSKFuyY=
X-Google-Smtp-Source: AGHT+IEHu04b8G6E1M5aLF9x3jvBgdLqXyswl45W4HkmskuzLADfkKE5XORdLXTzskZRneKz71+6cA==
X-Received: by 2002:a2e:b742:0:b0:2cc:72fc:c900 with SMTP id k2-20020a2eb742000000b002cc72fcc900mr1523474ljo.165.1703631094089;
        Tue, 26 Dec 2023 14:51:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:889a:0:b0:2cc:acc8:ade5 with SMTP id k26-20020a2e889a000000b002ccacc8ade5ls338364lji.1.-pod-prod-08-eu;
 Tue, 26 Dec 2023 14:51:32 -0800 (PST)
X-Received: by 2002:a2e:3904:0:b0:2cc:a6b6:a5ac with SMTP id g4-20020a2e3904000000b002cca6b6a5acmr1451793lja.113.1703631092165;
        Tue, 26 Dec 2023 14:51:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703631092; cv=none;
        d=google.com; s=arc-20160816;
        b=qQCEHq0X6PzU2F4wmn9KCl2mDOfc3ylfI/LbJSQFyganPWczMALytsZUhriLPy/CD8
         i5FgCGktBzuZF3gTG8/Gm5nH6B0SM4Evluh+jYxgmBlDvctmH+LjKRDx6594GmEg2Obf
         vhNrMp2iM85bPNMcfnD448dk5qL5zx1zks2YNhsi1G6Vxw5ct3xqzgyhAumgFcR3F6Yl
         Aqcs50LI+aCtxa6wXkrGhIwJG2p2qXPfmDW+YQClOfPhcXmj7j6vpyUkVNKuUiXDEzi+
         6nU2wbQ17qrm6RWpPbCepFJOeNsSNQtZDLyqSNGdPVErKA0pnoAMB5TUPr0nh/QyGNzB
         rUZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=KAcZVWUdwxMgEguWO/ipgfFw4d2BOub4xvB7dxmq+gU=;
        fh=sulfNaRLmIKl9mTxbTte4v+SlAbgVb4Hhi1Mpp+QlnA=;
        b=kzHk5is6vGsZVN4frE5venUAe1gk12Yh75+3RzqyWlv/Nnfiq8wP0/WUQHVH9lpfH6
         pj85ndeBbCEAIghcDMcN1WPbuisLiuSaluMMv6aN0RbIYCX+exNKhpFjzPXrs6qudM3A
         Xpg6seSUzH9Jdvb64Wqe9woscsFgf0wvpcqoMcePnGZpDGom6yl3ZM3fQQz1587dF3xe
         RVOYov+WMrZvgnDGfgnFGDZR19dn0l6Pxoc4I0Sa45GijtAhQlmNccG2T9GrOpqdj5Ic
         yfkf/gsGUbXi4P01M/gsq2UG3QimnQbF5c9+yLWo7/sg5tOHfrAi7V8Q7Mn3N+wa567p
         pQRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KsKHNPqD;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.177 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-177.mta1.migadu.com (out-177.mta1.migadu.com. [95.215.58.177])
        by gmr-mx.google.com with ESMTPS id u11-20020a2e91cb000000b002ccac2103f7si329518ljg.3.2023.12.26.14.51.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Dec 2023 14:51:31 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.177 as permitted sender) client-ip=95.215.58.177;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm] kasan: stop leaking stack trace handles
Date: Tue, 26 Dec 2023 23:51:21 +0100
Message-Id: <20231226225121.235865-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=KsKHNPqD;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.177 as
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

Commit 773688a6cb24 ("kasan: use stack_depot_put for Generic mode") added
support for stack trace eviction for Generic KASAN.

However, that commit didn't evict stack traces when the object is not put
into quarantine. As a result, some stack traces are never evicted from
the stack depot.

In addition, with the "kasan: save mempool stack traces" series, the
free stack traces for mempool objects are also not properly evicted from
the stack depot.

Fix both issues by:

1. Evicting all stack traces when an object if freed if it was not put
   into quarantine;

2. Always evicting an existing free stack trace when a new one is saved.

Also do a few related clean-ups:

- Do not zero out free track when initializing/invalidating free meta:
  set a value in shadow memory instead;

- Rename KASAN_SLAB_FREETRACK to KASAN_SLAB_FREE_META;

- Drop the kasan_init_cache_meta function as it's not used by KASAN;

- Add comments for the kasan_alloc_meta and kasan_free_meta structs.

Fixes: 773688a6cb24 ("kasan: use stack_depot_put for Generic mode")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Andrew, please put this as a separate patch on top of all KASAN patches
in mm.
---
 mm/kasan/common.c         | 27 +++++++++++++++---
 mm/kasan/generic.c        | 60 +++++++++++++++++++++++++++++++++------
 mm/kasan/kasan.h          | 25 ++++++++++++----
 mm/kasan/quarantine.c     | 20 +------------
 mm/kasan/report_generic.c |  6 ++--
 5 files changed, 97 insertions(+), 41 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a486e9b1ac68..223af53d4338 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -255,14 +255,33 @@ static inline bool poison_slab_object(struct kmem_cache *cache, void *object,
 bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 				unsigned long ip, bool init)
 {
-	bool buggy_object;
-
 	if (is_kfence_address(object))
 		return false;
 
-	buggy_object = poison_slab_object(cache, object, ip, init);
+	/*
+	 * If the object is buggy, do not let slab put the object onto the
+	 * freelist. The object will thus never be allocated again and its
+	 * metadata will never get released.
+	 */
+	if (poison_slab_object(cache, object, ip, init))
+		return true;
+
+	/*
+	 * If the object is put into quarantine, do not let slab put the object
+	 * onto the freelist for now. The object's metadata is kept until the
+	 * object gets evicted from quarantine.
+	 */
+	if (kasan_quarantine_put(cache, object))
+		return true;
+
+	/*
+	 * If the object is not put into quarantine, it will likely be quickly
+	 * reallocated. Thus, release its metadata now.
+	 */
+	kasan_release_object_meta(cache, object);
 
-	return buggy_object ? true : kasan_quarantine_put(cache, object);
+	/* Let slab put the object onto the freelist. */
+	return false;
 }
 
 static inline bool check_page_allocation(void *ptr, unsigned long ip)
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 0e77c43c559e..fc22ea1af775 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -480,10 +480,10 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
 {
 	struct kasan_alloc_meta *alloc_meta;
-	struct kasan_free_meta *free_meta;
 
 	alloc_meta = kasan_get_alloc_meta(cache, object);
 	if (alloc_meta) {
+		/* Zero out alloc meta to mark it as invalid. */
 		__memset(alloc_meta, 0, sizeof(*alloc_meta));
 
 		/*
@@ -495,9 +495,50 @@ void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
 		raw_spin_lock_init(&alloc_meta->aux_lock);
 		kasan_enable_current();
 	}
+
+	/*
+	 * Explicitly marking free meta as invalid is not required: the shadow
+	 * value for the first 8 bytes of a newly allocated object is not
+	 * KASAN_SLAB_FREE_META.
+	 */
+}
+
+void release_alloc_meta(struct kasan_alloc_meta *meta)
+{
+	/* Evict the stack traces from stack depot. */
+	stack_depot_put(meta->alloc_track.stack);
+	stack_depot_put(meta->aux_stack[0]);
+	stack_depot_put(meta->aux_stack[1]);
+
+	/* Zero out alloc meta to mark it as invalid. */
+	__memset(meta, 0, sizeof(*meta));
+}
+
+void release_free_meta(const void *object, struct kasan_free_meta *meta)
+{
+	/* Check if free meta is valid. */
+	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREE_META)
+		return;
+
+	/* Evict the stack trace from the stack depot. */
+	stack_depot_put(meta->free_track.stack);
+
+	/* Mark free meta as invalid. */
+	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREE;
+}
+
+void kasan_release_object_meta(struct kmem_cache *cache, const void *object)
+{
+	struct kasan_alloc_meta *alloc_meta;
+	struct kasan_free_meta *free_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (alloc_meta)
+		release_alloc_meta(alloc_meta);
+
 	free_meta = kasan_get_free_meta(cache, object);
 	if (free_meta)
-		__memset(free_meta, 0, sizeof(*free_meta));
+		release_free_meta(object, free_meta);
 }
 
 size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
@@ -573,11 +614,8 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 	if (!alloc_meta)
 		return;
 
-	/* Evict previous stack traces (might exist for krealloc). */
-	stack_depot_put(alloc_meta->alloc_track.stack);
-	stack_depot_put(alloc_meta->aux_stack[0]);
-	stack_depot_put(alloc_meta->aux_stack[1]);
-	__memset(alloc_meta, 0, sizeof(*alloc_meta));
+	/* Evict previous stack traces (might exist for krealloc or mempool). */
+	release_alloc_meta(alloc_meta);
 
 	kasan_save_track(&alloc_meta->alloc_track, flags);
 }
@@ -590,7 +628,11 @@ void kasan_save_free_info(struct kmem_cache *cache, void *object)
 	if (!free_meta)
 		return;
 
+	/* Evict previous stack trace (might exist for mempool). */
+	release_free_meta(object, free_meta);
+
 	kasan_save_track(&free_meta->free_track, 0);
-	/* The object was freed and has free track set. */
-	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREETRACK;
+
+	/* Mark free meta as valid. */
+	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREE_META;
 }
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 814e89523c64..645ae04539c9 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -156,7 +156,7 @@ static inline bool kasan_requires_meta(void)
 
 #ifdef CONFIG_KASAN_GENERIC
 
-#define KASAN_SLAB_FREETRACK	0xFA  /* freed slab object with free track */
+#define KASAN_SLAB_FREE_META	0xFA  /* freed slab object with free meta */
 #define KASAN_GLOBAL_REDZONE	0xF9  /* redzone for global variable */
 
 /* Stack redzone shadow values. Compiler ABI, do not change. */
@@ -253,6 +253,15 @@ struct kasan_global {
 
 #ifdef CONFIG_KASAN_GENERIC
 
+/*
+ * Alloc meta contains the allocation-related information about a slab object.
+ * Alloc meta is saved when an object is allocated and is kept until either the
+ * object returns to the slab freelist (leaves quarantine for quarantined
+ * objects or gets freed for the non-quarantined ones) or reallocated via
+ * krealloc or through a mempool.
+ * Alloc meta is stored inside of the object's redzone.
+ * Alloc meta is considered valid whenever it contains non-zero data.
+ */
 struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
 	/* Free track is stored in kasan_free_meta. */
@@ -278,8 +287,12 @@ struct qlist_node {
 #define KASAN_NO_FREE_META INT_MAX
 
 /*
- * Free meta is only used by Generic mode while the object is in quarantine.
- * After that, slab allocator stores the freelist pointer in the object.
+ * Free meta contains the freeing-related information about a slab object.
+ * Free meta is only kept for quarantined objects and for mempool objects until
+ * the object gets allocated again.
+ * Free meta is stored within the object's memory.
+ * Free meta is considered valid whenever the value of the shadow byte that
+ * corresponds to the first 8 bytes of the object is KASAN_SLAB_FREE_META.
  */
 struct kasan_free_meta {
 	struct qlist_node quarantine_link;
@@ -380,15 +393,15 @@ void kasan_report_invalid_free(void *object, unsigned long ip, enum kasan_report
 struct slab *kasan_addr_to_slab(const void *addr);
 
 #ifdef CONFIG_KASAN_GENERIC
-void kasan_init_cache_meta(struct kmem_cache *cache, unsigned int *size);
-void kasan_init_object_meta(struct kmem_cache *cache, const void *object);
 struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
 						const void *object);
 struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 						const void *object);
+void kasan_init_object_meta(struct kmem_cache *cache, const void *object);
+void kasan_release_object_meta(struct kmem_cache *cache, const void *object);
 #else
-static inline void kasan_init_cache_meta(struct kmem_cache *cache, unsigned int *size) { }
 static inline void kasan_init_object_meta(struct kmem_cache *cache, const void *object) { }
+static inline void kasan_release_object_meta(struct kmem_cache *cache, const void *object) { }
 #endif
 
 depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags);
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 782e045da911..8afa77bc5d3b 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -143,22 +143,10 @@ static void *qlink_to_object(struct qlist_node *qlink, struct kmem_cache *cache)
 static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
 {
 	void *object = qlink_to_object(qlink, cache);
-	struct kasan_alloc_meta *alloc_meta = kasan_get_alloc_meta(cache, object);
 	struct kasan_free_meta *free_meta = kasan_get_free_meta(cache, object);
 	unsigned long flags;
 
-	if (alloc_meta) {
-		stack_depot_put(alloc_meta->alloc_track.stack);
-		stack_depot_put(alloc_meta->aux_stack[0]);
-		stack_depot_put(alloc_meta->aux_stack[1]);
-		__memset(alloc_meta, 0, sizeof(*alloc_meta));
-	}
-
-	if (free_meta &&
-	    *(u8 *)kasan_mem_to_shadow(object) == KASAN_SLAB_FREETRACK) {
-		stack_depot_put(free_meta->free_track.stack);
-		__memset(&free_meta->free_track, 0, sizeof(free_meta->free_track));
-	}
+	kasan_release_object_meta(cache, object);
 
 	/*
 	 * If init_on_free is enabled and KASAN's free metadata is stored in
@@ -170,12 +158,6 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
 	    cache->kasan_info.free_meta_offset == 0)
 		memzero_explicit(free_meta, sizeof(*free_meta));
 
-	/*
-	 * As the object now gets freed from the quarantine,
-	 * take note that its free track is no longer exists.
-	 */
-	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREE;
-
 	if (IS_ENABLED(CONFIG_SLAB))
 		local_irq_save(flags);
 
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 99cbcd73cff7..f5b8e37b3805 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -110,7 +110,7 @@ static const char *get_shadow_bug_type(struct kasan_report_info *info)
 		bug_type = "use-after-free";
 		break;
 	case KASAN_SLAB_FREE:
-	case KASAN_SLAB_FREETRACK:
+	case KASAN_SLAB_FREE_META:
 		bug_type = "slab-use-after-free";
 		break;
 	case KASAN_ALLOCA_LEFT:
@@ -173,8 +173,8 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 		memcpy(&info->alloc_track, &alloc_meta->alloc_track,
 		       sizeof(info->alloc_track));
 
-	if (*(u8 *)kasan_mem_to_shadow(info->object) == KASAN_SLAB_FREETRACK) {
-		/* Free meta must be present with KASAN_SLAB_FREETRACK. */
+	if (*(u8 *)kasan_mem_to_shadow(info->object) == KASAN_SLAB_FREE_META) {
+		/* Free meta must be present with KASAN_SLAB_FREE_META. */
 		free_meta = kasan_get_free_meta(info->cache, info->object);
 		memcpy(&info->free_track, &free_meta->free_track,
 		       sizeof(info->free_track));
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231226225121.235865-1-andrey.konovalov%40linux.dev.
