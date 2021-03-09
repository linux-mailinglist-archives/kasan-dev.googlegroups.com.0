Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKHOTWBAMGQEYVSVIQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 433E7332702
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 14:24:57 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id j15sf4740096lfe.2
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 05:24:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615296296; cv=pass;
        d=google.com; s=arc-20160816;
        b=IgdlkEvjUfzhMABXJaLDr5hafkzoIO0XL5CS3YbKUrWo1szE0T8GOGwOL0fihh8WGW
         ZSHu3Owv6f/0cOdW48t/vwNNivAqhnO0ws6t8m2uUtIspNEbPp65lJ+/oIgH/V/82NiO
         SHe80Wx/Vh9HgKTlnDBnbeki8vzJEWF92fDOseO3HRfGDfFl0LaQ3n7+22bIy9faoXlI
         f3Seey8NMQ+YcmbKrz4HkCtalYylOb0Iooj/9ia2sJTTEjo9NmAXe3zxIvCuRmvigmnj
         6nQa1Hyp/uiqgRqYlHdsVhTpJJPntIypCBWA12EZdnvh/EWodifoymo3DXfUBb3cRX13
         kxcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=NZGpWdAnNAow/o+GkWcdsu/HQGkhvfSxzP6dZZECKdQ=;
        b=ZY0LQEvceQ66zWe2diFcgkofYlAzXTenbEIcbYGphzcYmRsjbfnRuhpqYG9EXC/mxc
         X8k+LaDmddWyi8pZvj+TrfWWDefo/HhWJjW8Z47jm2hS3Dr+2RTtNP+cGNGB8w+ilGXs
         iRrwviOpDWzXeiy4fvnvZr/A17rNqzaTaLS7gLjBEUYQMcIb3BR1GWq7x99AbPH30RvX
         w0H+M8j5t/kpyLjmj5UHOamX9qr0a6oTrUpl+TqMaamosUhhHjjnnS4MPkiwxvYWFr37
         GKl7oqHjAWLQxfE5IIEsRn+f5l4CiV3lledR0u/iGwkZWUGyaHhoGvEIi8hZ2pIaFNEO
         JV9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XsWCn7FE;
       spf=pass (google.com: domain of 3j3dhyaokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3J3dHYAoKCTwYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NZGpWdAnNAow/o+GkWcdsu/HQGkhvfSxzP6dZZECKdQ=;
        b=j3jbOGUuf3SLUhAsSsgkb/Dc1jfyNZKc7xxaR58UdxR8zTylAFonbZp6xzZsYG68k2
         s/U6lPCI4Pk91U+ISbeffzEn7o4hk9ilgOlQedkBGSS9lzNlMI4ux55V9/9Z/9X5Axw6
         aPXO++OSNlcPvMEcqPeuVMXzImTPBHxjvWxGMluBc7PIOEwVC89TiWVoTl2lhmPNVCJv
         lijJ/n/oXU2QSVQ8Mpqi5TdbaKY7EpVdNmAkl/BMemMS+jEFrtFjpBnK8h0UYe86vuLP
         /MC2vz1gtTZH3Mm0pzfp9skYp6in5lEtIDMsU9+DnXcg4eHskLiYzhMCzSPw/LHZbYRR
         77+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NZGpWdAnNAow/o+GkWcdsu/HQGkhvfSxzP6dZZECKdQ=;
        b=s700lv8+Hjoq4K9sKaBpj6r7K3VRMTP5yjZ76MEkrALzr9gKaOOpZCpB1TBpL96B/a
         3FVflh1cMvgQh6IFyTMU/HjI+EAc5dXhmy5t9OgbHYlWovCVyp6JrW2Ah2sU/DP69UE6
         EoO5a57/V1m7RfzoV1g0hEXd2p/ddIzjxkMRklWGxHoIlhNILqtIRdpKR6csg00PZ8oX
         4Sg7JNmpFu85tTX2GnQqqmQNdZ3KGwd9ia3ySwHRCgnWzwqA70HYKDraUneBBvgTEwk8
         WfbA9myroK1hblEX9K4/cd6cMXLmfuEsHG8oK7Rz5PJ8blIYzdqZ4nIzHbRQvt7PA1+7
         yY4w==
X-Gm-Message-State: AOAM533+n+0zva1KO9He45n/mLmUf53Lnwm9Aqjkn/J/0MVFp8YFtbDO
	rnWkGLHE5RE2btVpTnAdj3Y=
X-Google-Smtp-Source: ABdhPJzJikGirqKC/l6Xm1hzwdwfLhu9ZMHMHSOiglHe41HSz6c0W6SCDt52OlVtj0ZG/Jr2a8iEcA==
X-Received: by 2002:a19:7403:: with SMTP id v3mr17231228lfe.379.1615296296813;
        Tue, 09 Mar 2021 05:24:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3c10:: with SMTP id j16ls3565971lja.2.gmail; Tue, 09 Mar
 2021 05:24:55 -0800 (PST)
X-Received: by 2002:a05:651c:513:: with SMTP id o19mr17645594ljp.68.1615296295813;
        Tue, 09 Mar 2021 05:24:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615296295; cv=none;
        d=google.com; s=arc-20160816;
        b=YNb6Kq+plwIQw7/IL2M5U+k+aghrW4a3rEXRS6Ar+tLe8fiSOhFz2u6jSawB4iYoQO
         GaWZ7T3AgAq+CCi/seXfkDVQeSXcAnAqm+x1ddz6cXRvYiAlGlAVij0RAHM4/wjKavvF
         dI93076rK7rEhdjQGo/sFuVKErl+QA37iR6lv9Ih3snEBbgC0glYS/DK2hnWksSO3WA9
         WaLkyzkDH6sRU2DW+2V1eh5Cj5JgQVS8v5ceR/GX3mfPAgvzJvhcJaQjFtwhg98awPGH
         Y2BYt8k9+HbRXp6WBAvLDhPZgM7ZLlBfHxW1q5gltIOfSx+DxXSrQZzUrZwpsQpXgdN1
         Ip5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=qJAXU5d3STshdjmo9ZaLGYR5dtJDA06hL5AxGivV8jc=;
        b=M3xlw9je0mTqcSYK3cE8k731XVYmlPYZLQkenQ6+Hy9kqkLzok9W3S3VbaJyT6zVW4
         s8A95aqQqmQynHz8KjC4J0fcqvq3OKxJQz+90iONj74lFA8s7Ool+cUKSwMeiRZO6ew+
         GBuA7HK88J+O/fC2rSdiCYuPjtxMYyxOkmf4SQZclrttqaLubO7gA1ynBDS63rLBLIaX
         1zFW1QQB6M7V0H2jakVu1VdEWkufYUvH4CSnoDgV2p1+neMXysctjOAoQl+v0mtySwi6
         8/4MO6Hy7NR9/FQp/O556gacA4gUGOYvaR2zVaRXwTd1lbTJqwqFmqRtzzPdeD+hgELt
         MV8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XsWCn7FE;
       spf=pass (google.com: domain of 3j3dhyaokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3J3dHYAoKCTwYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id a10si175560lfs.11.2021.03.09.05.24.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Mar 2021 05:24:55 -0800 (PST)
Received-SPF: pass (google.com: domain of 3j3dhyaokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id m23so1428458wrh.7
        for <kasan-dev@googlegroups.com>; Tue, 09 Mar 2021 05:24:55 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:5802:818:ce92:dfef])
 (user=andreyknvl job=sendgmr) by 2002:a1c:7715:: with SMTP id
 t21mr4007265wmi.132.1615296295273; Tue, 09 Mar 2021 05:24:55 -0800 (PST)
Date: Tue,  9 Mar 2021 14:24:39 +0100
In-Reply-To: <cover.1615296150.git.andreyknvl@google.com>
Message-Id: <190fd15c1886654afdec0d19ebebd5ade665b601.1615296150.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1615296150.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH v3 5/5] kasan, mm: integrate slab init_on_free with HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XsWCn7FE;       spf=pass
 (google.com: domain of 3j3dhyaokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3J3dHYAoKCTwYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This change uses the previously added memory initialization feature
of HW_TAGS KASAN routines for slab memory when init_on_free is enabled.

With this change, memory initialization memset() is no longer called
when both HW_TAGS KASAN and init_on_free are enabled. Instead, memory
is initialized in KASAN runtime.

For SLUB, the memory initialization memset() is moved into
slab_free_hook() that currently directly follows the initialization loop.
A new argument is added to slab_free_hook() that indicates whether to
initialize the memory or not.

To avoid discrepancies with which memory gets initialized that can be
caused by future changes, both KASAN hook and initialization memset()
are put together and a warning comment is added.

Combining setting allocation tags with memory initialization improves
HW_TAGS KASAN performance when init_on_free is enabled.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 10 ++++++----
 mm/kasan/common.c     | 13 +++++++------
 mm/slab.c             | 15 +++++++++++----
 mm/slub.c             | 43 ++++++++++++++++++++++++-------------------
 4 files changed, 48 insertions(+), 33 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 85f2a8786606..ed08c419a687 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -203,11 +203,13 @@ static __always_inline void * __must_check kasan_init_slab_obj(
 	return (void *)object;
 }
 
-bool __kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
-static __always_inline bool kasan_slab_free(struct kmem_cache *s, void *object)
+bool __kasan_slab_free(struct kmem_cache *s, void *object,
+			unsigned long ip, bool init);
+static __always_inline bool kasan_slab_free(struct kmem_cache *s,
+						void *object, bool init)
 {
 	if (kasan_enabled())
-		return __kasan_slab_free(s, object, _RET_IP_);
+		return __kasan_slab_free(s, object, _RET_IP_, init);
 	return false;
 }
 
@@ -313,7 +315,7 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
 {
 	return (void *)object;
 }
-static inline bool kasan_slab_free(struct kmem_cache *s, void *object)
+static inline bool kasan_slab_free(struct kmem_cache *s, void *object, bool init)
 {
 	return false;
 }
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 7ea747b18c26..623cf94288a2 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -322,8 +322,8 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 	return (void *)object;
 }
 
-static inline bool ____kasan_slab_free(struct kmem_cache *cache,
-				void *object, unsigned long ip, bool quarantine)
+static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
+				unsigned long ip, bool quarantine, bool init)
 {
 	u8 tag;
 	void *tagged_object;
@@ -351,7 +351,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache,
 	}
 
 	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
-			KASAN_KMALLOC_FREE, false);
+			KASAN_KMALLOC_FREE, init);
 
 	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine))
 		return false;
@@ -362,9 +362,10 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache,
 	return kasan_quarantine_put(cache, object);
 }
 
-bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
+bool __kasan_slab_free(struct kmem_cache *cache, void *object,
+				unsigned long ip, bool init)
 {
-	return ____kasan_slab_free(cache, object, ip, true);
+	return ____kasan_slab_free(cache, object, ip, true, init);
 }
 
 static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
@@ -409,7 +410,7 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 			return;
 		kasan_poison(ptr, page_size(page), KASAN_FREE_PAGE, false);
 	} else {
-		____kasan_slab_free(page->slab_cache, ptr, ip, false);
+		____kasan_slab_free(page->slab_cache, ptr, ip, false, false);
 	}
 }
 
diff --git a/mm/slab.c b/mm/slab.c
index 936dd686dec9..3adfe5bc3e2e 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3425,17 +3425,24 @@ static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
 static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
 					 unsigned long caller)
 {
+	bool init;
+
 	if (is_kfence_address(objp)) {
 		kmemleak_free_recursive(objp, cachep->flags);
 		__kfence_free(objp);
 		return;
 	}
 
-	if (unlikely(slab_want_init_on_free(cachep)))
+	/*
+	 * As memory initialization might be integrated into KASAN,
+	 * kasan_slab_free and initialization memset must be
+	 * kept together to avoid discrepancies in behavior.
+	 */
+	init = slab_want_init_on_free(cachep);
+	if (init && !kasan_has_integrated_init())
 		memset(objp, 0, cachep->object_size);
-
-	/* Put the object into the quarantine, don't touch it for now. */
-	if (kasan_slab_free(cachep, objp))
+	/* KASAN might put objp into memory quarantine, delaying its reuse. */
+	if (kasan_slab_free(cachep, objp, init))
 		return;
 
 	/* Use KCSAN to help debug racy use-after-free. */
diff --git a/mm/slub.c b/mm/slub.c
index f53df23760e3..37afe6251bcc 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1532,7 +1532,8 @@ static __always_inline void kfree_hook(void *x)
 	kasan_kfree_large(x);
 }
 
-static __always_inline bool slab_free_hook(struct kmem_cache *s, void *x)
+static __always_inline bool slab_free_hook(struct kmem_cache *s,
+						void *x, bool init)
 {
 	kmemleak_free_recursive(x, s->flags);
 
@@ -1558,8 +1559,25 @@ static __always_inline bool slab_free_hook(struct kmem_cache *s, void *x)
 		__kcsan_check_access(x, s->object_size,
 				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
 
-	/* KASAN might put x into memory quarantine, delaying its reuse */
-	return kasan_slab_free(s, x);
+	/*
+	 * As memory initialization might be integrated into KASAN,
+	 * kasan_slab_free and initialization memset's must be
+	 * kept together to avoid discrepancies in behavior.
+	 *
+	 * The initialization memset's clear the object and the metadata,
+	 * but don't touch the SLAB redzone.
+	 */
+	if (init) {
+		int rsize;
+
+		if (!kasan_has_integrated_init())
+			memset(kasan_reset_tag(x), 0, s->object_size);
+		rsize = (s->flags & SLAB_RED_ZONE) ? s->red_left_pad : 0;
+		memset((char *)kasan_reset_tag(x) + s->inuse, 0,
+		       s->size - s->inuse - rsize);
+	}
+	/* KASAN might put x into memory quarantine, delaying its reuse. */
+	return kasan_slab_free(s, x, init);
 }
 
 static inline bool slab_free_freelist_hook(struct kmem_cache *s,
@@ -1569,10 +1587,9 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
 	void *object;
 	void *next = *head;
 	void *old_tail = *tail ? *tail : *head;
-	int rsize;
 
 	if (is_kfence_address(next)) {
-		slab_free_hook(s, next);
+		slab_free_hook(s, next, false);
 		return true;
 	}
 
@@ -1584,20 +1601,8 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
 		object = next;
 		next = get_freepointer(s, object);
 
-		if (slab_want_init_on_free(s)) {
-			/*
-			 * Clear the object and the metadata, but don't touch
-			 * the redzone.
-			 */
-			memset(kasan_reset_tag(object), 0, s->object_size);
-			rsize = (s->flags & SLAB_RED_ZONE) ? s->red_left_pad
-							   : 0;
-			memset((char *)kasan_reset_tag(object) + s->inuse, 0,
-			       s->size - s->inuse - rsize);
-
-		}
 		/* If object's reuse doesn't have to be delayed */
-		if (!slab_free_hook(s, object)) {
+		if (!slab_free_hook(s, object, slab_want_init_on_free(s))) {
 			/* Move object to the new freelist */
 			set_freepointer(s, object, *head);
 			*head = object;
@@ -3235,7 +3240,7 @@ int build_detached_freelist(struct kmem_cache *s, size_t size,
 	}
 
 	if (is_kfence_address(object)) {
-		slab_free_hook(df->s, object);
+		slab_free_hook(df->s, object, false);
 		__kfence_free(object);
 		p[size] = NULL; /* mark object processed */
 		return size;
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/190fd15c1886654afdec0d19ebebd5ade665b601.1615296150.git.andreyknvl%40google.com.
