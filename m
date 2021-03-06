Return-Path: <kasan-dev+bncBDX4HWEMTEBRBS4TROBAMGQEUT42KGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F13D32F729
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Mar 2021 01:16:12 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id q20sf1458599lja.20
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 16:16:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614989771; cv=pass;
        d=google.com; s=arc-20160816;
        b=owac6UdVDTrJ8cF2QC/SOji/hzVY37AeDHHdH4cdbrzSr1NkYCLrWP4WOP/gUnyIFG
         s13m2NrvUwwhWjDrS/k9lSWaK+SNNIprRD4w3PvTc154+B4IlqAwYn8IXedk/bmGri16
         4OrX0VgKfKzFbCOlA6yNAoeohRaZixLH/PzE0I4yZXLoFoCQyNbAoHa4B3PazlcJVMaW
         4RMWOMNyX9B2tsRGkrTt6BYZow7P+l1tD9fBY0S+8T95yaRMVbnJpGNpJr6gylRSVyNk
         r3ToJQo8sQudmbqWHDjNmzstLXxsuUOfLxBieDLlBhUTps5JUF6RAT3tPgOGCYK5zcOm
         WmdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Q6E3aHDLfkuiB//POJZXodDyFgv4XDjJHAk7dPeRBtI=;
        b=gsJNULtVOrH5V3/qxFWIciaUY1GaT10+1AypGCCJCJzvXGyFstdtpDntRNkAMeX6G5
         ja5BTiYUkExzoqB8QR6hgTI86e5iTT4L9JVM7gsj8fQntWDFbox3cioAptCD2bQGkB++
         6CJJsEEKkasVnHDCJdrwCsLAAviVX04ouQ5UlvwpwQWFMlj6B4W7bsz638v73Ckahwlf
         WBH0M95BA5huJIL2uvk0icJhA5mdQdaHhevivTQKc1Gjb7GHUrodhN01UjTZfEjzA2k5
         /cOyB+NBIpo2hAjkj9eFwz3li63x3QPDW/42lT38r898peKGPnUdlQWwlBf0h6eXLkDm
         uupQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dojzLQIL;
       spf=pass (google.com: domain of 3yslcyaokcxepcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3yslCYAoKCXEPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Q6E3aHDLfkuiB//POJZXodDyFgv4XDjJHAk7dPeRBtI=;
        b=RseeN9ZCOEdt/qoOm9zsRm5dQgFs3vgCwV6x04bgvL498Lw1YxCwhu+nRNRaUKrShD
         m5Cv6D9sVFH9crVvNhJh6XW/H2gjJ3ccgk86mIfUonldP1m4IxJFwanOpzig6SVsk6/9
         T3STj92Yoo7QhiArkNeoRdrVl0wfEksS9yyd7wL70grSguHqqPQk77iHLQGD1YQmrCuU
         bXmUkzPng4NQihvaYK1iuo5yOAwhzEHOwdnhMob/n0lKDcgEpKYRjb9B8nPt0Mfb2X8S
         aKzc7Wlh73JMn8nexnwlDtKjGknU8+aLoe//Pm2b+kyEmWQzVGAiKzNpjGqhtd/Xh/4i
         AasA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q6E3aHDLfkuiB//POJZXodDyFgv4XDjJHAk7dPeRBtI=;
        b=hkjjdI2hk/LTAZP1Ucm0UWxZUI/07LclgonR3yOsDKG3RmfY0WjRcpUatb2Ddd7t5U
         9cQ7NxAutsOXNpe9GuYIXKFrrIHL5vrI3Z41uL97OKqalSQha5p0ttWh9h+minCBD6n9
         EUMOZ7iy+6naAdsYdo6p/s6y/u0k9rp96Ap5qTDus01gRF+7WUijg1Y7KaJ76po9gbi6
         9n+uWPDQ6W3QskUA7sK39wwsZTYpdLG5IXSfRMDSq+VlC0zBKbHW/klagVMfXNEGpHaY
         3+EBAjTC/9CWxqxub8vRlJolLTnyVoP8KPYY7ja2XUfySxWOxZWUEZ4Vcox+p4E60Y6n
         94pg==
X-Gm-Message-State: AOAM531I5XoMOMJ3L8lulMgaC8NULDge8BKu2KGYB8K/IW+sFNAxkec7
	pOM2MWIr52XvQu2xIstqsBM=
X-Google-Smtp-Source: ABdhPJxwOI5+LYMOdzfkfedWaE4RjUhJP+a18Xinixe6FqDV3B+fLW+hridskroZwRnUJzHZVbJFUg==
X-Received: by 2002:a2e:9d14:: with SMTP id t20mr6714477lji.391.1614989771846;
        Fri, 05 Mar 2021 16:16:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls1049281lfu.3.gmail; Fri,
 05 Mar 2021 16:16:10 -0800 (PST)
X-Received: by 2002:a05:6512:6d0:: with SMTP id u16mr6849039lff.300.1614989770838;
        Fri, 05 Mar 2021 16:16:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614989770; cv=none;
        d=google.com; s=arc-20160816;
        b=S240ft1FyBB6jGXatOmK1Wy0A6/HMeQ3/A9c/oLo+JuYXt+bWO/2iYpEVeEz2dz0xI
         GkWVOWizOdv5dR6nMUn9HH4jbyupCymC2cHHkkuLQqXji4oxL84UnR0TrXtcPF5cvy5W
         XuB8zhHOz+vGVSye9vVCMdPj6Vc8y7nC2oQbxC1fUvSpFSjtngLL7Hz6VUJ2KQDezceX
         Sz5cbqfgU5cqG/c7CpqOK0xWcaH5WYQAc0IRJsXBkTDkoEftHg2b0n9OPHw8NZWk9xs6
         XeP4XLbhLi/pFqabPfOmHS7NRmx2K/OBrxPgxENenH39pidDqq22YHbaHm/B0i/uSHIa
         F4aA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=UrKz1IN65Ge5y9z4J0tlnwkje+fDVptcypjtSEQF9n0=;
        b=tJrt9nvkmiPZpdW8SnFbGP68dPrVKWe/L22IYXKwwX2eIOHecrjgHXSsN+vr1rqKMy
         3vxFEpkP3YBYRTd1Vpz1+h+VQnUWTEhRFB3CYKoTJLBoMtS8yTgZZ7LGySxJavfUNOic
         zeKIBXlMxU8GJ2g1vEldvHFQNQvK4rJEo9GwnZ19fZYyiO0+/7Npp9lOhCYNeLJ08JYF
         8A60cFmTV3oDI04sS+UAS6lG3NtkjuEPQ9cPpjKsJVUtzQkbOklQolSbBmNgNMs/w28r
         /MU4e3sHjaV8KCkpXzOJiXcxkNQYZMwehOf/UubB2Mn8H6dhIzDWKMMjIMysHMAZFXRd
         4q8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dojzLQIL;
       spf=pass (google.com: domain of 3yslcyaokcxepcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3yslCYAoKCXEPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id y3si165773lfb.6.2021.03.05.16.16.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 16:16:10 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yslcyaokcxepcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id v13so1771692wrs.21
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 16:16:10 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:953b:d7cf:2b01:f178])
 (user=andreyknvl job=sendgmr) by 2002:adf:f3cc:: with SMTP id
 g12mr12063558wrp.118.1614989770262; Fri, 05 Mar 2021 16:16:10 -0800 (PST)
Date: Sat,  6 Mar 2021 01:15:54 +0100
In-Reply-To: <cover.1614989433.git.andreyknvl@google.com>
Message-Id: <a313f27d68ad479eda7b36a114bb2ffd56d80bbb.1614989433.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1614989433.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH 5/5] kasan, mm: integrate slab init_on_free with HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dojzLQIL;       spf=pass
 (google.com: domain of 3yslcyaokcxepcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3yslCYAoKCXEPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
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

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 10 ++++++----
 mm/kasan/common.c     | 13 +++++++------
 mm/slab.c             | 15 +++++++++++----
 mm/slub.c             | 43 ++++++++++++++++++++++++-------------------
 4 files changed, 48 insertions(+), 33 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index bb756f6c73b5..1df0f7f0b493 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -193,11 +193,13 @@ static __always_inline void * __must_check kasan_init_slab_obj(
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
 
@@ -299,7 +301,7 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
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
index 936dd686dec9..d12ce9e5c3ed 100644
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
+	 * As memory initialization is integrated with hardware tag-based
+	 * KASAN, kasan_slab_free and initialization memset must be
+	 * kept together to avoid discrepancies in behavior.
+	 */
+	init = slab_want_init_on_free(cachep);
+	if (init && !IS_ENABLED(CONFIG_KASAN_HW_TAGS))
 		memset(objp, 0, cachep->object_size);
-
-	/* Put the object into the quarantine, don't touch it for now. */
-	if (kasan_slab_free(cachep, objp))
+	/* KASAN might put objp into memory quarantine, delaying its reuse. */
+	if (kasan_slab_free(cachep, objp, init))
 		return;
 
 	/* Use KCSAN to help debug racy use-after-free. */
diff --git a/mm/slub.c b/mm/slub.c
index f53df23760e3..c2755670d6bd 100644
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
+	 * As memory initialization is integrated with hardware tag-based
+	 * KASAN, kasan_slab_free and initialization memset's must be
+	 * kept together to avoid discrepancies in behavior.
+	 *
+	 * The initialization memset's clear the object and the metadata,
+	 * but don't touch the SLAB redzone.
+	 */
+	if (init) {
+		int rsize;
+
+		if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS))
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a313f27d68ad479eda7b36a114bb2ffd56d80bbb.1614989433.git.andreyknvl%40google.com.
