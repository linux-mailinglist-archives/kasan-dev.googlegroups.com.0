Return-Path: <kasan-dev+bncBAABBLVVSKWAMGQEHL4A4NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 7060881BF5B
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:06:07 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-50e6459533bsf423597e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:06:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703189167; cv=pass;
        d=google.com; s=arc-20160816;
        b=rLorAasVIA+kQCzeKgKk6fglg1uQppmOebyK38wi+0x9m1ilwZA+1mQJo5aVWW+j5b
         kzrgsHpqGlBsdJaiKdey8whc4uKlPpd8VE/qTbsSS1twTahpBKcuI+OM2fVi4VtnTzqS
         HHI1OoeaSzsyAYrlKTmo9XZOcuBIrxkyoKSGFmcUEUgoUmHg1E0ucu/CLOH2K8xm+Wit
         NWHceAoCfKguZWO1U807V6m4MxA2atCfly2FEqW/GFeW9jOi9s+Y1cZookyemxX7475f
         gXBgFyyyRk/L3MLhsHikfuwOm8fIIuto99XdwpxSI1jiqEd1B5ciHleFkcFOhnvk1RB5
         tnjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=fGzvXan+Ua0OKUsQc+3s8P6KddDK90KyVHGl4DjUtUE=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=CxUfhRTxEIeM2xYHc3FlSZKL3OSN+Fbs3QsfJaXvEvx3f9dXYTUbqGjAlGWsGkIBC1
         aqh5qKuzfh9HLw9fAkdDMUFNt6lSukG6CYKtLN7AVaOa2n1kYevMuwykRUZeHVjlXvO4
         jAyyGgbrDL+9U2yPGsTqJNvdv3PVnWfW+7UlEB4CeKYGGKkiva1OGM1oFAjMvI741eW5
         TjohAfLmnseMmvCDGHbQy7XHMw6ELZvQBRvcs77r5D3RtgKd2ABeB1PzB8KROKbobojS
         VFgbASZ5jiCOK46acacNxSPONVSsVmfCP8ZlikcOwHQqFoSWGmeAI3Eds2PLVIVuRnx7
         0+TA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=b9Brp+Gw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b6 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703189167; x=1703793967; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fGzvXan+Ua0OKUsQc+3s8P6KddDK90KyVHGl4DjUtUE=;
        b=raknXBntaQDPSOnX8MmDJCGGDvid9GvLHM7hb0sRySSgUnNvNHUdA/5KC1t55jB4gF
         j4qjrKTBPcXysUJ28pSS5j9Aa/5f2naR78nLjCuJEs4v1SzW4NTdbYuJOUQTTLSuRanZ
         adRgKnWBWl0+ucjmygIL9xZcwKMZ+mVjXFUUnz+o28k2YpKN4xGcZyHzLgGAj9AMuJUD
         k3w0f8tISMJM7vbqfN1cNm92REDN9IFZTqgXjwbTaq+mlo5UCschMyDojJbiyvVqbQkw
         TXxbzvAC5SpDFOVo2c9vatNvI0Xv7Fjj/II3/dGcx++9jQQ3Pk4uXOOa+fYOkNdKAjf8
         q0Ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703189167; x=1703793967;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fGzvXan+Ua0OKUsQc+3s8P6KddDK90KyVHGl4DjUtUE=;
        b=SNVvdswd/STFTvxIb2+3Vb91BOLnIMX72wPGW0CKCAjCxGBvb5j6/Wl2/4tFqnVWOJ
         x2VPsc70Anv6eWqh9hd2q4vDSjH991noIZ4oh7V6FHhAPIUX/w1jksiFV7S4YroAVvMf
         iy4d+bUJuzWLcen6kp42OLpdTOlaaqafKp/xCEfEaoSr7pyzLg675vcaVMj4SGREi9N7
         QCdzsZC7+TZsHioDYXRg9nJ3TieC6KAhINJROet7A0QU0fBzyKi7YNBdleyXUsJo8nhx
         JoCVy1s8BlU432MG16VBhHhJH0VmErPi/vaLTlv5oXgCwq1PIPB32cQISPbR3vYFmPEf
         Z1nw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwSYYIhRuMbwn5vmzRzF4/Sugg7TTfxZSerKc/oyQCyFnQBURWW
	wYD/IkeQlQg44Bp2uhSYErI=
X-Google-Smtp-Source: AGHT+IH6ybDqtoJqjGiSZkT35LIQ/zmhzwH8iIAR8gNFwPyoPD9IVzyZFjmwZYB8XoXT0eGS71GO4Q==
X-Received: by 2002:ac2:58c8:0:b0:50e:4e6c:e3c8 with SMTP id u8-20020ac258c8000000b0050e4e6ce3c8mr82353lfo.91.1703189166526;
        Thu, 21 Dec 2023 12:06:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e24:b0:50a:aa99:28a8 with SMTP id
 i36-20020a0565123e2400b0050aaa9928a8ls343983lfv.0.-pod-prod-01-eu; Thu, 21
 Dec 2023 12:06:05 -0800 (PST)
X-Received: by 2002:a05:6512:3f26:b0:50e:1f22:3110 with SMTP id y38-20020a0565123f2600b0050e1f223110mr89884lfa.65.1703189164983;
        Thu, 21 Dec 2023 12:06:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703189164; cv=none;
        d=google.com; s=arc-20160816;
        b=x4AwAYVs+OVC9CNbX5JM+Siq9+tKQyigMlRrrww9gDCaJ9Uh0YYWGB3H2fo9Qp4rNF
         YUefm8J+LIlj5T9BLKETvMGWrKHre5IQ7/lWieY2jfs6FI4I20sV5Q/AVyXKQPtth4uH
         Ul+czDwPiE4eRE/8Toalsx60KBa0BRMEjU+VQlaXNonAbqhzG0DQYSgEl9OBKPfZdJaP
         l8wUx0r/Kv6WApBc/GlRgfiRAffb0IOEno4NWQX1wSTnppqwJu1Wib3SOLlv7Vrb8rOq
         TE3jmOel6OXO/IEHehbZ6byJx+xmgJR0YoXmXb08jwIYbu/XaANMqb3SHRgBIKxvRX3k
         iwdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gSZaD965ObbhfRb2wl16gx9k0NFu/9CcW8O4J7mEceM=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=l6pG7i3+R3zKdZVn1wfbtCl4xAemfkpEAkY1WSKMllHDyNCGmq2FnjXQ8Y6HXYcFKi
         A2jm/cQMylOnHsUFZMY0cLjiKL3Vs86dksJDTss5DvpuUE21jMOQHTMuqOnHP/Y/kG90
         yP22dhxzoHIeF24sFHg6QUZOq3L9L6/I6a8dwlWUI57SzufR5Xa+rn9k2fzDFGWINcY1
         pPu/N2yOEaeosMudsQX0hnS+05xfE3uWu8IxwUKjpmk4fVUdP92CFFdlkzJc/yUbADCI
         v0EU97jhcpm11JvszGv6Zz+Es9tccTpzbt6LgFL3jSpx7jNInauafVCk0cvwsSGk7Q0Y
         x4KA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=b9Brp+Gw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b6 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-182.mta0.migadu.com (out-182.mta0.migadu.com. [2001:41d0:1004:224b::b6])
        by gmr-mx.google.com with ESMTPS id z36-20020a509e27000000b0055410f019ccsi171101ede.2.2023.12.21.12.06.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 12:06:04 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b6 as permitted sender) client-ip=2001:41d0:1004:224b::b6;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 06/11] kasan: clean up is_kfence_address checks
Date: Thu, 21 Dec 2023 21:04:48 +0100
Message-Id: <1065732315ef4e141b6177d8f612232d4d5bc0ab.1703188911.git.andreyknvl@google.com>
In-Reply-To: <cover.1703188911.git.andreyknvl@google.com>
References: <cover.1703188911.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=b9Brp+Gw;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::b6 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

1. Do not untag addresses that are passed to is_kfence_address: it
   tolerates tagged addresses.

2. Move is_kfence_address checks from internal KASAN functions
   (kasan_poison/unpoison, etc.) to external-facing ones.

   Note that kasan_poison/unpoison are never called outside of KASAN/slab
   code anymore; the comment is wrong, so drop it.

3. Simplify/reorganize the code around the updated checks.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 26 +++++++++++++++++---------
 mm/kasan/kasan.h  | 16 ++--------------
 mm/kasan/shadow.c | 12 ------------
 3 files changed, 19 insertions(+), 35 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index f4255e807b74..86adf80cc11a 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -79,6 +79,9 @@ EXPORT_SYMBOL(kasan_disable_current);
 
 void __kasan_unpoison_range(const void *address, size_t size)
 {
+	if (is_kfence_address(address))
+		return;
+
 	kasan_unpoison(address, size, false);
 }
 
@@ -218,9 +221,6 @@ static inline bool poison_slab_object(struct kmem_cache *cache, void *object,
 	tagged_object = object;
 	object = kasan_reset_tag(object);
 
-	if (is_kfence_address(object))
-		return false;
-
 	if (unlikely(nearest_obj(cache, virt_to_slab(object), object) != object)) {
 		kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT_INVALID_FREE);
 		return true;
@@ -247,7 +247,12 @@ static inline bool poison_slab_object(struct kmem_cache *cache, void *object,
 bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 				unsigned long ip, bool init)
 {
-	bool buggy_object = poison_slab_object(cache, object, ip, init);
+	bool buggy_object;
+
+	if (is_kfence_address(object))
+		return false;
+
+	buggy_object = poison_slab_object(cache, object, ip, init);
 
 	return buggy_object ? true : kasan_quarantine_put(cache, object);
 }
@@ -359,7 +364,7 @@ void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object
 	if (unlikely(object == NULL))
 		return NULL;
 
-	if (is_kfence_address(kasan_reset_tag(object)))
+	if (is_kfence_address(object))
 		return (void *)object;
 
 	/* The object has already been unpoisoned by kasan_slab_alloc(). */
@@ -417,7 +422,7 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 	if (unlikely(object == ZERO_SIZE_PTR))
 		return (void *)object;
 
-	if (is_kfence_address(kasan_reset_tag(object)))
+	if (is_kfence_address(object))
 		return (void *)object;
 
 	/*
@@ -483,6 +488,9 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 		return true;
 	}
 
+	if (is_kfence_address(ptr))
+		return false;
+
 	slab = folio_slab(folio);
 	return !poison_slab_object(slab->slab_cache, ptr, ip, false);
 }
@@ -492,9 +500,6 @@ void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip)
 	struct slab *slab;
 	gfp_t flags = 0; /* Might be executing under a lock. */
 
-	if (is_kfence_address(kasan_reset_tag(ptr)))
-		return;
-
 	slab = virt_to_slab(ptr);
 
 	/*
@@ -507,6 +512,9 @@ void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip)
 		return;
 	}
 
+	if (is_kfence_address(ptr))
+		return;
+
 	/* Unpoison the object and save alloc info for non-kmalloc() allocations. */
 	unpoison_slab_object(slab->slab_cache, ptr, size, flags);
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 1c34511090d7..5fbcc1b805bc 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -466,35 +466,23 @@ static inline u8 kasan_random_tag(void) { return 0; }
 
 static inline void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 {
-	addr = kasan_reset_tag(addr);
-
-	/* Skip KFENCE memory if called explicitly outside of sl*b. */
-	if (is_kfence_address(addr))
-		return;
-
 	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
 		return;
 	if (WARN_ON(size & KASAN_GRANULE_MASK))
 		return;
 
-	hw_set_mem_tag_range((void *)addr, size, value, init);
+	hw_set_mem_tag_range(kasan_reset_tag(addr), size, value, init);
 }
 
 static inline void kasan_unpoison(const void *addr, size_t size, bool init)
 {
 	u8 tag = get_tag(addr);
 
-	addr = kasan_reset_tag(addr);
-
-	/* Skip KFENCE memory if called explicitly outside of sl*b. */
-	if (is_kfence_address(addr))
-		return;
-
 	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
 		return;
 	size = round_up(size, KASAN_GRANULE_SIZE);
 
-	hw_set_mem_tag_range((void *)addr, size, tag, init);
+	hw_set_mem_tag_range(kasan_reset_tag(addr), size, tag, init);
 }
 
 static inline bool kasan_byte_accessible(const void *addr)
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 0154d200be40..30625303d01a 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -135,10 +135,6 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 	 */
 	addr = kasan_reset_tag(addr);
 
-	/* Skip KFENCE memory if called explicitly outside of sl*b. */
-	if (is_kfence_address(addr))
-		return;
-
 	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
 		return;
 	if (WARN_ON(size & KASAN_GRANULE_MASK))
@@ -175,14 +171,6 @@ void kasan_unpoison(const void *addr, size_t size, bool init)
 	 */
 	addr = kasan_reset_tag(addr);
 
-	/*
-	 * Skip KFENCE memory if called explicitly outside of sl*b. Also note
-	 * that calls to ksize(), where size is not a multiple of machine-word
-	 * size, would otherwise poison the invalid portion of the word.
-	 */
-	if (is_kfence_address(addr))
-		return;
-
 	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
 		return;
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1065732315ef4e141b6177d8f612232d4d5bc0ab.1703188911.git.andreyknvl%40google.com.
