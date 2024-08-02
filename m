Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBUEEWW2QMGQEYIEPCHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 30A3094646A
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Aug 2024 22:32:18 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-36835daf8b7sf5204604f8f.2
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Aug 2024 13:32:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722630738; cv=pass;
        d=google.com; s=arc-20160816;
        b=qJnOxRWwCH+o0eLeUbSttLHTfEq7CQkxyqgb9BIRLvZW1t8wGrsuLTkQNyuOMzqo23
         yuZyZwRt/8cHfcZXZeVWbj12JE8AwAV1IYVvw4rR1pLdRZSEgoZOGLULNWyxtnI+kI8f
         g2Yk+FzxiHrHTiJRsFaPasCW6Ah2BBNffxzctYAi2gc4GMjpkvNLJ2n50oZFTH6SxQK1
         tgfgCo1U5nuATxdon9ccxzzRqWMRCLRcasCJtQid8NOzuj5wS+hwHLRpovSRzjeyg2BN
         iwGbzea2tYS2YLRRsXGWPAPwv/KqJVSQ5am45DDw9M/aWMRfwlpi88DmGvAmuDvISJuR
         WGBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=56GpRGWva7esbWofOzqXU9MzYnVNxHE65C54H/sXGhg=;
        fh=ho0ZMpLRBonpHsa5onBCJHWvDVPhqw9noFcBKGVvGys=;
        b=P7HpiT4qhto05h+b61GcZAoylDB3ihpIVxEkaavf7CxvNXDMXw87O1qSVHENmhys4D
         XMVmXQI+lmGUn7BwLUMC5Qldnqtr4Ie02y9voKPjgHFrHMCv9+EpBlZfiHqKRFBaQ9px
         gz0dbPwfJ+Bo9xLkTVZbq8hdMJsM6VYltFrYT7+vdWgJKiqQ/T+6/geWEV4Izv6J1HFt
         jpIVTgGyuH0uq0ncXyzopT7GoGTMpaNHRWPH5ux7sxPmV81i7xXXGIohs5Pe4SAexB+k
         Pc1dcjOk/OPf0G3wPJSzwjh2Iw1hUOXJcGmNSFvNThOpfSUZUyMia0Gr6jTYr1vRWM5w
         ytVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XDLQwCG7;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722630738; x=1723235538; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=56GpRGWva7esbWofOzqXU9MzYnVNxHE65C54H/sXGhg=;
        b=QBvHL/3vHHn5coUH+2U8+tpc9fFG3HZl2iIr2a3qtC2VjrWLFyE0YhOakG1BQyVtak
         dPlr2cL1HLTIbg9Rm6JifxxxQflxbxvEhvCZq62w0B0gbS4+3urMq6jzo5pugy3GFRFH
         ll0MvKebg6AXBsrv1FOunqSIeB6tWCyrlvOKapi3jTOtinZqx02+bnFm+DFs/7F8E2nc
         LSQjkXyvknJjziumDIC45I33E/2aeaL1NKs/d+Xsts0JaLIZroCSRSeKddM1Cdw9NzC/
         DUu9emBagMXtDWCm+tUsI/a3Ew2/AvCD4rqus5o5gQxti/3UkY33wlIyRpJaDTeOdMEQ
         we8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722630738; x=1723235538;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=56GpRGWva7esbWofOzqXU9MzYnVNxHE65C54H/sXGhg=;
        b=RAwTDd+w0yEOVHwfo/Rna1r4a/+yIROHVitiQLmlLc4bvN9iwr5hu3yzFW7zG5nlcE
         qWz24Sn0n2rwm1MLrBcUkvNs2q990b0LcH2eGcAu/YM5hZIOXXPJ7a8IIb8UPuU310Ii
         a9ZzvkfNCghKK/BznVs5L6BbZEoaIj+ZNnhBziucvkO9uqsZm8ft5i48AOAZgp//ngy1
         4whH/IzCo9kT2SW834tStp8IJsHa93gUlyrM3/Lp+WkBWfcFuE1sHzwvE54B0wo+agqi
         HGPZtDbe6PLjGIQMiFUzwogPyBxtJrTacMvfdmIEGfu6NLrNrdWys/xQvlqhdVLfH5Ru
         ydaw==
X-Forwarded-Encrypted: i=2; AJvYcCWSJgKf4tvgSwm0iwp3aeU7PoCD0aqXM0QAgCjf5c3Wyv72GStiDnU4KQ6x3isVayBO7vyuDEH8sexQyUA9NrGV5kURmLNkgg==
X-Gm-Message-State: AOJu0Yw/t4WSji3tGND0i6hsUM1+k6z8oLK+aJ/EmS/WkXAEwHECAY7+
	xcH49b+oW3NPfPwQq0Cz12Cgju6buISxf3oIpoYfqwM3LoKBFM8V
X-Google-Smtp-Source: AGHT+IEbGuhj9KHD3ZG78dcfQzsDOPa4lc0ljNhmUC19nCCqJriXTJcvuBoFfeUFkuZ1W1BKa56R6w==
X-Received: by 2002:adf:f585:0:b0:368:3782:c2b3 with SMTP id ffacd0b85a97d-36bbc117a9cmr3878285f8f.29.1722630737078;
        Fri, 02 Aug 2024 13:32:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f0cb:0:b0:368:31b2:9e96 with SMTP id ffacd0b85a97d-36bcc184abbls125241f8f.1.-pod-prod-05-eu;
 Fri, 02 Aug 2024 13:32:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVwP0Q1WUxSdfaDL8VmreVd/ybNtbBmGnNqWzVKPOVZcP/zvUwU4BuxlPIua5S1e7q5iJeeqDRsdCpWJoNYl1ddT/MSZN2/GvJRRg==
X-Received: by 2002:a05:600c:358a:b0:425:81bd:e5ee with SMTP id 5b1f17b1804b1-428e6b07b18mr35597115e9.16.1722630734898;
        Fri, 02 Aug 2024 13:32:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722630734; cv=none;
        d=google.com; s=arc-20160816;
        b=zEiOxDsaVgwTP4AqU7GPiAByKMwNk+4haMSpyc+8XUv4zE01YMRwaUUHJ5Hb7vMCfn
         blEanKPhQhJs+k/qUzlNnDp1qsMV0ugkpV6SvGEv+uCnHOY1Sv7FWjD//fxOpS3/UarU
         PhhQQAyCz1Ovy6MXBQX/HkVpQR2eoBWrXPHK0p2+0L1FU+GyJyM4g29bZMRKldkCnTfn
         pF1GIo5x4GKZ+CYhOUaFjwxO8ZJkWtIu/mfMlfzFN/cmegV+8ejRmpIs3h76LDFvl9j3
         IXc6GVPAO8BIdLU87QacL5JU+vkZ+0nBPrOfvntVo44otIMWGrxLyFfopDInXkAOCuug
         KJJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=OtIY/lbfQ818ndlf2SV0BX8ni+uEKDx/O9Hr9lNf93M=;
        fh=skMN/skoIRYYMPh4gUl9EorBqsoo9+SkH58PDSOyTnc=;
        b=KSulIPIUYd0Rr9HLzeMPAU/RY88j7xJxJFwX5UFuvXyBVVyIC7uUq31KMorOXZpw0d
         mnpnh0gqQo2vtHHH/+xyhUZKt38l/yywdz/dAyojkMFoguCZ4IPb/92N3ZFGuEOgyRdH
         ApeK8nXvT4NXHkLtESiASV4cQ+47kRaNb2CLlw0JNLJSA+BbqnaWFn1qlGiT1qvCKPoa
         kpB3aZU7TwupUUojvxjOUNgHy5vm23SFF0xYdvXOsV8WjSJRH5FCC2L37ovqXqlxoC+Y
         tgfgKfEqUonl5rEgXmzVNzxQpBchkBlyMkEPrCGJHS9my10SpcpjLSupF1oZq0F7J6dx
         OG3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XDLQwCG7;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42824af684dsi7144505e9.1.2024.08.02.13.32.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Aug 2024 13:32:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-427fc9834deso259015e9.0
        for <kasan-dev@googlegroups.com>; Fri, 02 Aug 2024 13:32:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVK1s5ifDyCIPLPi/eMjNZ6lRjubXI8XcWRoHHokKP4ECmzQfLnj/Ak6xaqGmbOeDF4vb/xfjJugFrAdwNZ6b3LLDaY0uWO83OFNg==
X-Received: by 2002:a05:600c:a08c:b0:428:e6eb:1340 with SMTP id 5b1f17b1804b1-428ef3cbbdfmr44035e9.4.1722630733443;
        Fri, 02 Aug 2024 13:32:13 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:9337:bd1:a20d:682d])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-428e6e9d1b4sm43954895e9.39.2024.08.02.13.32.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 Aug 2024 13:32:12 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 02 Aug 2024 22:31:53 +0200
Subject: [PATCH v6 1/2] kasan: catch invalid free before SLUB reinitializes
 the object
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240802-kasan-tsbrcu-v6-1-60d86ea78416@google.com>
References: <20240802-kasan-tsbrcu-v6-0-60d86ea78416@google.com>
In-Reply-To: <20240802-kasan-tsbrcu-v6-0-60d86ea78416@google.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
 linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
 Jann Horn <jannh@google.com>
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=ed25519-sha256; t=1722630727; l=8985;
 i=jannh@google.com; s=20240730; h=from:subject:message-id;
 bh=n3HTPxz1vqklcUBCM2b1ohNM905PLTWckUn1zsgT95o=;
 b=pBuk9xoZ3On9sdWadP+S/JMQOgnWggeyhLUucDdlYyDK+oaS4P6P0S2gqDMVcBntQIES2k5g0
 G7Dzmk5va7PAV+bbKgU4Ounb6xSvRgiyFg+cTwdckFsSVg/xFZitzGz
X-Developer-Key: i=jannh@google.com; a=ed25519;
 pk=AljNtGOzXeF6khBXDJVVvwSEkVDGnnZZYqfWhP1V+C8=
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=XDLQwCG7;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::330 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

Currently, when KASAN is combined with init-on-free behavior, the
initialization happens before KASAN's "invalid free" checks.

More importantly, a subsequent commit will want to RCU-delay the actual
SLUB freeing of an object, and we'd like KASAN to still validate
synchronously that freeing the object is permitted. (Otherwise this
change will make the existing testcase kmem_cache_invalid_free fail.)

So add a new KASAN hook that allows KASAN to pre-validate a
kmem_cache_free() operation before SLUB actually starts modifying the
object or its metadata.

Inside KASAN, this:

 - moves checks from poison_slab_object() into check_slab_allocation()
 - moves kasan_arch_is_ready() up into callers of poison_slab_object()
 - removes "ip" argument of poison_slab_object() and __kasan_slab_free()
   (since those functions no longer do any reporting)

Acked-by: Vlastimil Babka <vbabka@suse.cz> #slub
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Jann Horn <jannh@google.com>
---
 include/linux/kasan.h | 54 ++++++++++++++++++++++++++++++++++++++++++---
 mm/kasan/common.c     | 61 ++++++++++++++++++++++++++++++---------------------
 mm/slub.c             |  7 ++++++
 3 files changed, 94 insertions(+), 28 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 70d6a8f6e25d..1570c7191176 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -172,19 +172,61 @@ static __always_inline void * __must_check kasan_init_slab_obj(
 {
 	if (kasan_enabled())
 		return __kasan_init_slab_obj(cache, object);
 	return (void *)object;
 }
 
-bool __kasan_slab_free(struct kmem_cache *s, void *object,
-			unsigned long ip, bool init);
+bool __kasan_slab_pre_free(struct kmem_cache *s, void *object,
+			unsigned long ip);
+/**
+ * kasan_slab_pre_free - Check whether freeing a slab object is safe.
+ * @object: Object to be freed.
+ *
+ * This function checks whether freeing the given object is safe. It may
+ * check for double-free and invalid-free bugs and report them.
+ *
+ * This function is intended only for use by the slab allocator.
+ *
+ * @Return true if freeing the object is unsafe; false otherwise.
+ */
+static __always_inline bool kasan_slab_pre_free(struct kmem_cache *s,
+						void *object)
+{
+	if (kasan_enabled())
+		return __kasan_slab_pre_free(s, object, _RET_IP_);
+	return false;
+}
+
+bool __kasan_slab_free(struct kmem_cache *s, void *object, bool init);
+/**
+ * kasan_slab_free - Poison, initialize, and quarantine a slab object.
+ * @object: Object to be freed.
+ * @init: Whether to initialize the object.
+ *
+ * This function informs that a slab object has been freed and is not
+ * supposed to be accessed anymore, except for objects in
+ * SLAB_TYPESAFE_BY_RCU caches.
+ *
+ * For KASAN modes that have integrated memory initialization
+ * (kasan_has_integrated_init() == true), this function also initializes
+ * the object's memory. For other modes, the @init argument is ignored.
+ *
+ * This function might also take ownership of the object to quarantine it.
+ * When this happens, KASAN will defer freeing the object to a later
+ * stage and handle it internally until then. The return value indicates
+ * whether KASAN took ownership of the object.
+ *
+ * This function is intended only for use by the slab allocator.
+ *
+ * @Return true if KASAN took ownership of the object; false otherwise.
+ */
 static __always_inline bool kasan_slab_free(struct kmem_cache *s,
 						void *object, bool init)
 {
 	if (kasan_enabled())
-		return __kasan_slab_free(s, object, _RET_IP_, init);
+		return __kasan_slab_free(s, object, init);
 	return false;
 }
 
 void __kasan_kfree_large(void *ptr, unsigned long ip);
 static __always_inline void kasan_kfree_large(void *ptr)
 {
@@ -368,12 +410,18 @@ static inline void kasan_poison_new_object(struct kmem_cache *cache,
 					void *object) {}
 static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
 				const void *object)
 {
 	return (void *)object;
 }
+
+static inline bool kasan_slab_pre_free(struct kmem_cache *s, void *object)
+{
+	return false;
+}
+
 static inline bool kasan_slab_free(struct kmem_cache *s, void *object, bool init)
 {
 	return false;
 }
 static inline void kasan_kfree_large(void *ptr) {}
 static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 85e7c6b4575c..f26bbc087b3b 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -205,59 +205,65 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
 	object = set_tag(object, assign_tag(cache, object, true));
 
 	return (void *)object;
 }
 
-static inline bool poison_slab_object(struct kmem_cache *cache, void *object,
-				      unsigned long ip, bool init)
+/* Returns true when freeing the object is not safe. */
+static bool check_slab_allocation(struct kmem_cache *cache, void *object,
+				  unsigned long ip)
 {
-	void *tagged_object;
-
-	if (!kasan_arch_is_ready())
-		return false;
+	void *tagged_object = object;
 
-	tagged_object = object;
 	object = kasan_reset_tag(object);
 
 	if (unlikely(nearest_obj(cache, virt_to_slab(object), object) != object)) {
 		kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT_INVALID_FREE);
 		return true;
 	}
 
-	/* RCU slabs could be legally used after free within the RCU period. */
-	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
-		return false;
-
 	if (!kasan_byte_accessible(tagged_object)) {
 		kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT_DOUBLE_FREE);
 		return true;
 	}
 
+	return false;
+}
+
+static inline void poison_slab_object(struct kmem_cache *cache, void *object,
+				      bool init)
+{
+	void *tagged_object = object;
+
+	object = kasan_reset_tag(object);
+
+	/* RCU slabs could be legally used after free within the RCU period. */
+	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
+		return;
+
 	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
 			KASAN_SLAB_FREE, init);
 
 	if (kasan_stack_collection_enabled())
 		kasan_save_free_info(cache, tagged_object);
+}
 
-	return false;
+bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
+				unsigned long ip)
+{
+	if (!kasan_arch_is_ready() || is_kfence_address(object))
+		return false;
+	return check_slab_allocation(cache, object, ip);
 }
 
-bool __kasan_slab_free(struct kmem_cache *cache, void *object,
-				unsigned long ip, bool init)
+bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init)
 {
-	if (is_kfence_address(object))
+	if (!kasan_arch_is_ready() || is_kfence_address(object))
 		return false;
 
-	/*
-	 * If the object is buggy, do not let slab put the object onto the
-	 * freelist. The object will thus never be allocated again and its
-	 * metadata will never get released.
-	 */
-	if (poison_slab_object(cache, object, ip, init))
-		return true;
+	poison_slab_object(cache, object, init);
 
 	/*
 	 * If the object is put into quarantine, do not let slab put the object
 	 * onto the freelist for now. The object's metadata is kept until the
 	 * object gets evicted from quarantine.
 	 */
@@ -501,17 +507,22 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 		if (check_page_allocation(ptr, ip))
 			return false;
 		kasan_poison(ptr, folio_size(folio), KASAN_PAGE_FREE, false);
 		return true;
 	}
 
-	if (is_kfence_address(ptr))
-		return false;
+	if (is_kfence_address(ptr) || !kasan_arch_is_ready())
+		return true;
 
 	slab = folio_slab(folio);
-	return !poison_slab_object(slab->slab_cache, ptr, ip, false);
+
+	if (check_slab_allocation(slab->slab_cache, ptr, ip))
+		return false;
+
+	poison_slab_object(slab->slab_cache, ptr, false);
+	return true;
 }
 
 void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip)
 {
 	struct slab *slab;
 	gfp_t flags = 0; /* Might be executing under a lock. */
diff --git a/mm/slub.c b/mm/slub.c
index 3520acaf9afa..0c98b6a2124f 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2223,12 +2223,19 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
 		__kcsan_check_access(x, s->object_size,
 				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
 
 	if (kfence_free(x))
 		return false;
 
+	/*
+	 * Give KASAN a chance to notice an invalid free operation before we
+	 * modify the object.
+	 */
+	if (kasan_slab_pre_free(s, x))
+		return false;
+
 	/*
 	 * As memory initialization might be integrated into KASAN,
 	 * kasan_slab_free and initialization memset's must be
 	 * kept together to avoid discrepancies in behavior.
 	 *
 	 * The initialization memset's clear the object and the metadata,

-- 
2.46.0.rc2.264.g509ed76dc8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240802-kasan-tsbrcu-v6-1-60d86ea78416%40google.com.
