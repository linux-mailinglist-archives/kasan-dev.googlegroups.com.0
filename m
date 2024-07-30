Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBPESUO2QMGQEQD5HBCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 11684941034
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 13:06:38 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2f01a8b90b6sf52002011fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 04:06:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722337597; cv=pass;
        d=google.com; s=arc-20160816;
        b=IstnefKuEXv5Jg7N8JIhCK5yfkvyeM9enJpwORpJ7VMtOZzO787YaayXqfY7yH3TE0
         RzbTC5lqPgc8cl9srYic/4wWhV1j7ALJdppkmR+Y3Tzw0pqXLZK/2wMR+XCO86d1jQf/
         I6L7UlRNu5I/VdAy0jAT7JNTU1FtEWZxD8JbFSet9qJRyX89OjfU9jFykuH4TlHEnpCG
         vbkN0twWF1qiU+xQz1NvmpKmMxLOk0iAb0FX3NmE4iSN6zWemo4NNH70AqmuxVenjiRk
         U1XGs9J7GABjL0WG2eWzhmkmtAhjQ31tw48dCiIbwZsgLjBw3oG9HnyvF0gBfAW6CMCl
         8UbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=DUO5Oy8QM4X2myiTbngYsabALQRXD9NLLggVYkqX75g=;
        fh=btzdX5AvqLYHVKUvcdnt/OIqgHb0FiziNGlomyzWZck=;
        b=hayQUwfz2wbxQhqJmOdGDJxFNoPLECLy5wXPCDgoRWs6LmMUkkBWwqilcCIlAZL84B
         UmogjC2ivRr9ol6gIrUHvCTqX3cTByex5hWtObmi04kVPYHYFDjRU6ds9g2oylc3K1Se
         bLYeEkHeMv5cTt4NvWTIHI0ydeJQq1vOqjYQLDXqAU2dLSfpN7VdBcLCrDMNVMOeqge9
         612xhMlVdb80ehENwEi9bYYodrhD20j4VDjGH98BPECQhpheiwGBSxGCCrLLHkl7mk/X
         XGVHYqDSHJdwWw2FQhC8hCjkD6fwr9Kp2vqQF93m3pxU/uhi2m4HIuYFSM8ZB0uZ9/xg
         CCjg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AMTDQwYF;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722337597; x=1722942397; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DUO5Oy8QM4X2myiTbngYsabALQRXD9NLLggVYkqX75g=;
        b=pPxSTBaI3/MNiPnlX2rI8Gerbeig8qdbKJCMA4gVxHNGWt5R7uFlir78AokZYMwprs
         JpJoX6Pd93J/n/6yUSeM8hd/zMZg0Qq41YwBwlcDdpd8vMPgHQuf6DsYB/n6C8dpxS73
         TwPmV00h5Gt73zgDNXPiNc5hNsrU/ze8kzBJFj8rjF5d72d6DcYKyNemRnms/4gNM79S
         xegjewVVUvVJOz1q556Issife8gVdjMDUcZLbKwwCR/px50kDjW9ANKha5wv7T48Acs4
         udNFJZhGO8Xb2CdyG0c0io/oxN4PbyzaWxgPAmEDWqguuqjgmll/k50clF1qLz5wi8B/
         zEUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722337597; x=1722942397;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DUO5Oy8QM4X2myiTbngYsabALQRXD9NLLggVYkqX75g=;
        b=LiMMw2IrDIIXU7l7c/ccraC/SdDKzkWRFG9Tt+SAGSKsAKZt6T06jK3JBF/nbqXRxD
         Th5w6lw1QyLtjM7ILOLfkj/ALV3QNPsbDzQHKPXmit4jye+ifeLNy0pYOgEocQ2X2J8E
         JFcEUnHqRc5JVyxo7DTu+LDsSwiZssWKAIs1yHW/QeLM2HQcF3EIdyd6IBxmv+qodCEn
         8W6miyJzIT4ZMaMmJ0yA0CQT5S+wbAjEouKp7N06Fmk2E9qdyOZ7wLMSqwPumBv5Ojsl
         eJd7a3JFxmzasQa3f7K+AvPnM/POBurxILay+DGUOrbbl7ND0vJk8TJPZYNNUhTMtgbp
         eJ+g==
X-Forwarded-Encrypted: i=2; AJvYcCUdIWof+3lV2iv31avxxcDxVkz/2A9/FgztbqTcmZE6i+lz80qZyYqG6Crys8J7mKOpng8vm3G1jyS8+XF934ERyjNNGNvFIg==
X-Gm-Message-State: AOJu0YyFff3WSiGdNy8hriYfA0V6yLNpaLWn2VxOlkv1Y7N7uGxYmuOa
	nKo//yry6+P9SJWd9/6ZTq7y1KBHSYWAqPK5JhGjpbFpw+C90Jd8
X-Google-Smtp-Source: AGHT+IFhtPN465V7a6DHJysg8LSOjaxY07Z8DMBsOz3fIqUuncf9VGHUJ3Qjx+nb7ncVYIoMkz2wfQ==
X-Received: by 2002:a05:651c:2227:b0:2ef:2ba5:d214 with SMTP id 38308e7fff4ca-2f12edfedaamr98746801fa.4.1722337596986;
        Tue, 30 Jul 2024 04:06:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1507:b0:2ef:256c:a264 with SMTP id
 38308e7fff4ca-2f03aa9de5fls22205981fa.2.-pod-prod-05-eu; Tue, 30 Jul 2024
 04:06:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCURC5Gb08lH0fIiiAAFp/QogwKnetf/1jdX38baenQH7JguoWg5lB/5zZKLy1TqC6qLzIN3ExjNjG3Fc7HXsVvo5qo35OU40uhDeA==
X-Received: by 2002:a2e:90cd:0:b0:2ef:24f3:fb9c with SMTP id 38308e7fff4ca-2f12ee57c3amr87676651fa.38.1722337594714;
        Tue, 30 Jul 2024 04:06:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722337594; cv=none;
        d=google.com; s=arc-20160816;
        b=dydadRMOve5kglJ7GdVjvKArIjNU/z5MP9W0XRvg/xlynnwAX6VrbBcl2M9gTda3ZO
         P/wHgcUKzuC/5Ni++D8D5LOuB5JKHkWudAIfjss7nNeP04aaNmFS3RMMWmC/X435ipFb
         Z2M75b9lkvdB/e+xKVZ0v9HcfxwMKrytzx8UJdXJP3R+3jhj0ERP/ijJb29P8Be+WRB2
         CW/6/7xT2qLEcsTTywUfG2j/oyNiaKdulZBGrC/m9vEcbA/PuAgGiBw7SxSFh0FZh4jA
         LqDLpzVEfqrKK2N+8WxSxrTYKO3zsUF0KTfGzGYgkW/ivY+lwFT5qJ8X8YCg8iryyWoA
         kT9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=bNxWbBeV69N1GBya0KWgugonlwiE99usGrtCl3FAeEo=;
        fh=4BXMzOMJCzjNniYYTlzYEJmOwsrXYQq+9tzB8A7nGMs=;
        b=ggO3B6q+Ikxs+xb1hML2Vsk8wMPITPTCFtP6oKhIU+GG2Ip4yGgrrd9PN9qUaR0h2L
         EW8AuqOyvm67gkCjUHB0cOWpp3jeY1HrgTY/laqV0g3d+CRXejJVhQDz9IpA2BPod2Ww
         8zYSjLmwxQLhhrejZIe3ygk+qGXdKSLVOuj5f9GIMIsq1uUzL0Ymgdu8vgHnWHeHZHtP
         7//Tft8KQsQ0sQ8TBpIKxOFF/kvmVP9W1elO0tlrtsbKFFecGRB3JZSiXtYxD/U46k+t
         WwDkTw+w55Zbb673QvLIHAUI3/pPvqBIz2D0As/KcZkC3G5OWGKJubsgFVxjFulvTJ+g
         Lp3w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AMTDQwYF;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f03cfff8dcsi2449331fa.4.2024.07.30.04.06.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Jul 2024 04:06:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id 5b1f17b1804b1-428063f4d71so41275e9.1
        for <kasan-dev@googlegroups.com>; Tue, 30 Jul 2024 04:06:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX3PAMJsUwJEVrkyjszNr+yKTpNGDe74Cc/KXjtNN9v2SbQWy13g4Yq+5426TU8QsCcFAU/iF53drCjNsVdTbZpPfC76eApXfwcRg==
X-Received: by 2002:a05:600c:1d1a:b0:424:898b:522b with SMTP id 5b1f17b1804b1-42824a359b1mr828395e9.1.1722337593356;
        Tue, 30 Jul 2024 04:06:33 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:be6a:cd70:bdf:6a62])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-428054b9196sm209130635e9.0.2024.07.30.04.06.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Jul 2024 04:06:32 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 30 Jul 2024 13:06:03 +0200
Subject: [PATCH v5 1/2] kasan: catch invalid free before SLUB reinitializes
 the object
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240730-kasan-tsbrcu-v5-1-48d3cbdfccc5@google.com>
References: <20240730-kasan-tsbrcu-v5-0-48d3cbdfccc5@google.com>
In-Reply-To: <20240730-kasan-tsbrcu-v5-0-48d3cbdfccc5@google.com>
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
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=AMTDQwYF;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32b as
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

 - moves checks from poison_slab_object() into check_slab_free()
 - moves kasan_arch_is_ready() up into callers of poison_slab_object()
 - removes "ip" argument of poison_slab_object() and __kasan_slab_free()
   (since those functions no longer do any reporting)
 - renames check_slab_free() to check_slab_allocation()

Acked-by: Vlastimil Babka <vbabka@suse.cz> #slub
Signed-off-by: Jann Horn <jannh@google.com>
---
 include/linux/kasan.h | 43 ++++++++++++++++++++++++++++++++++---
 mm/kasan/common.c     | 59 +++++++++++++++++++++++++++++++--------------------
 mm/slub.c             |  7 ++++++
 3 files changed, 83 insertions(+), 26 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 70d6a8f6e25d..34cb7a25aacb 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -172,19 +172,50 @@ static __always_inline void * __must_check kasan_init_slab_obj(
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
+ * kasan_slab_pre_free - Validate a slab object freeing request.
+ * @object: Object to free.
+ *
+ * This function checks whether freeing the given object might be permitted; it
+ * checks things like whether the given object is properly aligned and not
+ * already freed.
+ *
+ * This function is only intended for use by the slab allocator.
+ *
+ * @Return true if freeing the object is known to be invalid; false otherwise.
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
+ * kasan_slab_free - Possibly handle slab object freeing.
+ * @object: Object to free.
+ *
+ * This hook is called from the slab allocator to give KASAN a chance to take
+ * ownership of the object and handle its freeing.
+ * kasan_slab_pre_free() must have already been called on the same object.
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
@@ -368,12 +399,18 @@ static inline void kasan_poison_new_object(struct kmem_cache *cache,
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
index 85e7c6b4575c..8cede1ce00e1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -205,59 +205,65 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
 	object = set_tag(object, assign_tag(cache, object, true));
 
 	return (void *)object;
 }
 
-static inline bool poison_slab_object(struct kmem_cache *cache, void *object,
-				      unsigned long ip, bool init)
+/* returns true for invalid request */
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
@@ -503,15 +509,22 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 		kasan_poison(ptr, folio_size(folio), KASAN_PAGE_FREE, false);
 		return true;
 	}
 
 	if (is_kfence_address(ptr))
 		return false;
+	if (!kasan_arch_is_ready())
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
2.46.0.rc1.232.g9752f9e123-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240730-kasan-tsbrcu-v5-1-48d3cbdfccc5%40google.com.
