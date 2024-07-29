Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBWWLT62QMGQEU2CDSQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B3CC93FDD1
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 20:56:27 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-427ffa0c9c7sf28371375e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 11:56:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722279387; cv=pass;
        d=google.com; s=arc-20160816;
        b=DtIbOJPo2gupXRZDJjkzOog5cidAF6tMw458amCq/VMjhnegbiu2MFKt8fNNteRi4a
         km8u/RNc6wKiVgntD0QCwLWmHBoS5E6X9VkkXw+fRSqfp7GEciLHDT15pwbr6PNS2aIi
         bp2kYzSCG5G6noCKr0+iURhelOJTvHGFv9a9S1o0pLqzxcZZ23lubi2nq2dz8SZP5XxI
         FIaAb1z0JQGo0aROO6OQFr+UJZj0NwtMA45Zc7NHfOCmQhhDB+zZzcU/H5lVdx4ByzKg
         TllIJVUJEGy2sE6t/USjXJdmjoCfK+p67u80FEVLAPCtuPpliL2szQpKzviuz/I8Qnug
         sa8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=OEPK2fyzLIIAVqeOy2vWX3HpPwxZvqTMBKKyY+PcI0Q=;
        fh=RcRr0A+WO/wg+rJZLmzdRdxDN8l0NfRqUE6YvPBL/VM=;
        b=q2aIZelVXS6US7Jqb1Oyh6gcwLU3tRUvIV2S+GI92nuDiqfoEpcWmuCEIxj0coYQ8d
         fAx5iBa6+2W1qLnDB4HH+zVsRWJr4afDHp7iVjlcWv5IpF5arm7bK6laVXevI+M0/xo8
         MWuNJNqzXNRg7u57N0pjQzUwva1tltsGKMIW0IqJiLqbjbDJ01AiVULUFMbtfRAbt3OJ
         7KsC6OrHt/ZpEA6+avyikrXtKPDZcnT1R+kUNimHnTUlXTwlrkmlGSM0TpNuFNtjVQ/4
         nnLrisxXy926O9i3FyM2UMoY/fcOWT4Fbj5lBixeyUHaIPQW4p99XYNIm9G20jgbMvgo
         uNCA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="XRNP1/AG";
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722279387; x=1722884187; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OEPK2fyzLIIAVqeOy2vWX3HpPwxZvqTMBKKyY+PcI0Q=;
        b=gNP4v+k/K1sEjVHMkqm1KALOaO6YOYwXtpkEwoCMo8pV4kz11w3wl52ZSrLTe5nHfQ
         ftqEmah5XvPlENQ4M+LsAUKdNV/GRuidXbGxyO9BQYyKe6LdMxH985Vlqy+JttLyYu3t
         xRP2Bj83SXdDbS5KLuJH9io2RoDB7QfPXsuZKndz7FiviF9r6ZXgjOTnqmXA1fbQOHFI
         fgQz9YqOCc3MmDDCanaeFtTbrDmu3CvKYOO9UTXU10g4LjL8UwLlOXxlbLnL4lDezXhV
         iUvXqFRkhTERSnwFAJKmcJd363fTSGf8TZXZvzcyT15Gw4Jio2Iu6e8eNBmIEe9Qknix
         1q8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722279387; x=1722884187;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OEPK2fyzLIIAVqeOy2vWX3HpPwxZvqTMBKKyY+PcI0Q=;
        b=fygUSLXBP2M+8D5Gh6spKhSIjs0k6egeVseWLrI9Fcsv9A9h1FITjWoCYGzzTkEZ7F
         DgSk8/dw+2LJ/jCYTuG1bt1375/KmiJjMyPga7kwZ2OYIHpOPmov9FaTEq+zfZ2WbEV3
         KNuA49W75mA8IdQZT5X3OjB+Yr4NaRAX16rzYiaIjvgt7MUObFtgBsMea2jGcYyBKAeS
         YNbbdJ2B320+PA+qTansgcHq12hPOyI7jBqR0k/pDs9LpepmQsQZZQwHTfiIktCnulqP
         HQckKCXl4XqqpPOdFuDNdIcpqG84HVCzHbFVB6i1GZxFAZNZEsHbu0CbxDVQAm2yPZGr
         PlpA==
X-Forwarded-Encrypted: i=2; AJvYcCWgn/A99xg1qhPM0Ut/VxYlpyNb5ZxWLozMUVcNOEUvQJVf/XV1EwTCCkIT7OSje4LaMPZs12rEfHB5u/ZXjac/qQ0+Oc2VEQ==
X-Gm-Message-State: AOJu0YycSd6Yt+0VqmjXgfrAfn/lhavdj3gpb+2efzkH+VnG66jvewdy
	33deFZzp79seA3FkpzHDOGv8SbCljwGCeNH4S3iJAUx6MIkFvzbO
X-Google-Smtp-Source: AGHT+IHeqCWRuJ+vMo1YVzwAP12bhrYKbqNQ63Mub3gevt2qFlC2ARkPoEqs5/4wjc+E0SpdlBvXuQ==
X-Received: by 2002:a05:600c:138f:b0:426:5b44:2be7 with SMTP id 5b1f17b1804b1-42811d8bb34mr73002295e9.10.1722279386678;
        Mon, 29 Jul 2024 11:56:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b8c:b0:426:7318:c5a0 with SMTP id
 5b1f17b1804b1-42803b872e7ls29355005e9.2.-pod-prod-05-eu; Mon, 29 Jul 2024
 11:56:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV2Wg4OoeO2ZTtUKE/3U13UzuWIDQM8InqG9bxgN5bofnk2mzxDj6MK32ylUYjdJBRWjNDYu48Yjb+TQsq6stEdaGZHu7+CNwLUcA==
X-Received: by 2002:a05:600c:4311:b0:428:111a:193 with SMTP id 5b1f17b1804b1-42811e0b9a7mr57955495e9.37.1722279384697;
        Mon, 29 Jul 2024 11:56:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722279384; cv=none;
        d=google.com; s=arc-20160816;
        b=afXaoEWoAOCrpPleO5FJshDRvhtjQPSxiGt/OzsJyTwPzFrQicJVNs2H1UNZjD0ZEL
         cGVKL/TKeR1XhZ5SwQGd+acqrbKRLmwcUTV87h3StljkgKuk+inmQLhbpZSdIx7FRL7g
         smXYAATHN+Tv7T+6LsNFYC41esRbUxLsbTeWu1VraMP6tRHSvt8ChYgK857V6Q3iH80D
         tzDxKpQ+ULHvVGSPh7JFYChUwPpmZ07QoujnuHfNeLHyTio4fwILyb4w1jGLlAHK9J6B
         eodH0+/bjuOCi2BipfEkugkzcNybDc0+rcVXv1mRULywDMGxs8gYLUXgGWYX2AhDH5VX
         R9TA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=VCoOCGeg30WnFijIytAVeEgtIkuQktWy1Oz+PoUgncg=;
        fh=j1eetxPyGZSbmVL7ochjHCsPElSC+RvoqbakoavsbFE=;
        b=ZdL1xRikx1rotSD8ect1CpOyop4KJNxPyzmeVOAY7LjWhS8atjwB9I2iIEbqexNx6z
         y4noP7nOiH5vmOi6ujlANqMyBr4Y6Y9WdCdwffqBwUE4gw3SzW0RVkonO+dB2YX5V3if
         ngpS1qpKHrz4ksRP92BIu+btpypA0OWRqQByySRDeVN5fFJexYlGPgLQU2lxAZd1OZ1V
         6KvVOR7R5+zrF2HllS6n1bBXCws3KJsu7PAHX3uPSUxk1ynmw3m6pFwUq0byvF42BKYj
         oZYKyHdkpY9iFmLyDSMLsLU4+VUd0EiQwyGk7I76PrzYMto4NR3PDZ10uG6b442vUCg4
         8RJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="XRNP1/AG";
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4280718d1b9si2340385e9.1.2024.07.29.11.56.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jul 2024 11:56:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id 4fb4d7f45d1cf-5a18a5dbb23so2688a12.1
        for <kasan-dev@googlegroups.com>; Mon, 29 Jul 2024 11:56:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVsjXiHgqySNJGYyd6hCWJZSqYQy0Uxu+QdYP41ZlE8v965D3qC7Hc1S+pnHCkwFk5wWElDmhi+Myn/QMVFXqydboDlK9MuavF4MA==
X-Received: by 2002:a05:6402:4314:b0:58b:93:b624 with SMTP id 4fb4d7f45d1cf-5b40b12a598mr84009a12.1.1722279383641;
        Mon, 29 Jul 2024 11:56:23 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:a1f4:32c9:4fcd:ec6c])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-4281a936944sm60963535e9.31.2024.07.29.11.56.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Jul 2024 11:56:23 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Jul 2024 20:56:11 +0200
Subject: [PATCH v4 1/2] kasan: catch invalid free before SLUB reinitializes
 the object
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240729-kasan-tsbrcu-v4-1-57ec85ef80c6@google.com>
References: <20240729-kasan-tsbrcu-v4-0-57ec85ef80c6@google.com>
In-Reply-To: <20240729-kasan-tsbrcu-v4-0-57ec85ef80c6@google.com>
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
 header.i=@google.com header.s=20230601 header.b="XRNP1/AG";       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as
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
index 4927edec6a8c..34724704c52d 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2167,12 +2167,19 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240729-kasan-tsbrcu-v4-1-57ec85ef80c6%40google.com.
