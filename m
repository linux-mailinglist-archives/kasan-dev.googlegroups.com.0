Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB7G7RG2QMGQEGVYH7ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id C440293C66E
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 17:32:13 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2ef2fd50a2asf2581461fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 08:32:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721921533; cv=pass;
        d=google.com; s=arc-20160816;
        b=OwDSmoA+WnDCdjGFtqjYmMNT9sXuaZ0rbkJRB9zo/4Qh+jgV2aljHfvNCjDcWwGCVO
         hw62Rwh2IhzcieDS0E9Dc43+tkRs6rh8HQAWG/ZNA98/inuuWJ+QYakDvjjcHVTLrVjI
         5DwB5a0mnB9yZNY+I4IWXhxL5SuuM8CJycMnlPLUvnYWHyMrSXBELHZW3XAd2jrzoQGE
         +vH11bbPRhB6Xszv12XvUPN68RPz+3Hgg8WKjKFAjkF5N0r510JVHlGLS7pIv4oXh0BB
         a41BgDEJKhBAEuVCZ5Dh/qPNKM3pi1Yznx/DuAXOX7LqnNsdKlFNdRCdJmrcqXxmZ02e
         CLtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=M4QT/YbDC4JfR1HXLeWuR+lvZS5gyCOImST7dv735s8=;
        fh=YRftnRGx0yP3IuNEZ/5G2TRlmddRyZa50ZwDWL1b7TA=;
        b=IwezOvMvYfPmPWIXkR1prm6ea8bCXePYQ2vUWLnLzReXtCEXBJRwpz4a1jjjVrZgqJ
         tm8rz8QLtXp4h0eOv1iRe+taZvQmnVemO637JwPsPeJgG2RT37GDTZkS2b6XIs/vv43c
         Yj7s0gp1RFUYzzIBLwVmvkNCoZlEj11LEH5T8QqNlcfBfAc2KJWd+3pQuFAKTWXt4ssB
         Z42EmigYVILVIVBG3vLXr7rf35LFgg8MohXdXkgDd3P5rWFNswqRiXbSj3MaSUxCxpin
         0NZIoDmvjP/fyVn65BNEKOYBJeLcWt8fhjv2PJREmuS8fF/oVic2EI7b+Gn0bU1ct4et
         0ziA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=X+xJUB3X;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721921533; x=1722526333; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=M4QT/YbDC4JfR1HXLeWuR+lvZS5gyCOImST7dv735s8=;
        b=n/ZJcqvbWVTfMNa0b700pF2kKASD57gV06rNrYWdC5eIeGmJdRDQGRocL1+iDB4Uks
         EkEf467fYBJoa9/WHK/LWnvnyanlqft470kphKlQCCmBvqCAK6pQGpUsicg7f8O40Kir
         zT9PRJzEOIbYR9nTiaHpQJ8Trp5rsiIMFk8vq8AoktbcRJxjQFy304CdR9QEpRWITROw
         8JxiQKt/u5f4PQLUT+5u7srxa4tpH8lOTYIfNNUpfb9QiSFP61OxblMEqGgVr1LS6Owg
         mZw4mxkYdimQiONxAnakfCB0yKKFxorwvDC+EnWbKd8V0wuEqUp5qgQuzlRXV3NAXsu3
         BToA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721921533; x=1722526333;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=M4QT/YbDC4JfR1HXLeWuR+lvZS5gyCOImST7dv735s8=;
        b=VxYxiS8lnX48uoSfOrnEWZGKaWITIpuduXSfxQHi4wsZlXUeD8vmbMnKq4zQ1cCTZx
         H9hJnVL1l6+nqqxqG5LlrQqR1CS/gUd/HA3BeXPeJms7j2oMG+wIj+tdKKZ4MWZTHi/C
         qNqNT9vDEKP0xEyNaPjbleqHHKjoMJH9uuLIqolEOT5g9XZJ7lLDMRbziOEpMTsd/zbN
         5liN9N8LMl+cqA2PJFC4F+NFZDM7Iu+8uwmjfXNo8wy/ZQAbftxJajKHH90BfSm8jWgi
         6QgrZdAwRlwJzdQTTuZNo/xJqLJ+XCPMapj45OfN4Yp2WeILwW9kT7yESuE5dD0rxYTi
         9iqA==
X-Forwarded-Encrypted: i=2; AJvYcCWFT+X4eiRWIkEuAsDgDQRJSdnlUc6wiSO69KgyCL97h8dnXasxE8Hgdh9u1XZb2zU3MVIlZyaDmFTLWmgRJB2lRnsIe6oNTQ==
X-Gm-Message-State: AOJu0YxCmswE5ywr/qDEdWn9up7njvayeOXML07+NHtlF+oWcpaZt6yc
	AsDnq070aQqOp+0sAhfCW95lKHiNNj80Dulve439WC3S26B5VOHD
X-Google-Smtp-Source: AGHT+IGPoPmjXjpuXq9vRbZjbM5sd7TdaYHvZcHH6raVNSSCXl/7S5efMpHdIB7HzAbdh2XC2LQqAA==
X-Received: by 2002:a2e:8ec1:0:b0:2ef:1f51:c4ee with SMTP id 38308e7fff4ca-2f03db6cd5fmr17760771fa.9.1721921532627;
        Thu, 25 Jul 2024 08:32:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3208:b0:599:9c73:c38b with SMTP id
 4fb4d7f45d1cf-5ac0d99d9a1ls452926a12.2.-pod-prod-08-eu; Thu, 25 Jul 2024
 08:32:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUaJlLvHrJAmdsm0KzzlBYy8plnirKdbVQcCfO+qjCStPVlxevZ9yCrfjzGH8XFJkqvCW0xMRbm7nRz4c/T0wl3zoyBw6d6hGXXyQ==
X-Received: by 2002:a17:907:da1:b0:a7a:9f78:fef with SMTP id a640c23a62f3a-a7acb823589mr212540866b.45.1721921530837;
        Thu, 25 Jul 2024 08:32:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721921530; cv=none;
        d=google.com; s=arc-20160816;
        b=NGojooknfSKewrZVQMYAUU2MX/J8nPGhWBZfycl0DpZwGHD/2EJmQddktUkqQFGVOR
         /9ubsTZP5dUMFv2OBLdH8+5JnmZuWRvo95ACwCxj9ridmbVdWJOmspO4WKya8Ov/Jvp1
         XetZFU3yGzMaqmJevleJcmiDjx5UsvsSRE6lCchzCyErBlCdp04Vw1LlgsTW6ZquHxww
         pcxgt+uec4wb4gbkqqMq71jBOawG6IgVPRTB7N0fERT0pSDVX55m4UbWO9bnKj402Ddc
         iB20hfPkEXCWpVPblb2h1cIEfzcXanPIQZ3zbFy5NRoHnMiWMBoMiWTt/XVyprTZeRE7
         Hd+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=S80DlW207ZEjD96+lTTj/Jsz+nrwgqtEAZpXQKy+x/U=;
        fh=YJazPh7ZbEc2AwM5hHpHHBTF/o0ivofSAZQGhhHAw44=;
        b=in4JJ8RGuddaxnol3aEVbgRkQr8CQtNH/Qfxx9DaMK5JPn/G7tuMvaAD6KpwPJALOQ
         yiItPmWDOzmh/cflo5USV2q7WSQgTN+LDjuuzSw0xwsbZbUNM5/61i26+RtKaQRBhDrN
         6QC4zSXiRC8U7Tm8FNOKmVMsHBp87Ey+Zg6o56Q+qT/crEafOtSCWd+MUOwa+7BFvZ12
         mu+wg7V34sjGKRxPWNLIubz5FN/6v9ileC+5jbzI0400ZGBn9JJO5zyRGWkOPtybsvOI
         y8JWM29sYjiHltGDyyTfIqdXK9Q7zyrgYHA+0Jvu0jycrPPBhkIOv9SgKsEVihMCGojN
         ul3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=X+xJUB3X;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a7aca6e70c6si4198166b.0.2024.07.25.08.32.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Jul 2024 08:32:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-428063f4d71so49205e9.1
        for <kasan-dev@googlegroups.com>; Thu, 25 Jul 2024 08:32:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVWm3JV2Q6J5XRzaiVqDqquCG7NvwqHJJoh3lTZCW4xMugWrMNtKNlv/FJZ4f8CaEBsWcOxdcEIALzVL5kEKrd3/1356aFwsFQ8Ag==
X-Received: by 2002:a05:600c:4f8f:b0:426:66a0:6df6 with SMTP id 5b1f17b1804b1-42803fa97eemr1598795e9.0.1721921529416;
        Thu, 25 Jul 2024 08:32:09 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:8b71:b285:2625:c911])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-428057a6c81sm40998455e9.34.2024.07.25.08.32.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Jul 2024 08:32:08 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 25 Jul 2024 17:31:35 +0200
Subject: [PATCH v3 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240725-kasan-tsbrcu-v3-2-51c92f8f1101@google.com>
References: <20240725-kasan-tsbrcu-v3-0-51c92f8f1101@google.com>
In-Reply-To: <20240725-kasan-tsbrcu-v3-0-51c92f8f1101@google.com>
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
 header.i=@google.com header.s=20230601 header.b=X+xJUB3X;       spf=pass
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

Currently, KASAN is unable to catch use-after-free in SLAB_TYPESAFE_BY_RCU
slabs because use-after-free is allowed within the RCU grace period by
design.

Add a SLUB debugging feature which RCU-delays every individual
kmem_cache_free() before either actually freeing the object or handing it
off to KASAN, and change KASAN to poison freed objects as normal when this
option is enabled.

For now I've configured Kconfig.debug to default-enable this feature in the
KASAN GENERIC and SW_TAGS modes; I'm not enabling it by default in HW_TAGS
mode because I'm not sure if it might have unwanted performance degradation
effects there.

Note that this is mostly useful with KASAN in the quarantine-based GENERIC
mode; SLAB_TYPESAFE_BY_RCU slabs are basically always also slabs with a
->ctor, and KASAN's assign_tag() currently has to assign fixed tags for
those, reducing the effectiveness of SW_TAGS/HW_TAGS mode.
(A possible future extension of this work would be to also let SLUB call
the ->ctor() on every allocation instead of only when the slab page is
allocated; then tag-based modes would be able to assign new tags on every
reallocation.)

Signed-off-by: Jann Horn <jannh@google.com>
---
 include/linux/kasan.h | 14 ++++++----
 mm/Kconfig.debug      | 29 ++++++++++++++++++++
 mm/kasan/common.c     | 13 +++++----
 mm/kasan/kasan_test.c | 44 +++++++++++++++++++++++++++++
 mm/slab_common.c      | 12 ++++++++
 mm/slub.c             | 76 +++++++++++++++++++++++++++++++++++++++++++++------
 6 files changed, 170 insertions(+), 18 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index ebd93c843e78..c64483d3e2bd 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -186,12 +186,15 @@ static __always_inline bool kasan_slab_pre_free(struct kmem_cache *s,
 }
 
 bool __kasan_slab_free(struct kmem_cache *s, void *object,
-			unsigned long ip, bool init);
+			unsigned long ip, bool init, bool after_rcu_delay);
 static __always_inline bool kasan_slab_free(struct kmem_cache *s,
-						void *object, bool init)
+						void *object, bool init,
+						bool after_rcu_delay)
 {
-	if (kasan_enabled())
-		return __kasan_slab_free(s, object, _RET_IP_, init);
+	if (kasan_enabled()) {
+		return __kasan_slab_free(s, object, _RET_IP_, init,
+				after_rcu_delay);
+	}
 	return false;
 }
 
@@ -387,7 +390,8 @@ static inline bool kasan_slab_pre_free(struct kmem_cache *s, void *object)
 	return false;
 }
 
-static inline bool kasan_slab_free(struct kmem_cache *s, void *object, bool init)
+static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
+				   bool init, bool after_rcu_delay)
 {
 	return false;
 }
diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
index afc72fde0f03..0c088532f5a7 100644
--- a/mm/Kconfig.debug
+++ b/mm/Kconfig.debug
@@ -70,6 +70,35 @@ config SLUB_DEBUG_ON
 	  off in a kernel built with CONFIG_SLUB_DEBUG_ON by specifying
 	  "slab_debug=-".
 
+config SLUB_RCU_DEBUG
+	bool "Make use-after-free detection possible in TYPESAFE_BY_RCU caches"
+	depends on SLUB_DEBUG
+	default KASAN_GENERIC || KASAN_SW_TAGS
+	help
+	  Make SLAB_TYPESAFE_BY_RCU caches behave approximately as if the cache
+	  was not marked as SLAB_TYPESAFE_BY_RCU and every caller used
+	  kfree_rcu() instead.
+
+	  This is intended for use in combination with KASAN, to enable KASAN to
+	  detect use-after-free accesses in such caches.
+	  (KFENCE is able to do that independent of this flag.)
+
+	  This might degrade performance.
+	  Unfortunately this also prevents a very specific bug pattern from
+	  triggering (insufficient checks against an object being recycled
+	  within the RCU grace period); so this option can be turned off even on
+	  KASAN builds, in case you want to test for such a bug.
+
+	  If you're using this for testing bugs / fuzzing and care about
+	  catching all the bugs WAY more than performance, you might want to
+	  also turn on CONFIG_RCU_STRICT_GRACE_PERIOD.
+
+	  WARNING:
+	  This is designed as a debugging feature, not a security feature.
+	  Objects are sometimes recycled without RCU delay under memory pressure.
+
+	  If unsure, say N.
+
 config PAGE_OWNER
 	bool "Track page owner"
 	depends on DEBUG_KERNEL && STACKTRACE_SUPPORT
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 7c7fc6ce7eb7..d92cb2e9189d 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -238,7 +238,8 @@ static enum free_validation_result check_slab_free(struct kmem_cache *cache,
 }
 
 static inline bool poison_slab_object(struct kmem_cache *cache, void *object,
-				      unsigned long ip, bool init)
+				      unsigned long ip, bool init,
+				      bool after_rcu_delay)
 {
 	void *tagged_object = object;
 	enum free_validation_result valid = check_slab_free(cache, object, ip);
@@ -251,7 +252,8 @@ static inline bool poison_slab_object(struct kmem_cache *cache, void *object,
 	object = kasan_reset_tag(object);
 
 	/* RCU slabs could be legally used after free within the RCU period. */
-	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
+	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU) &&
+	    !after_rcu_delay)
 		return false;
 
 	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
@@ -270,7 +272,8 @@ bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
 }
 
 bool __kasan_slab_free(struct kmem_cache *cache, void *object,
-				unsigned long ip, bool init)
+				unsigned long ip, bool init,
+				bool after_rcu_delay)
 {
 	if (is_kfence_address(object))
 		return false;
@@ -280,7 +283,7 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	 * freelist. The object will thus never be allocated again and its
 	 * metadata will never get released.
 	 */
-	if (poison_slab_object(cache, object, ip, init))
+	if (poison_slab_object(cache, object, ip, init, after_rcu_delay))
 		return true;
 
 	/*
@@ -535,7 +538,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 		return false;
 
 	slab = folio_slab(folio);
-	return !poison_slab_object(slab->slab_cache, ptr, ip, false);
+	return !poison_slab_object(slab->slab_cache, ptr, ip, false, false);
 }
 
 void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip)
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 7b32be2a3cf0..cba782a4b072 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -996,6 +996,49 @@ static void kmem_cache_invalid_free(struct kunit *test)
 	kmem_cache_destroy(cache);
 }
 
+static void kmem_cache_rcu_uaf(struct kunit *test)
+{
+	char *p;
+	size_t size = 200;
+	struct kmem_cache *cache;
+
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB_RCU_DEBUG);
+
+	cache = kmem_cache_create("test_cache", size, 0, SLAB_TYPESAFE_BY_RCU,
+				  NULL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+
+	p = kmem_cache_alloc(cache, GFP_KERNEL);
+	if (!p) {
+		kunit_err(test, "Allocation failed: %s\n", __func__);
+		kmem_cache_destroy(cache);
+		return;
+	}
+	*p = 1;
+
+	rcu_read_lock();
+
+	/* Free the object - this will internally schedule an RCU callback. */
+	kmem_cache_free(cache, p);
+
+	/* We should still be allowed to access the object at this point because
+	 * the cache is SLAB_TYPESAFE_BY_RCU and we've been in an RCU read-side
+	 * critical section since before the kmem_cache_free().
+	 */
+	READ_ONCE(*p);
+
+	rcu_read_unlock();
+
+	/* Wait for the RCU callback to execute; after this, the object should
+	 * have actually been freed from KASAN's perspective.
+	 */
+	rcu_barrier();
+
+	KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*p));
+
+	kmem_cache_destroy(cache);
+}
+
 static void empty_cache_ctor(void *object) { }
 
 static void kmem_cache_double_destroy(struct kunit *test)
@@ -1937,6 +1980,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmem_cache_oob),
 	KUNIT_CASE(kmem_cache_double_free),
 	KUNIT_CASE(kmem_cache_invalid_free),
+	KUNIT_CASE(kmem_cache_rcu_uaf),
 	KUNIT_CASE(kmem_cache_double_destroy),
 	KUNIT_CASE(kmem_cache_accounted),
 	KUNIT_CASE(kmem_cache_bulk),
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 1560a1546bb1..19511e34017b 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -450,6 +450,18 @@ static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work)
 
 static int shutdown_cache(struct kmem_cache *s)
 {
+	if (IS_ENABLED(CONFIG_SLUB_RCU_DEBUG) &&
+	    (s->flags & SLAB_TYPESAFE_BY_RCU)) {
+		/*
+		 * Under CONFIG_SLUB_RCU_DEBUG, when objects in a
+		 * SLAB_TYPESAFE_BY_RCU slab are freed, SLUB will internally
+		 * defer their freeing with call_rcu().
+		 * Wait for such call_rcu() invocations here before actually
+		 * destroying the cache.
+		 */
+		rcu_barrier();
+	}
+
 	/* free asan quarantined objects */
 	kasan_cache_shutdown(s);
 
diff --git a/mm/slub.c b/mm/slub.c
index 34724704c52d..f44eec209e3e 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2144,15 +2144,26 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
 }
 #endif /* CONFIG_MEMCG_KMEM */
 
+#ifdef CONFIG_SLUB_RCU_DEBUG
+static void slab_free_after_rcu_debug(struct rcu_head *rcu_head);
+
+struct rcu_delayed_free {
+	struct rcu_head head;
+	void *object;
+};
+#endif
+
 /*
  * Hooks for other subsystems that check memory allocations. In a typical
  * production configuration these hooks all should produce no code at all.
  *
  * Returns true if freeing of the object can proceed, false if its reuse
- * was delayed by KASAN quarantine, or it was returned to KFENCE.
+ * was delayed by CONFIG_SLUB_RCU_DEBUG or KASAN quarantine, or it was returned
+ * to KFENCE.
  */
 static __always_inline
-bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
+bool slab_free_hook(struct kmem_cache *s, void *x, bool init,
+		    bool after_rcu_delay)
 {
 	kmemleak_free_recursive(x, s->flags);
 	kmsan_slab_free(s, x);
@@ -2163,7 +2174,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
 		debug_check_no_obj_freed(x, s->object_size);
 
 	/* Use KCSAN to help debug racy use-after-free. */
-	if (!(s->flags & SLAB_TYPESAFE_BY_RCU))
+	if (!(s->flags & SLAB_TYPESAFE_BY_RCU) || after_rcu_delay)
 		__kcsan_check_access(x, s->object_size,
 				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
 
@@ -2177,6 +2188,28 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
 	if (kasan_slab_pre_free(s, x))
 		return false;
 
+#ifdef CONFIG_SLUB_RCU_DEBUG
+	if ((s->flags & SLAB_TYPESAFE_BY_RCU) && !after_rcu_delay) {
+		struct rcu_delayed_free *delayed_free;
+
+		delayed_free = kmalloc(sizeof(*delayed_free), GFP_NOWAIT);
+		if (delayed_free) {
+			/*
+			 * Let KASAN track our call stack as a "related work
+			 * creation", just like if the object had been freed
+			 * normally via kfree_rcu().
+			 * We have to do this manually because the rcu_head is
+			 * not located inside the object.
+			 */
+			kasan_record_aux_stack_noalloc(x);
+
+			delayed_free->object = x;
+			call_rcu(&delayed_free->head, slab_free_after_rcu_debug);
+			return false;
+		}
+	}
+#endif /* CONFIG_SLUB_RCU_DEBUG */
+
 	/*
 	 * As memory initialization might be integrated into KASAN,
 	 * kasan_slab_free and initialization memset's must be
@@ -2200,7 +2233,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
 		       s->size - inuse - rsize);
 	}
 	/* KASAN might put x into memory quarantine, delaying its reuse. */
-	return !kasan_slab_free(s, x, init);
+	return !kasan_slab_free(s, x, init, after_rcu_delay);
 }
 
 static __fastpath_inline
@@ -2214,7 +2247,7 @@ bool slab_free_freelist_hook(struct kmem_cache *s, void **head, void **tail,
 	bool init;
 
 	if (is_kfence_address(next)) {
-		slab_free_hook(s, next, false);
+		slab_free_hook(s, next, false, false);
 		return false;
 	}
 
@@ -2229,7 +2262,7 @@ bool slab_free_freelist_hook(struct kmem_cache *s, void **head, void **tail,
 		next = get_freepointer(s, object);
 
 		/* If object's reuse doesn't have to be delayed */
-		if (likely(slab_free_hook(s, object, init))) {
+		if (likely(slab_free_hook(s, object, init, false))) {
 			/* Move object to the new freelist */
 			set_freepointer(s, object, *head);
 			*head = object;
@@ -4442,7 +4475,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 	memcg_slab_free_hook(s, slab, &object, 1);
 	alloc_tagging_slab_free_hook(s, slab, &object, 1);
 
-	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
+	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), false)))
 		do_slab_free(s, slab, object, object, 1, addr);
 }
 
@@ -4451,7 +4484,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 static noinline
 void memcg_alloc_abort_single(struct kmem_cache *s, void *object)
 {
-	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
+	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), false)))
 		do_slab_free(s, virt_to_slab(object), object, object, 1, _RET_IP_);
 }
 #endif
@@ -4470,6 +4503,33 @@ void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
 		do_slab_free(s, slab, head, tail, cnt, addr);
 }
 
+#ifdef CONFIG_SLUB_RCU_DEBUG
+static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
+{
+	struct rcu_delayed_free *delayed_free =
+			container_of(rcu_head, struct rcu_delayed_free, head);
+	void *object = delayed_free->object;
+	struct slab *slab = virt_to_slab(object);
+	struct kmem_cache *s;
+
+	if (WARN_ON(is_kfence_address(rcu_head)))
+		return;
+
+	/* find the object and the cache again */
+	if (WARN_ON(!slab))
+		return;
+	s = slab->slab_cache;
+	if (WARN_ON(!(s->flags & SLAB_TYPESAFE_BY_RCU)))
+		return;
+
+	/* resume freeing */
+	if (!slab_free_hook(s, object, slab_want_init_on_free(s), true))
+		return;
+	do_slab_free(s, slab, object, NULL, 1, _THIS_IP_);
+	kfree(delayed_free);
+}
+#endif /* CONFIG_SLUB_RCU_DEBUG */
+
 #ifdef CONFIG_KASAN_GENERIC
 void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
 {

-- 
2.45.2.1089.g2a221341d9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240725-kasan-tsbrcu-v3-2-51c92f8f1101%40google.com.
