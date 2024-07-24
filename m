Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBEG2QS2QMGQEM4CH62I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id A8F1E93B524
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2024 18:34:25 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-52fcf7eb289sf1090381e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2024 09:34:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721838865; cv=pass;
        d=google.com; s=arc-20160816;
        b=idVc9riR8c1u/ugVgMhIQe7KLfEcXWM71wxv2PQU+qUhmzviRjj6V9e/qNgPqSpDG5
         LxUqjl0UySIJoycCs/FYT9hYodoQdbf+AVoBFF1CN+83cZj85Cx2B7jixkWugPyf24xT
         U4xSuKtFISuKEffKfKSjJPaiVdZXlbjlhhSpRFawcOT7ETJOQt2R69Dv1z5WWJdwORx/
         qGxiEIjKom2QH6UvJhZknb2WSn6Rd1ILFUb/RzRby0vCqzbC2k/jHl2315HHgVB3Maoy
         0vRGbBS7QfVilvkqLw7qkpN5ZyW/6lTrXXETZ3jgQc+UF/R8sN8TMIE+PGzyatInk3iZ
         0ywg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=oGli48qD+N51WpFjF1TjtZnwsTjtIlCFRWzGUkQf2Bw=;
        fh=tPiIl2XIovUfwvlCkRpwo7Gylg7p6AoxjHCqXuJzbXo=;
        b=sTCXOCMEPLYoE0RcZ8BhgkXBoH9iVMFNpMMzlI9UW7ue39lsFk72R5z2P0rJWH/yy6
         XMbOF2lPxZszWyIGtLBFgOYwCu0oXNUaDN4ZGc41xeGLh8OqhoITgOsmUQHE0KqYyZWL
         zeN1uFRB7hVpncM0suZZF3MmdJNdXtDp8d2vM67+Tv5R2QUxdDwjCExCDuJPB1g0ZyVZ
         Wv4tG/Dm94aNvQh2uOqMW1c0fuuSg85CzA57NnJBZ8TDRL6OlmgVSvMDzQRgDXHGMvEL
         qyJ1oUP6jP/nfGK2LHTpove6223HnqmN0AQv+f5KBxJFHfJ9i6GKFEvdG9CcntotoObD
         bR0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GXXYIG34;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721838865; x=1722443665; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=oGli48qD+N51WpFjF1TjtZnwsTjtIlCFRWzGUkQf2Bw=;
        b=FSuL8Re4opr0E/tml494g38n0R0tlHqcpD2u9KO59h0z1Cmi6M19KbyEzoWizoHLUU
         LcEtSVrFT/jr0QZe/XFCt7BPNnmTyysEVYdv1F+lVv7KQXuLfbaFvNRdudq17AOkQVEO
         TPolGQPKz2crFnuwFzc7zYijHMbV/FKVQe+uiIPxbc53LLJ/IK/7ksk1xLAdfvmxXSX2
         9TrcIbZ0SHrAGHhvrQKyYIwgaxr3CTxYy5d/sdPwyM0o9QfBNFwd2wrQI9WgWsf/H/HX
         wyqWQtkMMIWRZAAvBwUE1bMb2SGXuE2XF/X5oX8DZMaG4IhqeTSzboNgpJTI1s1ZHYwH
         BPxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721838865; x=1722443665;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oGli48qD+N51WpFjF1TjtZnwsTjtIlCFRWzGUkQf2Bw=;
        b=O18hYzi8gt2ur4xyAEGr6X+Lfw/leu7m+dQybLtwHA8NGnpjugmSY2w6aVI54DF6cY
         /BGbQnavE3VwNGq6wGceocvQEEAydEdKW5muUw96oXcIoynSGYKl9ptPHF5q6krsIFJ2
         MyBTGELi79s0KBtR+Q6Zoy1ytS37hdrTPGR+OSZxXrLXpQYhHIPjKgv3FeGC1KxchvrU
         Vl0QHHvo83X21xtBUmEv78jPWOYKQXifUhI6Oph29AyMDtpbm6QZmrxNNDM7lZLC6T6B
         m2c9+Heoqko9OOa78qxy9LZe2DjVy0D2V4x/iLehzVOFqN46LGor/y1Z1Y2UYTD5xwto
         6NuQ==
X-Forwarded-Encrypted: i=2; AJvYcCXO8khot4Oh/Tj0kid9ky6LddZYQzXJOumrZ9FkVqho9wwTI3NT2kN1FroV/tEW8+e780G0vRh2P6g8X9RrJGDzYgYF5hZWmw==
X-Gm-Message-State: AOJu0YwIOkjrfODKnT8TH7O46OtKcoI5U+3eTcrkVUkHwn9zZUccUqIx
	3EfIsgNS3IhwMkuTavSVr22/OoN3xPl1qc/Bjm4zLiSlaIImNYcq
X-Google-Smtp-Source: AGHT+IGQzNxA00lt8Wl9IviRHTASzDnLMXBfnCiz+hlTSNZo1oZPCcDMP9xaT+zoONh3l6HI6PvIxg==
X-Received: by 2002:a05:6512:2204:b0:52c:8c4d:f8d6 with SMTP id 2adb3069b0e04-52fd3f65d66mr184903e87.45.1721838864342;
        Wed, 24 Jul 2024 09:34:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2822:b0:52c:e511:acdf with SMTP id
 2adb3069b0e04-52fd3f462a4ls39990e87.0.-pod-prod-08-eu; Wed, 24 Jul 2024
 09:34:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXhx/wpgBkyhJFrCVU0d/jfSUVDYPlvS0OxYYX33JVNafGRwhEgPwYwYQVBd2ZhLfhiYyOo3czbvvsMVpP84GrGWUHmD8h7/5SaEg==
X-Received: by 2002:a05:6512:118f:b0:52c:e133:7b2e with SMTP id 2adb3069b0e04-52fd3f32aa9mr186108e87.35.1721838862226;
        Wed, 24 Jul 2024 09:34:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721838862; cv=none;
        d=google.com; s=arc-20160816;
        b=UhS9Hoh8G8ja6i9VnnvzqJaUZCeIl+Siv4qJuM8aaz1Imz4Mycaa3HpuzUgxIewC1h
         4NxM17KvQAMhdPffAHOvMTY80P3lObzxCo0UOOQEs69Dv0Hyejgg+XSlzUrNuKO+WO5e
         ybwfLtSup+4JTtFI3saQka+T/bnt4G3YtoebiCYReR9UzWNF8KUc3L8tvW4WRkV3IZDQ
         CrLyarZP9bpQ+EHj1xWmy5VB/hu6/MI+2qZP7dYvBS6RaoRpNpqHUyY2k/jkrY4kz3SG
         tehsX8NAoZB1kogH9foWZJJ1DfiYB1ZBqHo1Wa8Q9YSlT6xfWVhh7pnTLCNU9VTJA8wY
         EVsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=VWWzyhCXN+jxGl2+QpwHyQ3Prr+vS+LnJTcEFO/Q0qs=;
        fh=KwNeV5i9wmFfOdjEVwTqU1LOpIOORivDPPG/9+FgWMA=;
        b=Jkf8f/PKvivq09ghNuFCRDpdYphlZUhmOqvGmS9lME4KgNJOuPYdv/UJG8zNMOAhb1
         ngsTGuSQ01avQ+/6U7tOiKj9Q/SH1C0UDVRTGjxAuKP+0G1IKGTprYEb1FJkcRurJKUS
         +26u1dQ0X/QbaHpNs3qLKhdYUBF61Iwcagx7/ccwAKWq6yXQ+oaU9ORHRtEAKruoqYzY
         jllOQD7PGgEZYwd49N5zIqVJmbRYeoQg2I+HaUvZi975jsMIR/mNpISdwvvPJrkoBOrf
         sDJ89vE7drcFjAnJ2htzbFMV29fnuFHRe9k0Pvx4QRYT1fpUeOwkDz/jF89m2OFZk+nG
         GEEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GXXYIG34;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52f003c15adsi181738e87.5.2024.07.24.09.34.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Jul 2024 09:34:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-4266edcc54cso445e9.0
        for <kasan-dev@googlegroups.com>; Wed, 24 Jul 2024 09:34:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWYP8f5h+cv77cHfMc6kqOmmuAIUt1HAt8lYku5fZ1t1QcLh9Sgd+Lw0IPLA+mNqPnwetOju0i8mtyvQLeD6LfEnoqadx3/JHgZYw==
X-Received: by 2002:a05:600c:4752:b0:421:7caf:eb69 with SMTP id 5b1f17b1804b1-427f7b5514bmr1868425e9.4.1721838860742;
        Wed, 24 Jul 2024 09:34:20 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:7aec:12da:2527:71ba])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-427f937e274sm36151485e9.14.2024.07.24.09.34.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Jul 2024 09:34:20 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 24 Jul 2024 18:34:13 +0200
Subject: [PATCH v2 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240724-kasan-tsbrcu-v2-2-45f898064468@google.com>
References: <20240724-kasan-tsbrcu-v2-0-45f898064468@google.com>
In-Reply-To: <20240724-kasan-tsbrcu-v2-0-45f898064468@google.com>
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
 header.i=@google.com header.s=20230601 header.b=GXXYIG34;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as
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

Note that this creates an aligned 16-byte area in the middle of the slab
metadata area, which kinda sucks but seems to be necessary in order to be
able to store an rcu_head in there that can be unpoisoned while the RCU
callback is pending.
(metadata_access_enable/disable doesn't work here because while the RCU
callback is pending, it will be accessed by asynchronous RCU processing.)
To be able to re-poison the area after the RCU callback is done executing,
a new helper kasan_poison_range_as_redzone() is necessary.

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
 include/linux/kasan.h | 10 +++++++
 mm/Kconfig.debug      | 25 +++++++++++++++++
 mm/kasan/common.c     | 14 +++++++++-
 mm/kasan/kasan_test.c | 44 ++++++++++++++++++++++++++++++
 mm/slab.h             |  3 +++
 mm/slab_common.c      | 12 +++++++++
 mm/slub.c             | 75 +++++++++++++++++++++++++++++++++++++++++++++------
 7 files changed, 174 insertions(+), 9 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index eee8ca1dcb40..876ebd4241fe 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -349,6 +349,8 @@ static __always_inline void kasan_mempool_unpoison_object(void *ptr,
 		__kasan_mempool_unpoison_object(ptr, size, _RET_IP_);
 }
 
+void kasan_poison_range_as_redzone(void *ptr, size_t size);
+
 /*
  * Unlike kasan_check_read/write(), kasan_check_byte() is performed even for
  * the hardware tag-based mode that doesn't rely on compiler instrumentation.
@@ -361,6 +363,8 @@ static __always_inline bool kasan_check_byte(const void *addr)
 	return true;
 }
 
+size_t kasan_align(size_t size);
+
 #else /* CONFIG_KASAN */
 
 static inline void kasan_unpoison_range(const void *address, size_t size) {}
@@ -416,10 +420,16 @@ static inline bool kasan_mempool_poison_object(void *ptr)
 }
 static inline void kasan_mempool_unpoison_object(void *ptr, size_t size) {}
 
+static inline void kasan_poison_range_as_redzone(void *ptr, size_t size) {}
+
 static inline bool kasan_check_byte(const void *address)
 {
 	return true;
 }
+static inline size_t kasan_align(size_t size)
+{
+	return size;
+}
 
 #endif /* CONFIG_KASAN */
 
diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
index afc72fde0f03..4eee5aa2de11 100644
--- a/mm/Kconfig.debug
+++ b/mm/Kconfig.debug
@@ -70,6 +70,31 @@ config SLUB_DEBUG_ON
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
+	  If unsure, say N.
+
 config PAGE_OWNER
 	bool "Track page owner"
 	depends on DEBUG_KERNEL && STACKTRACE_SUPPORT
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 7c7fc6ce7eb7..ff8843cc973d 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -251,7 +251,8 @@ static inline bool poison_slab_object(struct kmem_cache *cache, void *object,
 	object = kasan_reset_tag(object);
 
 	/* RCU slabs could be legally used after free within the RCU period. */
-	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
+	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU) &&
+	    !IS_ENABLED(CONFIG_SLUB_RCU_DEBUG))
 		return false;
 
 	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
@@ -566,6 +567,12 @@ void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip)
 		poison_kmalloc_redzone(slab->slab_cache, ptr, size, flags);
 }
 
+void kasan_poison_range_as_redzone(void *ptr, size_t size)
+{
+	if (kasan_enabled())
+		kasan_poison(ptr, size, KASAN_SLAB_REDZONE, false);
+}
+
 bool __kasan_check_byte(const void *address, unsigned long ip)
 {
 	if (!kasan_byte_accessible(address)) {
@@ -574,3 +581,8 @@ bool __kasan_check_byte(const void *address, unsigned long ip)
 	}
 	return true;
 }
+
+size_t kasan_align(size_t size)
+{
+	return round_up(size, KASAN_GRANULE_SIZE);
+}
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
diff --git a/mm/slab.h b/mm/slab.h
index 5f8f47c5bee0..77a8f28afafe 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -273,6 +273,9 @@ struct kmem_cache {
 	int refcount;			/* Refcount for slab cache destroy */
 	void (*ctor)(void *object);	/* Object constructor */
 	unsigned int inuse;		/* Offset to metadata */
+#ifdef CONFIG_SLUB_RCU_DEBUG
+	unsigned int debug_rcu_head_offset;
+#endif
 	unsigned int align;		/* Alignment */
 	unsigned int red_left_pad;	/* Left redzone padding size */
 	const char *name;		/* Name (only for display!) */
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
index 34724704c52d..999afdc1cffb 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1225,7 +1225,8 @@ static int check_bytes_and_report(struct kmem_cache *s, struct slab *slab,
  * 	A. Free pointer (if we cannot overwrite object on free)
  * 	B. Tracking data for SLAB_STORE_USER
  *	C. Original request size for kmalloc object (SLAB_STORE_USER enabled)
- *	D. Padding to reach required alignment boundary or at minimum
+ *	D. RCU head for CONFIG_SLUB_RCU_DEBUG (with padding around it)
+ *	E. Padding to reach required alignment boundary or at minimum
  * 		one word if debugging is on to be able to detect writes
  * 		before the word boundary.
  *
@@ -1251,6 +1252,11 @@ static int check_pad_bytes(struct kmem_cache *s, struct slab *slab, u8 *p)
 			off += sizeof(unsigned int);
 	}
 
+#ifdef CONFIG_SLUB_RCU_DEBUG
+	if (s->flags & SLAB_TYPESAFE_BY_RCU)
+		off = kasan_align(s->debug_rcu_head_offset + sizeof(struct rcu_head));
+#endif /* CONFIG_SLUB_RCU_DEBUG */
+
 	off += kasan_metadata_size(s, false);
 
 	if (size_from_object(s) == off)
@@ -2144,15 +2150,21 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
 }
 #endif /* CONFIG_MEMCG_KMEM */
 
+#ifdef CONFIG_SLUB_RCU_DEBUG
+static void slab_free_after_rcu_debug(struct rcu_head *rcu_head);
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
@@ -2163,7 +2175,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
 		debug_check_no_obj_freed(x, s->object_size);
 
 	/* Use KCSAN to help debug racy use-after-free. */
-	if (!(s->flags & SLAB_TYPESAFE_BY_RCU))
+	if (!(s->flags & SLAB_TYPESAFE_BY_RCU) || after_rcu_delay)
 		__kcsan_check_access(x, s->object_size,
 				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
 
@@ -2177,6 +2189,17 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
 	if (kasan_slab_pre_free(s, x))
 		return false;
 
+#ifdef CONFIG_SLUB_RCU_DEBUG
+	if ((s->flags & SLAB_TYPESAFE_BY_RCU) && !after_rcu_delay) {
+		struct rcu_head *rcu_head;
+
+		rcu_head = kasan_reset_tag(x) + s->debug_rcu_head_offset;
+		kasan_unpoison_range(rcu_head, sizeof(*rcu_head));
+		call_rcu(rcu_head, slab_free_after_rcu_debug);
+		return false;
+	}
+#endif /* CONFIG_SLUB_RCU_DEBUG */
+
 	/*
 	 * As memory initialization might be integrated into KASAN,
 	 * kasan_slab_free and initialization memset's must be
@@ -2214,7 +2237,7 @@ bool slab_free_freelist_hook(struct kmem_cache *s, void **head, void **tail,
 	bool init;
 
 	if (is_kfence_address(next)) {
-		slab_free_hook(s, next, false);
+		slab_free_hook(s, next, false, false);
 		return false;
 	}
 
@@ -2229,7 +2252,7 @@ bool slab_free_freelist_hook(struct kmem_cache *s, void **head, void **tail,
 		next = get_freepointer(s, object);
 
 		/* If object's reuse doesn't have to be delayed */
-		if (likely(slab_free_hook(s, object, init))) {
+		if (likely(slab_free_hook(s, object, init, false))) {
 			/* Move object to the new freelist */
 			set_freepointer(s, object, *head);
 			*head = object;
@@ -4442,7 +4465,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 	memcg_slab_free_hook(s, slab, &object, 1);
 	alloc_tagging_slab_free_hook(s, slab, &object, 1);
 
-	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
+	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), false)))
 		do_slab_free(s, slab, object, object, 1, addr);
 }
 
@@ -4451,7 +4474,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 static noinline
 void memcg_alloc_abort_single(struct kmem_cache *s, void *object)
 {
-	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
+	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), false)))
 		do_slab_free(s, virt_to_slab(object), object, object, 1, _RET_IP_);
 }
 #endif
@@ -4470,6 +4493,32 @@ void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
 		do_slab_free(s, slab, head, tail, cnt, addr);
 }
 
+#ifdef CONFIG_SLUB_RCU_DEBUG
+static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
+{
+	struct slab *slab = virt_to_slab(rcu_head);
+	struct kmem_cache *s;
+	void *object;
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
+	object = (void *)rcu_head - s->debug_rcu_head_offset;
+	kasan_poison_range_as_redzone(rcu_head, kasan_align(sizeof(*rcu_head)));
+
+	/* resume freeing */
+	if (!slab_free_hook(s, object, slab_want_init_on_free(s), true))
+		return;
+	do_slab_free(s, slab, object, NULL, 1, _THIS_IP_);
+}
+#endif /* CONFIG_SLUB_RCU_DEBUG */
+
 #ifdef CONFIG_KASAN_GENERIC
 void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
 {
@@ -5199,6 +5248,16 @@ static int calculate_sizes(struct kmem_cache *s)
 		if (flags & SLAB_KMALLOC)
 			size += sizeof(unsigned int);
 	}
+
+#ifdef CONFIG_SLUB_RCU_DEBUG
+	if (flags & SLAB_TYPESAFE_BY_RCU) {
+		size = kasan_align(size);
+		size = ALIGN(size, __alignof__(struct rcu_head));
+		s->debug_rcu_head_offset = size;
+		size += sizeof(struct rcu_head);
+		size = kasan_align(size);
+	}
+#endif /* CONFIG_SLUB_RCU_DEBUG */
 #endif
 
 	kasan_cache_create(s, &size, &s->flags);

-- 
2.45.2.1089.g2a221341d9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240724-kasan-tsbrcu-v2-2-45f898064468%40google.com.
