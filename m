Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB5M52S2QMGQEIKQP4FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9487B94C459
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Aug 2024 20:31:19 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2ef23ec8dcfsf11443701fa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Aug 2024 11:31:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723141879; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q+Z7Zq7lf1QtDIv92Q50MHVYeUkm0Lz7AM/NVcuD6KdiL7Vx/t6rcORQd2LxqNBp80
         HotF7jRYWByDIeMlE8qUURAhhIQSRn1hBN3lI/SYJkTBw6x94vvKwN6AwmUhdmqsY8Ps
         41n1H1NF66zcHFeSjKltiyjDDepTiRH4vBSMvMFG5OLlvTLzhaWBgdWai86F9bgpgQlq
         TYwlDJHtN13MueL82bc+xrrNpU9uB8Q+fOdIFtkjMI9ABvjI9YhtGQSKGSitCjbzakmX
         ADygRrjlocxuyT0woa3ZJVEmpVST3GjBK9Fg91N0AyRiaCBD8dpcCRMvtVoYe58HjVtp
         eS1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=ENyOWJMDZAt+w8SdPFu5IZG75fA5WT4uYMXJCtM/drA=;
        fh=1PRXIDe6+m2OENcrlOd0+Pbik9X+rnGtjT5Su7Ulfh0=;
        b=NrZLtQhWxSZQ2oPXSKq06FJGnqKN+Vop4DX5gKObq7qLAt3l8HhsOpjYXl/w8pA3dS
         SoQO15+RbAhTmUAVS6PH6ZICc0GrWLq2hZathc2QA+ZbAmxZFxsG3z8RvwWTLnD/tWwH
         EfmKNcTiaKNh77U5PrJ7yq/b6arexjkY5My1AvFjDSBAbamRGAPtWPUhKk9+lgk6cCTw
         VDwEDp1RinB74FWA4K2ATLOXn9aD239y+6fXF9oIILIhfEVdl50V/dfi4Fs0emqBelyi
         D+6Ofwh+lbQbLYoiCFAXw+td6E5t5oN2LqXDsVQHIcswcsaDaZHUvdAoO+CMatVuvOhK
         etWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JK2AG4Rx;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723141879; x=1723746679; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ENyOWJMDZAt+w8SdPFu5IZG75fA5WT4uYMXJCtM/drA=;
        b=AkD30M9BrY1eEB923EYuejh4Cg95ZbMW1+Aj9KnWhM4a6Q16gk5K1oGVLjkmLfj3cR
         LhA3a4p607JyBBICbcaMmOhmW9KaCxtJ6v6LyKi5GGMObKRPm+vLU/VOYYMMmdO0OBL+
         eoWh/LTOiULTZdIr9nHo3MnKxHQczjldtdgaUYi3s6obcqilxMO2GPDcbcMenjQ6eXOa
         zVmJaMqqF2CgNj7mjn2JHSBaC1u0aQ/KMbIkiNd/rW0UlBb8TuuRETkd2H2M6SbZl2tW
         cWo0fV/wUExhCpNur2v2Q0+6a5MckyoT0/2YV5KSiU7HaXTkVGieHFJOtqnvPQlATsf7
         Oo/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723141879; x=1723746679;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ENyOWJMDZAt+w8SdPFu5IZG75fA5WT4uYMXJCtM/drA=;
        b=i6u5GMmy9fCTP6CxzPPJNoj2LPiyR55gQvR8A2AzBUjPmhcN3O3MQ75/JD1U1/1ujh
         avVNRRNCIGHhjUbwjaDqcnWyL3OIbtNbKY62+eE2AnFvVHiLOYaQi33Sl0rJEVoOT/QK
         FYSl2Mb/udbPGruR1E/KT5+3zkM9ZAmFL2nCTuDzouucDypA3vuM6mVMrsYoLQYOEy5E
         lyDa3GyumWXfsuikyh9yQ0XQ6pYYPbO8X3/oRDgGa3uzzK8EXA3ASIlIG94wrYvxvhnY
         7Yr/SIaKw3BIot3jl7RMD65Ou4x7NIzq7lU2lJeD8sMmuFRA50Cyf9ajv4dRZ/JyagfY
         XS2g==
X-Forwarded-Encrypted: i=2; AJvYcCUlEg0w3QYsf4hhF8DpGzyxhG7NaAslQXaokM/xn7aAKXU0HOWuIn831vFpd4Dm5kImcv6vvfmpdxkXjSXDLHenyMppwV7diw==
X-Gm-Message-State: AOJu0YxOFb/8A5lO4zmOsKm0b0Gg5660DmQlkBaC8c844Ja6LknGrs+6
	tKBXARVK4PE/YClcH8fMsnFSKztsoPIjX6JSocuzPxwYP26f7F2F
X-Google-Smtp-Source: AGHT+IE3tQF1VvEUdNxj/9QJY5EZCKNBXOCJBHO7CKW5CM4uxTQWPVZpEFRxB7AiBNYq9CN76ZFShA==
X-Received: by 2002:a2e:bc07:0:b0:2ef:2608:2e46 with SMTP id 38308e7fff4ca-2f19de1f64cmr24318841fa.6.1723141878220;
        Thu, 08 Aug 2024 11:31:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2203:0:b0:2ef:2eec:5052 with SMTP id 38308e7fff4ca-2f19bc583fals5750761fa.1.-pod-prod-03-eu;
 Thu, 08 Aug 2024 11:31:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUJ2PYD81BUN/UkrOZe5XbBLGLFqzHwf1fnkow7ndYHDDsAoK0GYZMmb0IJT3Es6hsX+Cnogk1Y7U9Ty9p6bYL+pXEpqHI84iBmYg==
X-Received: by 2002:ac2:4c48:0:b0:52c:8206:b986 with SMTP id 2adb3069b0e04-530e5899e8fmr2137931e87.56.1723141876078;
        Thu, 08 Aug 2024 11:31:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723141876; cv=none;
        d=google.com; s=arc-20160816;
        b=PPQ2TDu/NiZQj4WonutV9JDLEf/QpMRH/d2aakcsrCLMb4Py+PDESfuuzUfSPAPO8A
         05VXsqFDvZsmEUFpNnHsO5q/plGhJKSN7aUDzpQQQa1I1+7t3SYg2TIg8oA76dQ2gVBB
         1mrbuNrSziRaq242bJrweoJGQ6FUkU87sLQEBWr1vN0vTd8M1kBcBy8gFG8Mf48Jdq2i
         RCYVA2f3ppgev0YvLAn9fzmk2jfNISeVp0MnyU2g3so5kq5Bh5H/P62t/Du5XJmrE2FB
         FN0RV9EeMn+gHznENEH0jsqrmVJZSQbZVXXSRGZKo6IpIRqrEXHRAPRsWVoiJ09kWo5p
         GBxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=N+PyumrqcJpgwsYfmjIw/CKiRtSxZuY78aagcb5lFIE=;
        fh=FweEsj+wV5AqaZVZrxMG4zJp8c3SOXBgqAK7ED4Z5jE=;
        b=QysjscpPkLlmslDJCFhI1nhCp3+2DKiiOVvuLjiEfD5P8Jys97fNNNZsa0DpRIURhs
         WE9CWj8JNQu87lBQpNmIVlO5mXJ4LXrv6pU+2eLlA8/gpoKn4kz7kpMwPybbexcAfqaQ
         A5O88I037ov246TQOegcgiy8dNqCktBSZaK38VNHOE8NZm/Jh9mSJA+Z+04OCk+a/GYy
         NvaGK2sCyJnZ9U7MuinOji20ScxlG3VKBQMR4DqEPatcs3sSnSFc4QgFjUqJtYp27rXZ
         8tnngt5tYsCAsJOjb/TzxfPc65ePT0nzmDyUOJgB414wOps6UaNiYrmgXiUvb009rNb8
         +pYg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JK2AG4Rx;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52f.google.com (mail-ed1-x52f.google.com. [2a00:1450:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5bbb2f0d6fdsi47226a12.5.2024.08.08.11.31.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Aug 2024 11:31:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52f as permitted sender) client-ip=2a00:1450:4864:20::52f;
Received: by mail-ed1-x52f.google.com with SMTP id 4fb4d7f45d1cf-5a28b61b880so1393a12.1
        for <kasan-dev@googlegroups.com>; Thu, 08 Aug 2024 11:31:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWsp9co4EVOkarMvYvoR/9PgY0gZKhLGcSAoj0kbhlv2a+64mgWuyasEEiwAdpV6oujZ8fqcaTxrInd6p4W4vZbcpA2KEln88x3DA==
X-Received: by 2002:a05:6402:2707:b0:5b8:ccae:a8b8 with SMTP id 4fb4d7f45d1cf-5bbbc87c5b6mr5695a12.3.1723141868622;
        Thu, 08 Aug 2024 11:31:08 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:fc0e:258b:99ae:88ba])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-36d27208c2fsm2789843f8f.74.2024.08.08.11.31.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Aug 2024 11:31:08 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 08 Aug 2024 20:30:46 +0200
Subject: [PATCH v7 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240808-kasan-tsbrcu-v7-2-0d0590c54ae6@google.com>
References: <20240808-kasan-tsbrcu-v7-0-0d0590c54ae6@google.com>
In-Reply-To: <20240808-kasan-tsbrcu-v7-0-0d0590c54ae6@google.com>
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
 David Sterba <dsterba@suse.cz>, Jann Horn <jannh@google.com>, 
 syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=ed25519-sha256; t=1723141862; l=18413;
 i=jannh@google.com; s=20240730; h=from:subject:message-id;
 bh=z5bSbkCj94GnaiGWLuFtbBdFDDwX9unmguhfbktiJvc=;
 b=F3SfVhr1qcLR3GRRnzcuAVLHRy01xrdo1AoS8KU+jo1CF/QYoWlNQZLZ6W4V4qE2pTTWu7r02
 hwX2Os8yKMnBrtpeeea2x3qURQee3aaAPWN8/zRKGg9MyojK3xocauf
X-Developer-Key: i=jannh@google.com; a=ed25519;
 pk=AljNtGOzXeF6khBXDJVVvwSEkVDGnnZZYqfWhP1V+C8=
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=JK2AG4Rx;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52f as
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

Tested-by: syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Acked-by: Marco Elver <elver@google.com>
Signed-off-by: Jann Horn <jannh@google.com>
---
 include/linux/kasan.h | 17 +++++++----
 mm/Kconfig.debug      | 32 +++++++++++++++++++++
 mm/kasan/common.c     | 11 +++----
 mm/kasan/kasan_test.c | 46 +++++++++++++++++++++++++++++
 mm/slab_common.c      | 12 ++++++++
 mm/slub.c             | 80 +++++++++++++++++++++++++++++++++++++++++++++------
 6 files changed, 179 insertions(+), 19 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 1570c7191176..00a3bf7c0d8f 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -193,40 +193,44 @@ static __always_inline bool kasan_slab_pre_free(struct kmem_cache *s,
 {
 	if (kasan_enabled())
 		return __kasan_slab_pre_free(s, object, _RET_IP_);
 	return false;
 }
 
-bool __kasan_slab_free(struct kmem_cache *s, void *object, bool init);
+bool __kasan_slab_free(struct kmem_cache *s, void *object, bool init,
+		       bool still_accessible);
 /**
  * kasan_slab_free - Poison, initialize, and quarantine a slab object.
  * @object: Object to be freed.
  * @init: Whether to initialize the object.
+ * @still_accessible: Whether the object contents are still accessible.
  *
  * This function informs that a slab object has been freed and is not
- * supposed to be accessed anymore, except for objects in
- * SLAB_TYPESAFE_BY_RCU caches.
+ * supposed to be accessed anymore, except when @still_accessible is set
+ * (indicating that the object is in a SLAB_TYPESAFE_BY_RCU cache and an RCU
+ * grace period might not have passed yet).
  *
  * For KASAN modes that have integrated memory initialization
  * (kasan_has_integrated_init() == true), this function also initializes
  * the object's memory. For other modes, the @init argument is ignored.
  *
  * This function might also take ownership of the object to quarantine it.
  * When this happens, KASAN will defer freeing the object to a later
  * stage and handle it internally until then. The return value indicates
  * whether KASAN took ownership of the object.
  *
  * This function is intended only for use by the slab allocator.
  *
  * @Return true if KASAN took ownership of the object; false otherwise.
  */
 static __always_inline bool kasan_slab_free(struct kmem_cache *s,
-						void *object, bool init)
+						void *object, bool init,
+						bool still_accessible)
 {
 	if (kasan_enabled())
-		return __kasan_slab_free(s, object, init);
+		return __kasan_slab_free(s, object, init, still_accessible);
 	return false;
 }
 
 void __kasan_kfree_large(void *ptr, unsigned long ip);
 static __always_inline void kasan_kfree_large(void *ptr)
 {
@@ -416,13 +420,14 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
 
 static inline bool kasan_slab_pre_free(struct kmem_cache *s, void *object)
 {
 	return false;
 }
 
-static inline bool kasan_slab_free(struct kmem_cache *s, void *object, bool init)
+static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
+				   bool init, bool still_accessible)
 {
 	return false;
 }
 static inline void kasan_kfree_large(void *ptr) {}
 static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
 				   gfp_t flags, bool init)
diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
index afc72fde0f03..41a58536531d 100644
--- a/mm/Kconfig.debug
+++ b/mm/Kconfig.debug
@@ -67,12 +67,44 @@ config SLUB_DEBUG_ON
 	  equivalent to specifying the "slab_debug" parameter on boot.
 	  There is no support for more fine grained debug control like
 	  possible with slab_debug=xxx. SLUB debugging may be switched
 	  off in a kernel built with CONFIG_SLUB_DEBUG_ON by specifying
 	  "slab_debug=-".
 
+config SLUB_RCU_DEBUG
+	bool "Enable UAF detection in TYPESAFE_BY_RCU caches (for KASAN)"
+	depends on SLUB_DEBUG
+	# SLUB_RCU_DEBUG should build fine without KASAN, but is currently useless
+	# without KASAN, so mark it as a dependency of KASAN for now.
+	depends on KASAN
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
 	select DEBUG_FS
 	select STACKTRACE
 	select STACKDEPOT
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index f26bbc087b3b..ed4873e18c75 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -227,43 +227,44 @@ static bool check_slab_allocation(struct kmem_cache *cache, void *object,
 	}
 
 	return false;
 }
 
 static inline void poison_slab_object(struct kmem_cache *cache, void *object,
-				      bool init)
+				      bool init, bool still_accessible)
 {
 	void *tagged_object = object;
 
 	object = kasan_reset_tag(object);
 
 	/* RCU slabs could be legally used after free within the RCU period. */
-	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
+	if (unlikely(still_accessible))
 		return;
 
 	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
 			KASAN_SLAB_FREE, init);
 
 	if (kasan_stack_collection_enabled())
 		kasan_save_free_info(cache, tagged_object);
 }
 
 bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
 				unsigned long ip)
 {
 	if (!kasan_arch_is_ready() || is_kfence_address(object))
 		return false;
 	return check_slab_allocation(cache, object, ip);
 }
 
-bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init)
+bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
+		       bool still_accessible)
 {
 	if (!kasan_arch_is_ready() || is_kfence_address(object))
 		return false;
 
-	poison_slab_object(cache, object, init);
+	poison_slab_object(cache, object, init, still_accessible);
 
 	/*
 	 * If the object is put into quarantine, do not let slab put the object
 	 * onto the freelist for now. The object's metadata is kept until the
 	 * object gets evicted from quarantine.
 	 */
@@ -515,13 +516,13 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 
 	slab = folio_slab(folio);
 
 	if (check_slab_allocation(slab->slab_cache, ptr, ip))
 		return false;
 
-	poison_slab_object(slab->slab_cache, ptr, false);
+	poison_slab_object(slab->slab_cache, ptr, false, false);
 	return true;
 }
 
 void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip)
 {
 	struct slab *slab;
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 7b32be2a3cf0..567d33b493e2 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -993,12 +993,57 @@ static void kmem_cache_invalid_free(struct kunit *test)
 	 */
 	kmem_cache_free(cache, p);
 
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
+	/*
+	 * We should still be allowed to access the object at this point because
+	 * the cache is SLAB_TYPESAFE_BY_RCU and we've been in an RCU read-side
+	 * critical section since before the kmem_cache_free().
+	 */
+	READ_ONCE(*p);
+
+	rcu_read_unlock();
+
+	/*
+	 * Wait for the RCU callback to execute; after this, the object should
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
 {
 	struct kmem_cache *cache;
 
@@ -1934,12 +1979,13 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(workqueue_uaf),
 	KUNIT_CASE(kfree_via_page),
 	KUNIT_CASE(kfree_via_phys),
 	KUNIT_CASE(kmem_cache_oob),
 	KUNIT_CASE(kmem_cache_double_free),
 	KUNIT_CASE(kmem_cache_invalid_free),
+	KUNIT_CASE(kmem_cache_rcu_uaf),
 	KUNIT_CASE(kmem_cache_double_destroy),
 	KUNIT_CASE(kmem_cache_accounted),
 	KUNIT_CASE(kmem_cache_bulk),
 	KUNIT_CASE(mempool_kmalloc_oob_right),
 	KUNIT_CASE(mempool_kmalloc_large_oob_right),
 	KUNIT_CASE(mempool_slab_oob_right),
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 40b582a014b8..d266fa41e648 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -582,12 +582,24 @@ void kmem_cache_destroy(struct kmem_cache *s)
 	rcu_set = s->flags & SLAB_TYPESAFE_BY_RCU;
 
 	s->refcount--;
 	if (s->refcount)
 		goto out_unlock;
 
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
 	err = shutdown_cache(s);
 	WARN(err, "%s %s: Slab cache still has objects when called from %pS",
 	     __func__, s->name, (void *)_RET_IP_);
 out_unlock:
 	mutex_unlock(&slab_mutex);
 	cpus_read_unlock();
diff --git a/mm/slub.c b/mm/slub.c
index 0c98b6a2124f..eb68f4a69f59 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2197,45 +2197,81 @@ static inline bool memcg_slab_post_alloc_hook(struct kmem_cache *s,
 static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
 					void **p, int objects)
 {
 }
 #endif /* CONFIG_MEMCG */
 
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
+	/* Are the object contents still accessible? */
+	bool still_accessible = (s->flags & SLAB_TYPESAFE_BY_RCU) && !after_rcu_delay;
+
 	kmemleak_free_recursive(x, s->flags);
 	kmsan_slab_free(s, x);
 
 	debug_check_no_locks_freed(x, s->object_size);
 
 	if (!(s->flags & SLAB_DEBUG_OBJECTS))
 		debug_check_no_obj_freed(x, s->object_size);
 
 	/* Use KCSAN to help debug racy use-after-free. */
-	if (!(s->flags & SLAB_TYPESAFE_BY_RCU))
+	if (!still_accessible)
 		__kcsan_check_access(x, s->object_size,
 				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
 
 	if (kfence_free(x))
 		return false;
 
 	/*
 	 * Give KASAN a chance to notice an invalid free operation before we
 	 * modify the object.
 	 */
 	if (kasan_slab_pre_free(s, x))
 		return false;
 
+#ifdef CONFIG_SLUB_RCU_DEBUG
+	if (still_accessible) {
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
 	 * kept together to avoid discrepancies in behavior.
 	 *
 	 * The initialization memset's clear the object and the metadata,
@@ -2253,42 +2289,42 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
 			memset(kasan_reset_tag(x), 0, s->object_size);
 		rsize = (s->flags & SLAB_RED_ZONE) ? s->red_left_pad : 0;
 		memset((char *)kasan_reset_tag(x) + inuse, 0,
 		       s->size - inuse - rsize);
 	}
 	/* KASAN might put x into memory quarantine, delaying its reuse. */
-	return !kasan_slab_free(s, x, init);
+	return !kasan_slab_free(s, x, init, still_accessible);
 }
 
 static __fastpath_inline
 bool slab_free_freelist_hook(struct kmem_cache *s, void **head, void **tail,
 			     int *cnt)
 {
 
 	void *object;
 	void *next = *head;
 	void *old_tail = *tail;
 	bool init;
 
 	if (is_kfence_address(next)) {
-		slab_free_hook(s, next, false);
+		slab_free_hook(s, next, false, false);
 		return false;
 	}
 
 	/* Head and tail of the reconstructed freelist */
 	*head = NULL;
 	*tail = NULL;
 
 	init = slab_want_init_on_free(s);
 
 	do {
 		object = next;
 		next = get_freepointer(s, object);
 
 		/* If object's reuse doesn't have to be delayed */
-		if (likely(slab_free_hook(s, object, init))) {
+		if (likely(slab_free_hook(s, object, init, false))) {
 			/* Move object to the new freelist */
 			set_freepointer(s, object, *head);
 			*head = object;
 			if (!*tail)
 				*tail = object;
 		} else {
@@ -4474,40 +4510,68 @@ static __fastpath_inline
 void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 	       unsigned long addr)
 {
 	memcg_slab_free_hook(s, slab, &object, 1);
 	alloc_tagging_slab_free_hook(s, slab, &object, 1);
 
-	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
+	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), false)))
 		do_slab_free(s, slab, object, object, 1, addr);
 }
 
 #ifdef CONFIG_MEMCG
 /* Do not inline the rare memcg charging failed path into the allocation path */
 static noinline
 void memcg_alloc_abort_single(struct kmem_cache *s, void *object)
 {
-	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
+	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), false)))
 		do_slab_free(s, virt_to_slab(object), object, object, 1, _RET_IP_);
 }
 #endif
 
 static __fastpath_inline
 void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
 		    void *tail, void **p, int cnt, unsigned long addr)
 {
 	memcg_slab_free_hook(s, slab, p, cnt);
 	alloc_tagging_slab_free_hook(s, slab, p, cnt);
 	/*
 	 * With KASAN enabled slab_free_freelist_hook modifies the freelist
 	 * to remove objects, whose reuse must be delayed.
 	 */
 	if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt)))
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
+	kfree(delayed_free);
+
+	if (WARN_ON(is_kfence_address(object)))
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
+	do_slab_free(s, slab, object, object, 1, _THIS_IP_);
+}
+#endif /* CONFIG_SLUB_RCU_DEBUG */
+
 #ifdef CONFIG_KASAN_GENERIC
 void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
 {
 	do_slab_free(cache, virt_to_slab(x), x, x, 1, addr);
 }
 #endif

-- 
2.46.0.76.ge559c4bf1a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240808-kasan-tsbrcu-v7-2-0d0590c54ae6%40google.com.
