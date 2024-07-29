Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBXGLT62QMGQELXUDACQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id ADD5A93FDD3
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 20:56:29 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2ef1b1f93basf37553001fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 11:56:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722279389; cv=pass;
        d=google.com; s=arc-20160816;
        b=YMHnmhlH//6Zzh+asCOUUFO0JKMM/nSxK3dypC022dr5B4WgaYua38WSsA3mniMFnu
         QRa6+Vk/BJk2yDyRCfIQB6xpboObXeulNQTJTXdzvL5VQezQXGqH86ZwUgVSnCN2vkG7
         4VMOeUTuKviiy/NdAO86tXhTTGGS/8uh2PLSbVdVpFa4qeAkhaI2KmbCSBt7+cObCYBy
         litEOb2al8Qp2EQc3bwYSkv4+wjsoFSZv/tLgmqkaR44gv7IZRAZzEEXNhnHTWLDQQSJ
         Ym4USG4ebacauQqJgGzMQwIntyvpLRjtyl11teV6bADhRw475cB/EfIFuqpR9HDDYPdU
         a8sQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=nmuCjW2kvGrh0TPPV5iyg9qBA0oLEjQ10jizZSbYgBY=;
        fh=YRokNdoY4l+bBnRRKDmkgXmv+wTZW3e6wN0fXggrgCM=;
        b=cK/3ha5awlMEDnZDOmTyLgC5sFfJKVP99mddRElIH3pdLfXkBECD4S8utLlCsdqzao
         eJCvsqwLFRaU8NTG2RaaOJDCkSaWyxugvYeiY1UxTmc6CkLHQp9O8uw9G0ahHNob8agY
         9HEjm1CfCrxDi7denTT94VnGmflEycRgVQ7g6NeROvMNXxcLIdiHbDWJwYGBr7HSHLDF
         f6dR53SRiYy9IE5iyoDq8k+qKsoQAdEXyuQddEmV+4ZB0vHjyYerT5ayWjtCifA1JFqP
         rGmymZ+X++e9pssJBibTSkblCBh70ElQ6s6XGLCOHQHbd2Rix06iYVPazsjWdZGkWLSG
         KU7A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LmAJ1xF+;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722279389; x=1722884189; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=nmuCjW2kvGrh0TPPV5iyg9qBA0oLEjQ10jizZSbYgBY=;
        b=qhdHJGbQH1IfN2e8Ogm1UVFO7nTWbduPujeAJ4YxEUEEJbMygV1jL/0Qv7KA4nVwYQ
         8MXa+6ywCqhSPRatzQ96tuBIdAUzbmbhcZYt4FL/bYehl83m56unGaT5LopldSLPCBIM
         vKvb3wjL72KR5fsc/W3QP2oZ5yLUaZsLlK6FF7uFUYMPAKYZj4YNUuW+gn+h3Ng88Ko6
         K4JQ8F8OCH5pzoUU7zmngqKNm70aYjG56fOnqAmY6B2lQMlcvkIoSNNc1A1JMicoXkOP
         2uP1xPemNU5f43q+VFgk7Wf88wA+0nrQsTy+XWjzuXZjEGE1JwhnGB2Qurs1W4Ki29t7
         sn6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722279389; x=1722884189;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nmuCjW2kvGrh0TPPV5iyg9qBA0oLEjQ10jizZSbYgBY=;
        b=E5HCfgy7s/rZ01WZvTO826Hbg/JDcclYIa6VAJXChpGkyBojzJAHzOvD5UOQ0Bs0RP
         apxpnmv6sLbJXhLMuMQr9IPWNOz78D1dy79CdJwwMBztYgS12BW31y1z6sMcou2VJvIO
         d7BA8Lp6Ugs+6LOelfUpLo+cYFREuUW4n6yIUApdM0Ri0Yw90l6OBqhn013PicTYPfhu
         7TO/VDDwW8m8Oh+eTmBj4YASVaI4X6sg1IJ9/U3WvRoNlgMQKu0GK3Kye1mOz+cwsNcB
         euKAPOVik1NzQ1vR5Ag9BfEBAT1gdiqfh96LdYBvBW71/9eZd2vIrsTKK+ntQsUbUdic
         0AqA==
X-Forwarded-Encrypted: i=2; AJvYcCWh8KX3lP9ycVNgV/c47etJSskToM1YYAvcQBtJvGH9cFn9BeOQb7w01Z7QV2eEbrG8QNL568DBOqr9kNqk9RLniNET/AFM8w==
X-Gm-Message-State: AOJu0YyRNq3mlfHav6zgJ5wL1d7hUdSOaL4qqka7eu9MXtNYjtWlR9Wm
	gNrdmWe7kBxkfJaVRTFO6ux/o/Jb7+s5XHK9ZMJmF+pWVJxhAr16
X-Google-Smtp-Source: AGHT+IE+YknIib92naIZQ3M/kiKzb0KpUcEUTswy786L3nb4s+NP/L6Nzxqs2PZJgcEx2YC6h67Yyw==
X-Received: by 2002:a2e:b055:0:b0:2f0:1a44:cdea with SMTP id 38308e7fff4ca-2f12edd604cmr54135611fa.26.1722279388442;
        Mon, 29 Jul 2024 11:56:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2110:b0:2ef:1eb3:473b with SMTP id
 38308e7fff4ca-2f03a2b4be5ls22708451fa.0.-pod-prod-02-eu; Mon, 29 Jul 2024
 11:56:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVWpBdOit2Uyk6eCJOk45lUbPSByhBqyyl0zPpczCxNmTd/HWnDB0RJJXxyAlAZgm72JysbvkAxPZYh/VRMA6QJHMDelyPKoNzB+Q==
X-Received: by 2002:a2e:a306:0:b0:2ef:2ac1:6d2b with SMTP id 38308e7fff4ca-2f12edd531cmr54025961fa.24.1722279386019;
        Mon, 29 Jul 2024 11:56:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722279386; cv=none;
        d=google.com; s=arc-20160816;
        b=u1CftmxpV7qfnKV/3Vh+8iwlCXtKpnljBl1Gr4n7B8vs4LhqvC5fLZ1Rnc8hfi50Jp
         P2TsNGWtY9y61n7/z2Rrc4Pwv3EohrUqfrKjyMLytqsgfXhhq/Tr+RgGOxtU0/lhO91j
         tUwf1VKghyu2lreTe/bMHG3ezjE94MrpYslrD+wAaKrFxCqgwyChjhNfh1DjJAwF3NhI
         JcHajBINiw8rpnl2ZqepkZZhLjW/qB7r3B+56mDBWXNksR9f/KGz1X88Lf270tJYWZ9m
         Oo1fv+D77eHvwWBe8eiIB151leAGmxAUz2Qdef4OgWrLZzSxl2lNCkd99i+uTOV1ndyH
         e/yQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=cvKURe6uz2KBoHo6CYpr3vofSMW71BLVp5QpK4A+tK4=;
        fh=O4GgpWDRqGnKEMnxO5p83iLwZNdB7/W1e8+3I9LijRk=;
        b=lImHCnqVTxLiMcq9NXdtyUnYH7JXrEkJzWB+oVVuV9zGMYkQG6hDAiBNtVcc2mLa4H
         Hv0jE6mpJiGU7O3J9bG4iQachwbKz1cVCtOCxLrjnWXo7IK3Nrzur78NcmvTtSfa8t3z
         P7sX4FeKbkrFkMCSu1yfMvRW3q37z89iAV4QPJEu+wFUruMy4mpWu7YBGd6Mkh3L+Gs+
         elKIl0gu6HiCk9ByC8t6ksNamREw7RgXP6z+KpAk5JyxEXdSGnHG5CCTdCv99BqG5wzQ
         yR+YrSqiHecoUP+Qb1m4TCXyJJcdcZR25mv1jDEvSSf+YcdhvnoWM2IifHPuIWM3kPb+
         Tfqw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LmAJ1xF+;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f03cf0c978si2070261fa.2.2024.07.29.11.56.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jul 2024 11:56:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id 4fb4d7f45d1cf-5a869e3e9dfso3097a12.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Jul 2024 11:56:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX6LaioMl7J0QgdH7lm6EBGJzdGWU5Ynhvnf6tH+udk3I2ofuJDw+GVr8FPcEdUkI9rYy7mr1bYbzWUuMSioyfX6Kf3b3PtrdkxGA==
X-Received: by 2002:a05:6402:1ec7:b0:5aa:19b1:ffc7 with SMTP id 4fb4d7f45d1cf-5b40b12a89fmr71108a12.2.1722279384655;
        Mon, 29 Jul 2024 11:56:24 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:a1f4:32c9:4fcd:ec6c])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-36b367d9bd7sm12835010f8f.34.2024.07.29.11.56.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Jul 2024 11:56:24 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Jul 2024 20:56:12 +0200
Subject: [PATCH v4 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240729-kasan-tsbrcu-v4-2-57ec85ef80c6@google.com>
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
 header.i=@google.com header.s=20230601 header.b=LmAJ1xF+;       spf=pass
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
 include/linux/kasan.h | 11 +++++---
 mm/Kconfig.debug      | 30 ++++++++++++++++++++
 mm/kasan/common.c     | 11 ++++----
 mm/kasan/kasan_test.c | 46 +++++++++++++++++++++++++++++++
 mm/slab_common.c      | 12 ++++++++
 mm/slub.c             | 76 +++++++++++++++++++++++++++++++++++++++++++++------
 6 files changed, 169 insertions(+), 17 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 34cb7a25aacb..0b952e11c7a0 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -194,28 +194,30 @@ static __always_inline bool kasan_slab_pre_free(struct kmem_cache *s,
 {
 	if (kasan_enabled())
 		return __kasan_slab_pre_free(s, object, _RET_IP_);
 	return false;
 }
 
-bool __kasan_slab_free(struct kmem_cache *s, void *object, bool init);
+bool __kasan_slab_free(struct kmem_cache *s, void *object, bool init,
+		       bool after_rcu_delay);
 /**
  * kasan_slab_free - Possibly handle slab object freeing.
  * @object: Object to free.
  *
  * This hook is called from the slab allocator to give KASAN a chance to take
  * ownership of the object and handle its freeing.
  * kasan_slab_pre_free() must have already been called on the same object.
  *
  * @Return true if KASAN took ownership of the object; false otherwise.
  */
 static __always_inline bool kasan_slab_free(struct kmem_cache *s,
-						void *object, bool init)
+						void *object, bool init,
+						bool after_rcu_delay)
 {
 	if (kasan_enabled())
-		return __kasan_slab_free(s, object, init);
+		return __kasan_slab_free(s, object, init, after_rcu_delay);
 	return false;
 }
 
 void __kasan_kfree_large(void *ptr, unsigned long ip);
 static __always_inline void kasan_kfree_large(void *ptr)
 {
@@ -405,13 +407,14 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
 
 static inline bool kasan_slab_pre_free(struct kmem_cache *s, void *object)
 {
 	return false;
 }
 
-static inline bool kasan_slab_free(struct kmem_cache *s, void *object, bool init)
+static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
+				   bool init, bool after_rcu_delay)
 {
 	return false;
 }
 static inline void kasan_kfree_large(void *ptr) {}
 static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
 				   gfp_t flags, bool init)
diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
index afc72fde0f03..8e440214aac8 100644
--- a/mm/Kconfig.debug
+++ b/mm/Kconfig.debug
@@ -67,12 +67,42 @@ config SLUB_DEBUG_ON
 	  equivalent to specifying the "slab_debug" parameter on boot.
 	  There is no support for more fine grained debug control like
 	  possible with slab_debug=xxx. SLUB debugging may be switched
 	  off in a kernel built with CONFIG_SLUB_DEBUG_ON by specifying
 	  "slab_debug=-".
 
+config SLUB_RCU_DEBUG
+	bool "Enable UAF detection in TYPESAFE_BY_RCU caches (for KASAN)"
+	depends on SLUB_DEBUG
+	depends on KASAN # not a real dependency; currently useless without KASAN
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
index 8cede1ce00e1..0769b23a9d5f 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -227,43 +227,44 @@ static bool check_slab_allocation(struct kmem_cache *cache, void *object,
 	}
 
 	return false;
 }
 
 static inline void poison_slab_object(struct kmem_cache *cache, void *object,
-				      bool init)
+				      bool init, bool after_rcu_delay)
 {
 	void *tagged_object = object;
 
 	object = kasan_reset_tag(object);
 
 	/* RCU slabs could be legally used after free within the RCU period. */
-	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
+	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU) && !after_rcu_delay)
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
+		       bool after_rcu_delay)
 {
 	if (!kasan_arch_is_ready() || is_kfence_address(object))
 		return false;
 
-	poison_slab_object(cache, object, init);
+	poison_slab_object(cache, object, init, after_rcu_delay);
 
 	/*
 	 * If the object is put into quarantine, do not let slab put the object
 	 * onto the freelist for now. The object's metadata is kept until the
 	 * object gets evicted from quarantine.
 	 */
@@ -517,13 +518,13 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 
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
index 1560a1546bb1..19511e34017b 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -447,12 +447,24 @@ static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work)
 		kmem_cache_release(s);
 	}
 }
 
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
 
 	if (__kmem_cache_shutdown(s) != 0)
 		return -EBUSY;
 
diff --git a/mm/slub.c b/mm/slub.c
index 34724704c52d..b5a05234c5d1 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2141,45 +2141,78 @@ static inline bool memcg_slab_post_alloc_hook(struct kmem_cache *s,
 static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
 					void **p, int objects)
 {
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
 
 	debug_check_no_locks_freed(x, s->object_size);
 
 	if (!(s->flags & SLAB_DEBUG_OBJECTS))
 		debug_check_no_obj_freed(x, s->object_size);
 
 	/* Use KCSAN to help debug racy use-after-free. */
-	if (!(s->flags & SLAB_TYPESAFE_BY_RCU))
+	if (!(s->flags & SLAB_TYPESAFE_BY_RCU) || after_rcu_delay)
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
 	 * kept together to avoid discrepancies in behavior.
 	 *
 	 * The initialization memset's clear the object and the metadata,
@@ -2197,42 +2230,42 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
 			memset(kasan_reset_tag(x), 0, s->object_size);
 		rsize = (s->flags & SLAB_RED_ZONE) ? s->red_left_pad : 0;
 		memset((char *)kasan_reset_tag(x) + inuse, 0,
 		       s->size - inuse - rsize);
 	}
 	/* KASAN might put x into memory quarantine, delaying its reuse. */
-	return !kasan_slab_free(s, x, init);
+	return !kasan_slab_free(s, x, init, after_rcu_delay);
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
@@ -4439,40 +4472,67 @@ static __fastpath_inline
 void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 	       unsigned long addr)
 {
 	memcg_slab_free_hook(s, slab, &object, 1);
 	alloc_tagging_slab_free_hook(s, slab, &object, 1);
 
-	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
+	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), false)))
 		do_slab_free(s, slab, object, object, 1, addr);
 }
 
 #ifdef CONFIG_MEMCG_KMEM
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
+	do_slab_free(s, slab, object, object, 1, _THIS_IP_);
+	kfree(delayed_free);
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
2.46.0.rc1.232.g9752f9e123-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240729-kasan-tsbrcu-v4-2-57ec85ef80c6%40google.com.
