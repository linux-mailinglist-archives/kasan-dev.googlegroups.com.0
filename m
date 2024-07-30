Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBPMSUO2QMGQELSQZLAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id A065A941035
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 13:06:38 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-428076fef5dsf25769955e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 04:06:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722337598; cv=pass;
        d=google.com; s=arc-20160816;
        b=N2kVyCsSvefVwXXOIvWwYkWG87O7CllMpub3aOPnDoac/Et7gzTYUwJF9gTs3gJRFW
         BjvP2gOTKtcK6ope2EP6n1kh6IYftxZsDBCZ3F66C6yY5lYa6umMavd/2LCPxG18cULX
         3JLr4FXkEg7OoLkhOZx3R/uKY6TCpaCJDsLcJeF42kna396LLoV9bD1gR9WcDB2Mnmjv
         LxQDfisr3EgjoTsE+uYMi4OJzsrjLhYb46sSo4l/py49hCrwnhZy5yrZcX451CBaSviN
         uIkK+nG4hT9cbGBz5nR6Oo4uJf6Xik5y3nGaDnXwRzKK/4f6V7au1D+W0fIZUryJqpJd
         tgYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=ccqRoI91Nb6qmrpRjtnqZSU/plinZj/SYM9e1B0eNuU=;
        fh=sKeSAQWu5TRUQ0NCwiA+uirJKpuruP8FO/sVbSH+z6g=;
        b=eyubBfdLgp++PuqaKffPW3VL6qxZF1Q4aRyWviPIgmV1jTwooqYoVIHrstZtImvfpv
         e0hJm9md8ognmZL9cVXIwnPNa7C1xMosjNPKqL2e+MNR3YRVoiFmxaF/4qq5d9EOASh7
         /2RX4TtE+M+F3h2xdrGSrW1n/arEDsxSnnSqAW6za94EMFdLQSndRNt/VVzx0UfDMgVb
         +STFKdsB1I93FML+T/rlJ3D8I18cHPIbJksBwlyjG20hmkcJCWsNuheV/9ItDXNG4/2A
         VuunHoXicSkb+RCN+2Ry0xd0Z1SCB6X1Zm0pt89De2yBcIVLs8QirmMokrZfsvKZepjy
         fhaA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Dk/FHdFS";
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722337598; x=1722942398; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ccqRoI91Nb6qmrpRjtnqZSU/plinZj/SYM9e1B0eNuU=;
        b=LK9M141jC2Q5ZtCtPPqgGFH6wpJ9nVQdPd+/hgoJ61v5PdCGTGlxezE1Tu/fqLBpBW
         B0KQ2hg0pxYG2pzB0mQLV/wCDOHto/Upke4o4DgIXHl/q1AL3IZigfGajpFbxFWZRSqn
         WDGLQO2zlRuInW2qm1bt087oUB7zPfzpjIqajmb4HP8C57pmx0vPFsn82SJnf4yzgYMd
         VuXkk7B0zEgVJFGDToN3MpSIEWz2teREkcxl9cs76Sci8SqCD+YVXvFraWeWN6upuLPs
         gI5xVbBSibHvbl/GdSCdp3d9nO+mW8fXXIZTVsE56wkzgXomtiowTWbQt0gjoDxD2CIZ
         0qVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722337598; x=1722942398;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ccqRoI91Nb6qmrpRjtnqZSU/plinZj/SYM9e1B0eNuU=;
        b=rQw+Q/QvqfaZ3V8szTStjL1NkxEAqnBx/IRGj0atATjeJmgIuvkR7S0w1InSt35AdH
         oH72RV6o91+DqjG3vtf2IqC3B9y9bB/eAotmbBJpCovyyCMSk3v1PHzSkUgf32195em/
         yu37TOoKMzVj4jOSFDWCQdZQcfeagJPCggiA13mYWhMJVCH7S9JhsRjQ0dveyqYnm0X3
         33TGqwpXVdS1afT2GEpS4NSoKprcLoy64VYvPXK2rV9eUbSN/GLyv/lWwW7ustCfVB70
         1ICNcor3+Q/Kxg+W6jPvPdVsiYPZZRLmw+5NbcySJ9WHq/pc6MNIOVjrkKy9x64+Ey4x
         6ZHw==
X-Forwarded-Encrypted: i=2; AJvYcCUlZ8LICXYCksX6PSQf0HWL6Wh9EDNK/4Kw0YaebBRmmGFrfc6HFjO/0xH6Gf4JcWdP70EGbqAD4Cd7XEuM9IWQqlSAu9lPKg==
X-Gm-Message-State: AOJu0Ywk656Mx9yIvqLIrObeteBEAwRqPcukqDcQx+F7cjX+A0izz7qI
	Jevk2O4cIg+wDX3Yr9YO8y+w0tbG1wTwj8uHPp62VYHs7Z9CpXVv
X-Google-Smtp-Source: AGHT+IHWRbEiIJQcyIUhNtxIJ3R3bIBmuchjJS0fnVe/J9/27v3MeXG0FaWmTK8degLQeCXy/yPxew==
X-Received: by 2002:a05:600c:5492:b0:426:5b3a:96c with SMTP id 5b1f17b1804b1-42811dcd245mr64130505e9.28.1722337597754;
        Tue, 30 Jul 2024 04:06:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3ca3:b0:426:6eba:e1f4 with SMTP id
 5b1f17b1804b1-4280386beabls25751185e9.0.-pod-prod-02-eu; Tue, 30 Jul 2024
 04:06:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXlZ2KmGsozS3YqBbnzgjIDmRSzUYpLNAFIM2EJm/tQ1y1SFCl9KFkGHomhQz8q0FCGEEnjHLoFKFhxLf442dpoSK4mTt14Tm5mgg==
X-Received: by 2002:a05:600c:450d:b0:427:d8f2:332 with SMTP id 5b1f17b1804b1-42811d6cb65mr65214935e9.7.1722337595831;
        Tue, 30 Jul 2024 04:06:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722337595; cv=none;
        d=google.com; s=arc-20160816;
        b=OwA1uudZ0RTw2JB1fmWwTQVun+wtkEAga4gBDSDJd7wFaAtHFMyWeZ4k6Y5m5cz812
         x/ma4fjaNNf8hx15xpAJjA97HnRLCBrnyoururFLVeZknzoQxorkbolosFqexoEWJq+X
         1MmjQ9j0lu0vX4ig/n7DPzk8BK+u5LfOM0y3q44fx/lhJt33ZkulOl7cPSx1T+7xih9R
         77eLvDuvn+YlmMiGw0w+69VqfsSlUzYJp6DPHbgNkyVUxz9vQqrJMuhoV1fHuI+VW8Pf
         E3te48Xuyq1tKtcqW1ohJK4E8cVDqxFA2lUzNjO0Pxur1CDsMN4Yhbdzq5xirlOesGVd
         fBew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=vmYnUldkyV8zW3ad+ul844E0nMNraotF/7viCO1++yg=;
        fh=LP74KScZKuShA3rlxuCJgASU/m76pfLeFD7CQ+Y3+8Q=;
        b=uIH2BumW1KUXDa1PxSg/Fh+Y3nWYXKumOOydH9jmsHCprBFFz78fb2WqjT7p2XSQBf
         94Ba4q8XCF1vjo7M/hi9jxuIPnACHCjEP1kSjxkcRzvBCwrceARfsKlo1+jqrEC2u53O
         c/cg31cGmWCJSaAc7Np+6uE+v1RQtgIsVYuqRHP9T/8m8+n5VF0Y320N6Uhu7kNpu1e+
         CWH0btBsAkIPrNg+L5tkiWB0lEdpNhjUs+fmEPdA8Cel+sTHxRKCOu7p5AEHBQIVda6m
         74TFQmeR2kIhyFC3S2D9uFIXMTnYSe2vwaoQeZtX6x1Upxb2M+/unPfmidB5OgP5xjUm
         86RQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Dk/FHdFS";
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x533.google.com (mail-ed1-x533.google.com. [2a00:1450:4864:20::533])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42824af9292si606365e9.1.2024.07.30.04.06.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Jul 2024 04:06:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::533 as permitted sender) client-ip=2a00:1450:4864:20::533;
Received: by mail-ed1-x533.google.com with SMTP id 4fb4d7f45d1cf-5a1b073d7cdso12918a12.0
        for <kasan-dev@googlegroups.com>; Tue, 30 Jul 2024 04:06:35 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUgssqFh2kiVM630QBoBuHrej9oHRurgdeV3suoUjN74OMOeVFh4jE+gXtB4udTqQ1YvQ2FSVc+vx2IjL00MNWgd3cCxW2s6n+KTA==
X-Received: by 2002:a05:6402:35c3:b0:5a0:d4ce:59a6 with SMTP id 4fb4d7f45d1cf-5b45f835dbbmr103010a12.2.1722337594577;
        Tue, 30 Jul 2024 04:06:34 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:be6a:cd70:bdf:6a62])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-36b36801828sm14371147f8f.65.2024.07.30.04.06.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Jul 2024 04:06:34 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 30 Jul 2024 13:06:04 +0200
Subject: [PATCH v5 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240730-kasan-tsbrcu-v5-2-48d3cbdfccc5@google.com>
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
 header.i=@google.com header.s=20230601 header.b="Dk/FHdFS";       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::533 as
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
index 40b582a014b8..df09066d56fe 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -539,12 +539,24 @@ static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work)
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
index 0c98b6a2124f..f0d0e3c30837 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2197,45 +2197,78 @@ static inline bool memcg_slab_post_alloc_hook(struct kmem_cache *s,
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
@@ -2253,42 +2286,42 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
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
@@ -4474,40 +4507,67 @@ static __fastpath_inline
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240730-kasan-tsbrcu-v5-2-48d3cbdfccc5%40google.com.
