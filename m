Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBJXP3C2QMGQE4IDSN2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DF7894D3AC
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2024 17:37:11 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2ef2a44c3dfsf20554961fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2024 08:37:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723217831; cv=pass;
        d=google.com; s=arc-20160816;
        b=ARjFm6QvVJrH/fyZu4PYQwozLbFedr8/UNHcLT7xRpZOSP0MR0SkJW6nQ16iD0DAgi
         P5n0DAlXHq83Fc9boqDUFdVOVb+/+r/t/a7YMTpyxLn4oVR/mpDKCL14mSsEUo71UDzG
         sTm+t9yfjOvzkMYhG8ryyz7KAzlKnuLczphdT/qjDvr5+HvolQ8hXwfQ5/6RsOTSqj0Z
         t5IOB538XDDHNErmhK8AN7WWE03LmkCh2C2Huq29A0Wd9p7ChmEYI9J/RIeDZRHTA3TW
         rp9DgqjT+tqHIDV1BZev/vGiWHFEiMKDUUa/wXixSDZctIscbqX6FKpxP4+tpuXeW3jy
         vA6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=ZSi+67uBhJgJa6IyQxMSNmtu86wT0ffLdLoxR9jKrI4=;
        fh=552Rkt0QZVwI0IqzaawYVKiOZu0qCiIMikkE+iXZ5VQ=;
        b=kzECeMzYc2De/D0z7Pq+hZhwSg1XoNfFXDkuX+BkmPBNItGnVh2/FcVN1B6rSBKKfE
         MrVzqFyUZ8v53SM0Fkmgwt6UMMa2pjM+vLcBSHh3pONcM8m0YkGrBOt1ViBh7iT4JVQZ
         rtPJtz5sT9YrGZUo/zhvMMgReWEUiO7I8lOiQz9QmbU7ykPmXgfzEluvKi/4HrrF68e6
         U6J+v7cmWfr960uBWjmAE7/emWQ8sQIqEp/iOYjEznrW3rMHYtCGxA+WnShrHFUaqH7S
         5W3OgZ316bEp/FrPPetzsILOzqWcjmlzk50VZmXb+FewDzHGyW3WasdMpbWfS6SOY8LS
         xYBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TDwj+JXG;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723217831; x=1723822631; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ZSi+67uBhJgJa6IyQxMSNmtu86wT0ffLdLoxR9jKrI4=;
        b=aVJz+99XC+M5EW2GWrD2BGT47IZ9mbR+Iq5t7t44Mg1BgmSHL7FNjzpIF981EcAGDJ
         EPuZmFDxkYpqUVEEw2efhdKrM7flt1tdHIMMm087OGf2t3cY8rA1uiO1salRjf4QAX1+
         YQvifd6pTeFGGOExmnyyovJNcCFY8OzT9OF1dBMVj9Zz3qJzpmZ3nwHO44kIfkheRPoF
         JTeBWHd16EYTC2QYv9fz3CVRFSGZkgYnRPim89YnFs676wO/zHpVJy9Qf35TSGVZvOf8
         lOmq5N4YcWG0leqseitjtZAwP3KE2uflCxONXQqhb6FIi1+1aMqqi8gnkB073ydOPnOZ
         5WjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723217831; x=1723822631;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZSi+67uBhJgJa6IyQxMSNmtu86wT0ffLdLoxR9jKrI4=;
        b=HLqr8n0n8STNUS3ehCrxsdgXJD2BlIq2QOHy5orGJgz9L1yRB0x6GxhlCr//Yql7J0
         6ijlmrx5/AdW6eYkAxENw9ShQXmrc8K6h4DK+7cVVFIbcolb+H65IBbgDxR1vha+9DAu
         95xGcfOVm+mgQNhIERB/sc/cgzIexrNN//5ayRIe0xMUO0uajaeceasYMW0EXkXXCssa
         +EuibFdIxZOSpyeaX03oorW8PEenWQfwu7yUiT3+GukYYz++akgcgHHxd9XKajUwoLB0
         PS7Rm4hzVv37cdSFj4s3JsirSmkCSiz7ibRgSJWzLu/8SBNahW2Nsu8GglAbua9UE3re
         HekA==
X-Forwarded-Encrypted: i=2; AJvYcCXnslNW3Ab2EfCPOFGiUia9tLN7JNIq/vevHtpkQEwGbrMTE0CQ3kjYRtsML13zEn9BFYlz6A==@lfdr.de
X-Gm-Message-State: AOJu0YwC2EvuH1tS5z4sRZh6MFwyFyXdmRCMAFYy21nfP5C1DHhzScH8
	KkcVImnyj5rV3XUXamaAdX5/Y8IVnJvtKuJOg9R95tJ8EkL+MzE5
X-Google-Smtp-Source: AGHT+IEK4qDf1YjiwuxJnVPGRUNHCXm7cw+oR25lvgi+l4zYByYSP8MlO8ZMTIJs/rWbUHKe3cXTWg==
X-Received: by 2002:a2e:5109:0:b0:2ee:7c12:7b36 with SMTP id 38308e7fff4ca-2f1a6d0e42dmr16276151fa.19.1723217830303;
        Fri, 09 Aug 2024 08:37:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:1f12:0:b0:2ef:256c:a265 with SMTP id 38308e7fff4ca-2f19bc5f278ls6054971fa.2.-pod-prod-09-eu;
 Fri, 09 Aug 2024 08:37:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV5aDhg4Jypjf4qA2pdOfwTc0d0thpECDXfDtU4lZ6i4J+tn9O0pSFAFw7/ChMtSk2WRm8rhEi9DVw=@googlegroups.com
X-Received: by 2002:a05:651c:221e:b0:2ef:2450:81f3 with SMTP id 38308e7fff4ca-2f1a6d00270mr16506691fa.6.1723217828052;
        Fri, 09 Aug 2024 08:37:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723217828; cv=none;
        d=google.com; s=arc-20160816;
        b=0d5yQ1NGxBFNP0evNrzru5nzwxPyQ4TFArF6ZOylEZZN9ONH5INUOV6MuXh+Gqeaah
         DxKmawkRkr50i6RCE60jy9LL0U++NLtfnGwOhY7hcHHxyQ2wB9x+WULM5bHkMwIknmtH
         YS++bGteK5AS9S8eQlA68SlaTe0cr+ShK9l8E1VCrRxM0AW6FRrVTqZbGd6OpGUt4Iv0
         jnxxmFIAbQIzayREkpF/sbBdFsbXJqGVwJRjx7q/VcMKuwxSnkXh76hRmBMOez3xZFqZ
         qYgIZY/BTq2aHK0zwrt1JY6bnf5kvUGDUTvNCzzyEF9zz/XTV5XttR0PPdttsZ4xB+Lc
         cXJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=04hH29wKOUh4zO671E3nNC0Fq21jgPwt4FhdP1F+2dI=;
        fh=1Ie32+ovaWmQQBzFPLuKN7ymXwbOZPHi0a56rDiOrKI=;
        b=vwN7i50Eg1Q+JCt8ubvmqiaM0KJ2K/mjTif7Kad2RnRKLLgvac9VWnbZe4Lc11425L
         F9Ik1nImP8lQU553pK0k+LDJSgmD2CXUgeC++TZGw0zAVHfDuqaI1usFZitPJIK3qt9K
         eX5yeUkaHbttu68VwBJA6Vz6ZV8etAtb557o9nAHZc6rRi6igD/SbqYVXOxqkdIuEEN5
         Ls9U/0qYMsU+9khPjZziwsBpQzkxdK+Uu9VublhOzUGe3UjYc0bn9y1cQ4YO8Wknou/g
         KXHYgY+MjF0FC1CiR3+Mf8ehmjlnVUmUjjdo/p6Bqc0KMn7v01pM+bbj7+ysASusEHn6
         J9+Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TDwj+JXG;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f15e1677aasi3679641fa.1.2024.08.09.08.37.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Aug 2024 08:37:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-427fc9834deso65825e9.0
        for <kasan-dev@googlegroups.com>; Fri, 09 Aug 2024 08:37:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVOjC3jR7kM3nAHiU/WPkISc0J3vyFYa7psFLfz8FxsCOPrVSk7DyNbRha1gZLIdsxpZ57vOret/eA=@googlegroups.com
X-Received: by 2002:a05:600c:3d0e:b0:426:8ee5:3e9c with SMTP id 5b1f17b1804b1-429c170502fmr1680895e9.6.1723217826322;
        Fri, 09 Aug 2024 08:37:06 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:1cbc:ea05:2b3e:79e6])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-42905971d06sm131370035e9.19.2024.08.09.08.37.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Aug 2024 08:37:05 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 09 Aug 2024 17:36:55 +0200
Subject: [PATCH v8 1/2] kasan: catch invalid free before SLUB reinitializes
 the object
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240809-kasan-tsbrcu-v8-1-aef4593f9532@google.com>
References: <20240809-kasan-tsbrcu-v8-0-aef4593f9532@google.com>
In-Reply-To: <20240809-kasan-tsbrcu-v8-0-aef4593f9532@google.com>
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
 David Sterba <dsterba@suse.cz>, Jann Horn <jannh@google.com>
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=ed25519-sha256; t=1723217820; l=8980;
 i=jannh@google.com; s=20240730; h=from:subject:message-id;
 bh=6bMIRMeh/1RVCY2STakwRPDtPkfm0ed8OAz2i9tHk/A=;
 b=cgEyMnkYj8fG04Ew4yST4NXZcj+IbXd0To9wuYcsObX2VYDJHqQIXKwsJaH/bAV6w1Fth+GPk
 VGb/0LWxPB2Cf5nOFT6Ov7qUiEcbqCHMirvJ0P2oCCgijDCf5jxeXGE
X-Developer-Key: i=jannh@google.com; a=ed25519;
 pk=AljNtGOzXeF6khBXDJVVvwSEkVDGnnZZYqfWhP1V+C8=
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=TDwj+JXG;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as
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
2.46.0.76.ge559c4bf1a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240809-kasan-tsbrcu-v8-1-aef4593f9532%40google.com.
