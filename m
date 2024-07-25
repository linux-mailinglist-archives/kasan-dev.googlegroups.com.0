Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB7O7RG2QMGQEBCGVB3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1500B93C66F
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 17:32:15 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-428076fef5dsf5506155e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 08:32:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721921534; cv=pass;
        d=google.com; s=arc-20160816;
        b=U7NJqk18O+yeLqZPgN/L8led1H1Z3OoE3yAKxX2B/No3CVZqczH136VJUOmQzusCNG
         GV/df4EsI10rDvLzwHR3Kxcj2I88v1bVJWHhezH9D9fziSzp7+lwNS/K3aFsFEX1COqG
         dxzJ0K9zCwdAdeAUViF+wQOvuOlRW30P7Y3t4ilrmIRZAAm/ohyHy4fLtbCvF3dxhj2f
         cPy/l0qAVHYzQ1czRQs9vx/ro6CEiXryePJfCm4XA+8HJ7RMSwXovyV7n2dw59uRFWt2
         aTHDG0EaS/vwDMXqVVodJmZWAk5FKedO7GDUOLMIaL8jVG9SPQ34K6Lh/YBlEeaAjk2e
         5eIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=F8EpmNfmOIP3YPgNYTKu4MONkKVh7+WE1H3VRjWszIk=;
        fh=Dae64OjZ2yQ1CG40ffWDgR4qPJa2Kgq+yZ1UI/5nAyY=;
        b=SswemAdgk/38j7rGBKqfXN9t+aPPxr9PJdXigvz4DTmrkuGsWAjlOk1vAHR0XOtGXq
         YXWd5NFiZcJnfFPN72Kj5T2jli7yr4sSXHr98my4esUWY3eOTCi5aRePXONwTaTWANA4
         yo6AmDooLVtyTcHN7BsOZmg5bDQAULEkxAudf1i2JSLRxaT/5snJ+0mEbNMTJgK9ZyEz
         oLnc2Mp8e1gSZGWM3REecoTvaF1hrvCT7iROFVW3zh62rpQ8KCECtHSrDb2cfkF8aV6j
         vcotvWeN/v4RRBvegSpt5j8VpVkZkGBCH375RiSoBBl7ldjY4WjNhl3q5PQqiL96uDjW
         EDwQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=L0Vclwy2;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721921534; x=1722526334; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=F8EpmNfmOIP3YPgNYTKu4MONkKVh7+WE1H3VRjWszIk=;
        b=hzESaL/heJwaiuSiZXFiklspcCj7+56bY/krhbzWimc5onrVAxNgWgrFZ9OM9/8EvH
         7rs+ZNYW7BWMMjkN4ECk2QBF0Q+7Qox6DDRuBr58AFb+rp90DeQ6y6IzNnQW4LWpytDo
         Iy5I28tBviCIHVWhSoD/EjUAFHzKc7XBD+Ueo4dJMZeO8URB/YEpru6E0KesXqffCr9f
         o8cxsC2+GPb9PWaXLpGT1zBMXD4ok6xQ88oBoqghIyDOMv5UFVNKCXeH2KRdTkaCPOLL
         9p/CJJOIfWbdF63ZoXNsNDZZYLHwSk7Dgwlxo8lWfYeriLJpphh77dZFqz2KgdTiwXat
         mgXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721921534; x=1722526334;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F8EpmNfmOIP3YPgNYTKu4MONkKVh7+WE1H3VRjWszIk=;
        b=KEQw+jy0nmsLAROl+7zutuUS9TvKEviD+qJXUL7+9UBYnL7Kpv/R++vn/Kxs5UMfr3
         bz6rVV1BfXEVVZ9uGAqmiWWxXWfpXG7RADyZzQ9uW6YW9Auf5ekPCszCv4ebkCoiGbZ3
         1xTvepnxKt9RllVLChGiyX3euJo900alE5kzPDUgqGnBry6XHmabWFAYA8POvOUaaU+k
         IyAwLxJyJjkf86F+ryshxR4i4HWEuNhnb4ctqXFfLzH2a+ZVdMTHUcmz2nhJisoDrNh6
         ijNDveaDuRjC+WB/SNxi6znpxVi5S+t27SxLChbsf0wtislcFZ9VzlmkVcm5anMGwKg6
         6OUg==
X-Forwarded-Encrypted: i=2; AJvYcCVYe3oVnd0fulahqMgpChd+mLNxvgcup8GqhOinmlgP2Wi5fRBkfj6G3d81Fiq33pfMuNO7giauS4OPBze95hkjPMW2T1i5jA==
X-Gm-Message-State: AOJu0YwfallE9y1VOCDKIkVbyo4DrAk16jM3sOr0ygWhBqkcXCQYkWRO
	TYR51h/rFHPZu0SIKkAR46uDKUqTDkCtQ8gXvg3UN56oZG+XK9sV
X-Google-Smtp-Source: AGHT+IF2mxIltE/PMwpx/Uc8L5lN5kQk/5QAUqp/JURaxEys8IpLbHwiqt6LnlN76HRTQfORYq/EGw==
X-Received: by 2002:a05:600c:4f8f:b0:426:5471:156a with SMTP id 5b1f17b1804b1-428057086b9mr19433315e9.13.1721921533958;
        Thu, 25 Jul 2024 08:32:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3ca3:b0:426:6eba:e1f4 with SMTP id
 5b1f17b1804b1-4280386beabls4919265e9.0.-pod-prod-02-eu; Thu, 25 Jul 2024
 08:32:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWMwDJPZFc/S6uJnD2iBuxDfy4HqKjUryqg3mtnBL866f50CeXNKVP/TmR73qFe8ln+cKvC8+82I1/DMxJcVMOYVmZJqoySP6pj9w==
X-Received: by 2002:a05:600c:468d:b0:426:5f0a:c8b4 with SMTP id 5b1f17b1804b1-42805748b0cmr17229855e9.33.1721921532144;
        Thu, 25 Jul 2024 08:32:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721921532; cv=none;
        d=google.com; s=arc-20160816;
        b=crXkyHWFWZNPFpF3CdS904YKqKnpzpg/1i7ys8ZYlIsDi1+6FjjvbKlx89pNmWVuSh
         V8hiNGO27htk4Rz/gekLsRcC5JCihabZX1UIYDoeWgytllvUHRGZLJRnk+MUJrIFdVI2
         lmtGqnrJJhniDrwMSrnOFfHRKEAxQpBtsZdQPwHjFyrny9Z1+CL4KkS33LYIBBJe+j09
         hEEZ81VKg14Vyo6SzyiNxXvxatrh+Eqc12Nt+rmX/JcUssi7LVDg0BmCZYHV8Vee8bLC
         k5IXf4pIrQe35QMD6wDPxUsqCCyl4ptlJ6/nSGxHJDKfwz19s+dHsZuV7rrrHa/Ceu+N
         FYeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=8vTJQJdpFKknSoM6KqvVMqLh+KmmrksaVuFYJyrU9io=;
        fh=7l75q1nHdYIuOXaQ+oviUFl4opSMVnCRPOkHlLlKL08=;
        b=PEekRfJAGgwPxliQ8K16GiO8mM+5XFs8PKn7NwaIQHGoBQm+a6f1XkZFThMDpka4ag
         /z9OvqvjXXH1m5Mw8a+3W6p8gPCUvC4nnQDfbcSubjgkwYuxvZ3VSkxJNuY1uOaoESJA
         wNsxHyX1toUhVNoMVkpsbnzE/sMEfMV5Go6xE7scOqvwfSyTGUqTHUJrW4jXHeCSsHpI
         MN2J0Ehrn4uh0r32HAaTm3ADdjvAdY3vWbSZ2NsUuIhplEhc/HzTXm6xtkFsa8k1UQgT
         4AAzJxpJPSNpUXWTpErB7S6BXmXkKPY2S0ntbFjuP33MqWND+eKmz1qcDxsKLJz5Eal5
         r8uw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=L0Vclwy2;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-427f1f6e8f0si3099435e9.1.2024.07.25.08.32.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Jul 2024 08:32:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id 5b1f17b1804b1-427fc9834deso55705e9.0
        for <kasan-dev@googlegroups.com>; Thu, 25 Jul 2024 08:32:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUfsK+Hqy7j7THfrMswo3WEO+V+taVef4IK7P+zW52Azhvdc/C79s4kIaAJSpfMJUR4egzXiL0U3/mqpNxNFhavzRb2l7mvEYQDjQ==
X-Received: by 2002:a05:600c:5108:b0:426:62a2:dfc with SMTP id 5b1f17b1804b1-42804caec94mr1456125e9.5.1721921527673;
        Thu, 25 Jul 2024 08:32:07 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:8b71:b285:2625:c911])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-427f93e65a7sm83054705e9.33.2024.07.25.08.32.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Jul 2024 08:32:07 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 25 Jul 2024 17:31:34 +0200
Subject: [PATCH v3 1/2] kasan: catch invalid free before SLUB reinitializes
 the object
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240725-kasan-tsbrcu-v3-1-51c92f8f1101@google.com>
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
 header.i=@google.com header.s=20230601 header.b=L0Vclwy2;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32d as
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

More importantly, a subsequent commit will want to use the object metadata
region to store an rcu_head, and we should let KASAN check that the object
pointer is valid before that. (Otherwise that change will make the existing
testcase kmem_cache_invalid_free fail.)

So add a new KASAN hook that allows KASAN to pre-validate a
kmem_cache_free() operation before SLUB actually starts modifying the
object or its metadata.

Acked-by: Vlastimil Babka <vbabka@suse.cz> #slub
Signed-off-by: Jann Horn <jannh@google.com>
---
 include/linux/kasan.h | 16 ++++++++++++++++
 mm/kasan/common.c     | 51 +++++++++++++++++++++++++++++++++++++++------------
 mm/slub.c             |  7 +++++++
 3 files changed, 62 insertions(+), 12 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 70d6a8f6e25d..ebd93c843e78 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -175,6 +175,16 @@ static __always_inline void * __must_check kasan_init_slab_obj(
 	return (void *)object;
 }
 
+bool __kasan_slab_pre_free(struct kmem_cache *s, void *object,
+			unsigned long ip);
+static __always_inline bool kasan_slab_pre_free(struct kmem_cache *s,
+						void *object)
+{
+	if (kasan_enabled())
+		return __kasan_slab_pre_free(s, object, _RET_IP_);
+	return false;
+}
+
 bool __kasan_slab_free(struct kmem_cache *s, void *object,
 			unsigned long ip, bool init);
 static __always_inline bool kasan_slab_free(struct kmem_cache *s,
@@ -371,6 +381,12 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
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
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 85e7c6b4575c..7c7fc6ce7eb7 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -208,31 +208,52 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 	return (void *)object;
 }
 
-static inline bool poison_slab_object(struct kmem_cache *cache, void *object,
-				      unsigned long ip, bool init)
+enum free_validation_result {
+	KASAN_FREE_IS_IGNORED,
+	KASAN_FREE_IS_VALID,
+	KASAN_FREE_IS_INVALID
+};
+
+static enum free_validation_result check_slab_free(struct kmem_cache *cache,
+						void *object, unsigned long ip)
 {
-	void *tagged_object;
+	void *tagged_object = object;
 
-	if (!kasan_arch_is_ready())
-		return false;
+	if (is_kfence_address(object) || !kasan_arch_is_ready())
+		return KASAN_FREE_IS_IGNORED;
 
-	tagged_object = object;
 	object = kasan_reset_tag(object);
 
 	if (unlikely(nearest_obj(cache, virt_to_slab(object), object) != object)) {
 		kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT_INVALID_FREE);
-		return true;
+		return KASAN_FREE_IS_INVALID;
 	}
 
-	/* RCU slabs could be legally used after free within the RCU period. */
-	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
-		return false;
-
 	if (!kasan_byte_accessible(tagged_object)) {
 		kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT_DOUBLE_FREE);
-		return true;
+		return KASAN_FREE_IS_INVALID;
 	}
 
+	return KASAN_FREE_IS_VALID;
+}
+
+static inline bool poison_slab_object(struct kmem_cache *cache, void *object,
+				      unsigned long ip, bool init)
+{
+	void *tagged_object = object;
+	enum free_validation_result valid = check_slab_free(cache, object, ip);
+
+	if (valid == KASAN_FREE_IS_IGNORED)
+		return false;
+	if (valid == KASAN_FREE_IS_INVALID)
+		return true;
+
+	object = kasan_reset_tag(object);
+
+	/* RCU slabs could be legally used after free within the RCU period. */
+	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
+		return false;
+
 	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
 			KASAN_SLAB_FREE, init);
 
@@ -242,6 +263,12 @@ static inline bool poison_slab_object(struct kmem_cache *cache, void *object,
 	return false;
 }
 
+bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
+				unsigned long ip)
+{
+	return check_slab_free(cache, object, ip) == KASAN_FREE_IS_INVALID;
+}
+
 bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 				unsigned long ip, bool init)
 {
diff --git a/mm/slub.c b/mm/slub.c
index 4927edec6a8c..34724704c52d 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2170,6 +2170,13 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
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

-- 
2.45.2.1089.g2a221341d9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240725-kasan-tsbrcu-v3-1-51c92f8f1101%40google.com.
