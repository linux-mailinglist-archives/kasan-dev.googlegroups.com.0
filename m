Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBDW2QS2QMGQEDAOWUTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BC6C93B523
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2024 18:34:24 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-427df7b6879sf31607835e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2024 09:34:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721838864; cv=pass;
        d=google.com; s=arc-20160816;
        b=WSStixDM3oyeqgKDcpx7SZOuX7VAE1Iuktvjh9+LZEEP/gOkeOZ3o6lVXh/4PF0cfw
         0oDOsFiJ1gXpa4QU5/D25OIwCEaCXe9A0ZSENtnIu9vfno990WSy9wuAZ1uGphoiD18N
         S7Ub1NmPRpMVn5RrNyjC/nXr+ryX8iqPjlcPC1xj34FQNkpVZyyAH3b6I7vTSax7i1Zc
         kDzDNPej8GX/gpX84DIox2uFbH1pJomyQ4cNR1xniRu8xJGlXAXv0sYrT2o0bJlnQjx9
         D03Y9u5yeH74eY1NoT4ty2+0ITNnuWX5lCX6rlfwQFNQk9O7kAxaPcZushodYE9X8tNl
         O+fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=A+mHZYpG76kukFTNG19cKcPNcwVri2XmHI0rr5zBGfI=;
        fh=nZkF1vz4K0XV8J3B454FavyF0YQosBvfJD4kqle0WmM=;
        b=A/hdtToMdxcHHSMu/ILC2F4GttKFZL2LjzqQywKAMpkDwcmsLgkgadX09j7vBxZtoW
         NCKMQPeyisAMo8eHPHThoHtmPEaNC0l1ZgTocY+hnfNqXgr1SoJ+SWKZqTgWUW9zjIwI
         kMLR5/gTFT+1UzpNbgHuXINEMnK2aDbN3so7QV/LFxSIw8jFuLnBN7V6Fy5L5sx9sWNH
         MgZLvwN1wi1/Hrch0Fvzw0GEY5riu1tRucIRvXfPREalceewQbm7HjuOvLBJus9aliMs
         LtXlWgZwrZcFAD4lpko+AwtZf6nC9Q3vRuF3O2fZGGs7r/fREOZP3UupithFQIkHyyaL
         EZzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oICPiDwr;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721838864; x=1722443664; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=A+mHZYpG76kukFTNG19cKcPNcwVri2XmHI0rr5zBGfI=;
        b=P9ZjLCjes1NukgBeDpivWln+LE3UczN2dsXbdTB6tud63YmdYVSm3zUgWnhhDkqHK/
         zbzN8Vqd3jOOCnKkl06XrTSg/588LQPHawiG1/c4x4gHayXi7XxE/3jFDYBW46AxdgHr
         4eNBFdtuPrusLDuz6uQakQnCCRax757qBTsCq/pcvMfvfDQh3wSTjxJg41jBT8pT74R/
         2nzfC8zpNM70oMNQQ+VOiEUF3QkoKmO8Bot5L9vtiwmp78SEjX6Wl+v6PwnX+noDxWmK
         OeYOG0NF3DvICwg0d6OFH8zCQcNX+gtg+SIueo/AZK8TAjRNjjZCUCIaHiPfgwM2NJ+K
         qK+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721838864; x=1722443664;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=A+mHZYpG76kukFTNG19cKcPNcwVri2XmHI0rr5zBGfI=;
        b=htu+ZlYKWCruC/Wo3XSeqntMp7LQTgmOGvrjwarEKVlXbTFtogZVbkFGDNjUIkXuQg
         1BJ23WZXGSmlyA/ezg6p+u/BJjjxI0XSoeTTrDNVSNLL5TMjYcbupw6JCudsvqK6ai+P
         rHK66okVqM5d1aXrHJWEMygG/OaJhy+xlz9FRORkULQre+LrLYhPT0GAXzwEYBlcO6e4
         SYHYjoMndgE8KhBdQJK0A81/w1bREiLxVwKujnrm45d/sBwkSCu7YyYAJXVveknzzgIy
         cRsRVXWwY2WmQhn8hJXsL4uDpRtvDhIXt1HuP9BM4Udo6WUBlyBoEHhcjknMP8v3g7ne
         sogA==
X-Forwarded-Encrypted: i=2; AJvYcCXrDi8WUqvNvHEk4D+A+i25WUtA+nq10sUmU9xr2dqvw7pTzupaJpQt+9//Hn/zUaSsjZJe5Esjoz9ulq1SMH9Kug2i+DzbDQ==
X-Gm-Message-State: AOJu0Yw2szF9qDXUPLfVjhZycBa7t2FBVltQNy+q/rNCGrV9F7LrCrzk
	utJ+4rmo7eSbzvkZtTPKqkK7QER3mIrHiKRkewajeNKhi1bmVYsd
X-Google-Smtp-Source: AGHT+IHXnovUgHF0uvm8UvbeXSbPEn0GsZCCBujNbR4Odz1KaQhxpnNmsK34Q/BF38bsKQON5hob7Q==
X-Received: by 2002:a5d:6da5:0:b0:368:41e0:16c0 with SMTP id ffacd0b85a97d-36b319dd2b4mr198288f8f.22.1721838862862;
        Wed, 24 Jul 2024 09:34:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:ac4:b0:368:4489:3f40 with SMTP id
 ffacd0b85a97d-36b31acb718ls11917f8f.2.-pod-prod-07-eu; Wed, 24 Jul 2024
 09:34:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUXGN6ciZyDEbCoukCJvKeSbjEmxd9wxTpMfLA0IhlWvhkjE2SF1vOF3ly9DjKPSIrVwv0Z+O01kDlHAw/G6p9Au33uhcEJ9Kykuw==
X-Received: by 2002:a05:600c:3b21:b0:427:d740:f38c with SMTP id 5b1f17b1804b1-427dd0e82dcmr88254695e9.17.1721838860871;
        Wed, 24 Jul 2024 09:34:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721838860; cv=none;
        d=google.com; s=arc-20160816;
        b=uJvJulZ5EapjCKEkLkvSRxOk9rFdU0c49bubA+puYFRah9T0grO2GZoHb34xbDZ3XP
         Ibmbf1HjBp8Jsd5yVmvIfiLgLYcRi6Ew/St9w3VdSk9AhZamV+BCl/pqpgdlOASp0qQp
         1VQoo3FM5zrrtwqcqBx8KBsj34w52dVmtTgbq957xaG6JOFmTToppiBCmNo6f5zhd3YS
         mG/ekYk8xc+dPvzICsZdyD+XI58wEvitMU581HgSvjQWVj7XuKg4KfyInuSiLm/3G+Pb
         J7fm/H8xZlWSGhB5w548/x6er6MQjnBp33W0mApMnrBynUJbzve9ja5iQK5rWPQIwFus
         6sVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=7EM+ZpXg0gF/YjekvI/GGKZPQZmJkVX1r6GY58f54Us=;
        fh=oKk2SAHnuxXsUm/or0PJugPV7YfJmio/tN5Q/6Xhttc=;
        b=MNulo1RlM5r4VuCVkat3EZ2zm2oFU+OJN5V+3VgtFZTxkiTa3nLDAiF0rusXy/NUVU
         RYS8Jm0gJJyNePhhyfsj6AUvtdA38dsD4p4tT7R/W/8vnRdBsJ69GqkuG1aAnKG4b2o1
         QIyR4wOFE/jDqfcK+4gYKQNjBVi+GL5aMs7rvxuvP8ErK38O2HwhxuYkCpM/IMSrBeMs
         RNKuU8Tujsfkl0XGmLaQZZ+EcuH3Nwf2pAhzhoGKG4a837OH7BAWBuHGBPbNXCPEcCiU
         Vnw84gBeuoF/Ew73Cmrc7Ui1btUAiXBdi0/rIg7FuBqRujl2oxNkyah++9850EertTR0
         Jcww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oICPiDwr;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-427f1f5c1f0si896235e9.1.2024.07.24.09.34.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Jul 2024 09:34:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id 5b1f17b1804b1-427fc9834deso1395e9.0
        for <kasan-dev@googlegroups.com>; Wed, 24 Jul 2024 09:34:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWpuCUam3KBpY2ftRuq9c/q7l9nkGW+PVbTqjli7drlCmnXkXjKPRvpClZno9XRWpsSxT3dbmE/sEgLrJZ/Xf18lh0xeFH5PvwWgQ==
X-Received: by 2002:a05:600c:4454:b0:426:68ce:c97a with SMTP id 5b1f17b1804b1-427f7c5c3b3mr1464825e9.7.1721838859742;
        Wed, 24 Jul 2024 09:34:19 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:7aec:12da:2527:71ba])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-427f92c7cb3sm37264285e9.0.2024.07.24.09.34.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Jul 2024 09:34:19 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 24 Jul 2024 18:34:12 +0200
Subject: [PATCH v2 1/2] kasan: catch invalid free before SLUB reinitializes
 the object
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240724-kasan-tsbrcu-v2-1-45f898064468@google.com>
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
 header.i=@google.com header.s=20230601 header.b=oICPiDwr;       spf=pass
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

More importantly, a subsequent commit will want to use the object metadata
region to store an rcu_head, and we should let KASAN check that the object
pointer is valid before that. (Otherwise that change will make the existing
testcase kmem_cache_invalid_free fail.)

So add a new KASAN hook that allows KASAN to pre-validate a
kmem_cache_free() operation before SLUB actually starts modifying the
object or its metadata.

Signed-off-by: Jann Horn <jannh@google.com>
---
 include/linux/kasan.h | 10 ++++++++++
 mm/kasan/common.c     | 51 +++++++++++++++++++++++++++++++++++++++------------
 mm/slub.c             |  7 +++++++
 3 files changed, 56 insertions(+), 12 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 70d6a8f6e25d..eee8ca1dcb40 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240724-kasan-tsbrcu-v2-1-45f898064468%40google.com.
