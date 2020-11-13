Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTELXT6QKGQEUF3R2KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E5B52B2808
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:16:47 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id i7sf3073023otp.14
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:16:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305806; cv=pass;
        d=google.com; s=arc-20160816;
        b=u202Hu9/Bvjga3IUC09DZHkHC8AqKSuWQ9QfAGvsInI2FbKfgXqjbZXynwYcqdLj2+
         Xo58VGZSsy5RCUShL+KN1Dpn6pbBArhZv0Lh5knc4OXEvxkcc3EIx4jA4MHy+Fl79Ptu
         O+V9JWAJP4M/R/D8AMGFXsPsC5FXQbn/Vd/BXvpZqNjd0o5ufqIKJ7oDVp5u6+ao9qdL
         clHyqfBpIiS6VNAr1ihzNRFAZ66Bg0n8jTX/6W32/GYm95fsRUnQXHZJgruZuJqS8sUe
         mURnLZ+iwCVstJ9832Gyo0Vn2dIgsNMClzZ2m2jEiHTkAIymSWa9a8rutvZK64gu66R+
         BMmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=3BOEKyMueYsC1gjxguLHndYjOm3QxbP/Xy0s44QqDz4=;
        b=USC/2QvDV9X2rjbXh711SzpMsFlpCYy1eP6KTFaT92/dFr6Bf2+UL1cHUev5/YnB1c
         YHPOlgLCORPEirmjPFp8ZfznwhdRGe/8e23BfgZBhr4Ml5XOw+ynsNxIcvAcLE7OqJMX
         aG5FMsNs5rrp/JJ09NF3oOQnnnheerWlGOgLDf4jxJCYkhtCFWB2p1mUbbXdXxqtbxxW
         pwaiptIBEKHqNBi3XnNx8cgsVmVO1gk60DbqbYXf4omy9KOY6Z5otAGDTpbGil1fCh/D
         tj1/IyYpWmq6S0Cnk9IjC3C7lcwosVJa668m7u5MSRyV5MFbyOkLEEnsfZUTTdMff9SV
         MKQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kEaoU6im;
       spf=pass (google.com: domain of 3ywwvxwokczy0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3ywWvXwoKCZY0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3BOEKyMueYsC1gjxguLHndYjOm3QxbP/Xy0s44QqDz4=;
        b=RijOgb+M9koh2cM4yxB+LjyM+lgWW8QoC9G75dh3DQeLWXcrxdBNnYGiixLGRiWEmn
         eu1Ltm6Obc+jzKoQ/8KGIxw3sPZD5Mghj8sCrA4VjalvjtIAppYfobTo8Cz4iSxJz8uN
         Av8m+flt0dNLYNtcwCFObU+pye/+OfoUE8ruEiqDE82mKWybIiZirD8Of60TvC2+/cza
         KO0YYWKsSbYZatWFiCYzyQmiB5852VXAbwjjNE1J9ZiEMvvT5xRRpFka4ryW6h+kHpmY
         GUrVFKVFwPo+Dv8NeBtYbFS5yKBrYVBGXlyl9MVQjtue4NrugbBOAlgLuam7KVVQCT0I
         UlyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3BOEKyMueYsC1gjxguLHndYjOm3QxbP/Xy0s44QqDz4=;
        b=H79o2P5FyzEfIHvpO9s/t6twJ9pJvbVuiG63EKuSztUSJkgONTiX33BA+kssQ0QSJI
         U5BdPlq8eTqr8irmpsUkiRfX6aFTo6gMOQx9w/br7TPbX/iZ6VTszj5QeS1PjpszSvBi
         Q8Y+9tdIUQl7Kjdl8R60mfkzXqgTu9sWTCuxkJDINYw99H3ke12P+lnJmb6y6fGlrPtr
         tPDg9PgyLquGZ5h2SyCTw3RgvgxEylC3HB+weP7SOYqKgkNsTJJp+8a0TOizOdYte1ry
         7nOZB+KlEKovu6Qiit8co6lij6nvk5CuLZTUg/VP1xR0ecoaBW4p+JeokV7RHWazML5L
         TTXQ==
X-Gm-Message-State: AOAM533bvYkpO2+7PilAiUKUJRSvf/CvFBWMe7Xz3//ddcFgTlCWMXTA
	gfclqCStM84nTX+UEq2lPBA=
X-Google-Smtp-Source: ABdhPJwIwwE3GTQLCR7KlsTiV21QdrEehifgPjXAv5CbLP1iaRKW56ye9UNCJutdSm1PSHJ9p4UcVg==
X-Received: by 2002:a05:6830:23a3:: with SMTP id m3mr3265780ots.135.1605305804490;
        Fri, 13 Nov 2020 14:16:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:389:: with SMTP id r9ls479168ooj.1.gmail; Fri, 13
 Nov 2020 14:16:43 -0800 (PST)
X-Received: by 2002:a4a:e519:: with SMTP id r25mr3185176oot.56.1605305803782;
        Fri, 13 Nov 2020 14:16:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305803; cv=none;
        d=google.com; s=arc-20160816;
        b=UDlUb2x2sz19CnFYgGMkx6C/hfIW5TN286c0a5VHOckjs1mI80Gnn9uxdxwlBw7mAI
         LPAXD+gjdA2scfck4cuWJI66kVCWgn38A6GRBYU6za+SRfJrkS8jmFSZObCqvBO5dbCb
         zuk2shSd+VN3PI7vix0HOnPHA4PSvvzyJiNTDVnKd62jMZ4Ttlq2dNMVhba0VqBHJBEN
         nMAsi1Hd7pN45y/FBS5IqivKHvvMmaQUDfW7MpXTxMfl5m5Xed4Hxv6xfSIcDrirQX/e
         s18ohkznKCRsoE/Fjx0ux9w5Lr340NhESmIPyQSZd9pgZqxu7o2zTZGUcSWpN2AYLn4Q
         daHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=KBw2xb89iGf5nkQBhVPMBrv+WXUlpFCEGVTeqj9IKE8=;
        b=FjvEYNshNBz9wp38V8lYNDIXhcPxMy/C4bLdZhD7XA9k4LMsGAGP1zlW/EoYexGXuv
         mUkYRJo93iT2DzADXLNPNMWFFeTnle67bHy7jaPDCgoQqUjZUyGyXBIxIFXBHkPINCRu
         bFkh9NitQ1aOApfROtckP/Fl05lQL/l8EXo5uf+gvrxeanTKF73BxCPfjB1ojLDKRN3S
         nBHShydCFnuVfnIQ1QHn+8tngNiJCP6l80oEGccb+GwTY13EZwZnz+wu6KNVMaEeIMq3
         mZSpjpPPIB0+NxsqMC2g3B7sZe9/oibI3a2ypEhNeHabrDd6LnhLhP4Z8nfBu4ucTRph
         U1Rg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kEaoU6im;
       spf=pass (google.com: domain of 3ywwvxwokczy0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3ywWvXwoKCZY0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id f16si926518otc.0.2020.11.13.14.16.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:16:43 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ywwvxwokczy0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id v1so3841714qvf.11
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:16:43 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:54cd:: with SMTP id
 j13mr4460435qvx.8.1605305803272; Fri, 13 Nov 2020 14:16:43 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:40 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <6b1a801b2132bf11e19c4421b2b079d242b152f3.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 12/42] kasan: hide invalid free check implementation
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kEaoU6im;       spf=pass
 (google.com: domain of 3ywwvxwokczy0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3ywWvXwoKCZY0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

For software KASAN modes the check is based on the value in the shadow
memory. Hardware tag-based KASAN won't be using shadow, so hide the
implementation of the check in check_invalid_free().

Also simplify the code for software tag-based mode.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I5fae9531c9fc948eb4d4e0c589744032fc5a0789
---
 mm/kasan/common.c  | 19 +------------------
 mm/kasan/generic.c |  7 +++++++
 mm/kasan/kasan.h   |  2 ++
 mm/kasan/sw_tags.c |  9 +++++++++
 4 files changed, 19 insertions(+), 18 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index b3ebee6fcfca..ae55570b4d32 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -278,25 +278,9 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 	return (void *)object;
 }
 
-static inline bool shadow_invalid(u8 tag, s8 shadow_byte)
-{
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
-		return shadow_byte < 0 ||
-			shadow_byte >= KASAN_GRANULE_SIZE;
-
-	/* else CONFIG_KASAN_SW_TAGS: */
-	if ((u8)shadow_byte == KASAN_TAG_INVALID)
-		return true;
-	if ((tag != KASAN_TAG_KERNEL) && (tag != (u8)shadow_byte))
-		return true;
-
-	return false;
-}
-
 static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 			      unsigned long ip, bool quarantine)
 {
-	s8 shadow_byte;
 	u8 tag;
 	void *tagged_object;
 	unsigned long rounded_up_size;
@@ -318,8 +302,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
 		return false;
 
-	shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(object));
-	if (shadow_invalid(tag, shadow_byte)) {
+	if (check_invalid_free(tagged_object)) {
 		kasan_report_invalid_free(tagged_object, ip);
 		return true;
 	}
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 754217c258a8..67642acafe92 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -188,6 +188,13 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 	return check_memory_region_inline(addr, size, write, ret_ip);
 }
 
+bool check_invalid_free(void *addr)
+{
+	s8 shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
+
+	return shadow_byte < 0 || shadow_byte >= KASAN_GRANULE_SIZE;
+}
+
 void kasan_cache_shrink(struct kmem_cache *cache)
 {
 	quarantine_remove_cache(cache);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index eec88bf28c64..e5b5f60bc963 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -166,6 +166,8 @@ void unpoison_range(const void *address, size_t size);
 bool check_memory_region(unsigned long addr, size_t size, bool write,
 				unsigned long ret_ip);
 
+bool check_invalid_free(void *addr);
+
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
 
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index c0b3f327812b..64540109c461 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -121,6 +121,15 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 	return true;
 }
 
+bool check_invalid_free(void *addr)
+{
+	u8 tag = get_tag(addr);
+	u8 shadow_byte = READ_ONCE(*(u8 *)kasan_mem_to_shadow(reset_tag(addr)));
+
+	return (shadow_byte == KASAN_TAG_INVALID) ||
+		(tag != KASAN_TAG_KERNEL && tag != shadow_byte);
+}
+
 #define DEFINE_HWASAN_LOAD_STORE(size)					\
 	void __hwasan_load##size##_noabort(unsigned long addr)		\
 	{								\
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6b1a801b2132bf11e19c4421b2b079d242b152f3.1605305705.git.andreyknvl%40google.com.
