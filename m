Return-Path: <kasan-dev+bncBAABB5WK3GMAMGQE2YZS6EA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BA225ADAAC
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:09:11 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id a17-20020a05600c349100b003a545125f6esf7922401wmq.4
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:09:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412150; cv=pass;
        d=google.com; s=arc-20160816;
        b=K3ISSLXYGU/8nWpQdzhreIbYLR6fI53U65KkgpxQ4ykVR/mtcI7MnOpw/rki4rMiV8
         apbWJxdaviytn7bg/KiQNavlBTQTKhJA3vQiEJ2T8OImfYfhH5emZWGG6ZCxb8GU+MsV
         i1247yKPHzZ4HCZpG0c8Xdl+6w6sz58CRIig4zyGzk7Zvn4l5Ur6ux/NK1L8++jvfZDa
         lo7ymWypOt3cb1SCqvhJhVRZvjRhp+O4b/aGN97oawytIaycxF+UbAF8BTFPuIZffO3v
         7bU9Xbg+Dnuz6p+LvyOAE8dQlt6JlmnP6DjKZi+k9GgWGcyC48H+x3yLDuyV1ekHaYX2
         2Ylw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=RPyun7rB0vtoTWRavT1Jr7OrGzCia6YG16u64WG/HD0=;
        b=037DFX3DMRd2g0ngs8+s3N2Vq9TrOFc96zOqXgdfyhCyUHQiifV1x291fMP9lxa8g8
         lLPi/iDTKHhNjWN3AkKXot36ULNKVJRdWOrbT101Jc3xdZxUHsu96qRL5dJ4WVFvoayl
         5CIabOS8Zum4fEo5/OhqTi+VSKYZs5gBz3iJBWeiSg6b5tDpZHyDu8bgkyT425QSK7XT
         kToCJzl93I91vTtkPumBEty7l9qKh/FXxSJapJIl/jUCslAzgGf2SB1LqRRQhlg5jloK
         2VHBJba9DTJ0CaRSWn55289DMoEHMyWLAR6JE58nmrEs3y6mxpv63NN5dbmWchZZ7uPG
         VQWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=U0OnRaxU;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=RPyun7rB0vtoTWRavT1Jr7OrGzCia6YG16u64WG/HD0=;
        b=tEjm12sY6gL4Z8FZpnI32+EFiVl/jn//wFmrC2cB7jZgXFO13UG9wmVlBXLpyhJ94c
         +cLcJ/5tjzh9QTd9B6r6FD6aw6pdygqWAaIA9j6a2FympDFVfRbkBhSg5M08ZSQcEX23
         74YkOl/rujL6WOEU6ocPGUSy6JNvu+R+iZ3cpgzlcm5iIB1ogCHjKWjyfnEII+XY/0TG
         vezwa32rjY7BJkjWK3RoUrHxcubMOCflAkZPoMtA7PF3TTc6sDIk9LhkZ2a/8xS7KWcK
         /BcwDAKwL1ufsuoK1Zj9gkzn2fNqt2DvD+deQ2FHbfTUWh75/jWw8graGY69B/F0xHRJ
         I7XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=RPyun7rB0vtoTWRavT1Jr7OrGzCia6YG16u64WG/HD0=;
        b=o2hEcS2IuxskQfpCBtXmFuUPAgwQVIyaQYvFCLQPMyQ/ovhSlidaP5eik3N1hfik2A
         Q7Tsm5M1CARWS9LWbr6GTMMQOg4gW3v+jXAOFIs6AGrOL7SO+VT6SrJfQPEB4Q2Ecqpq
         1U01dtMUZjGPytDP/FZ9lW2eAPChd8p8jOal8a6mhTcyP/aVIGKc5rBfvO8H/QTXybLb
         UnLBO7CUr5L4KF9l1jtNy5qTn516omnTUuTSVBoeji3p/dDNcboaFengGEats4p2oSDz
         Q6e/jYsW/58pX9BBJVXhNFxIHyLPUR6IpNEfprrB8YCh14MjXx4c0hHhICrGdcN7eAoF
         Nizg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3MGkpIoqEGo5BGdPVqBFNeUl3okORdh7XmQ/pMjw3GflOLS8zl
	uQvzPR9R4sv73U/rJ0GYhXQ=
X-Google-Smtp-Source: AA6agR6MFbmHpVCyZSgUSL4ZRVGh/Ht6DBpYC+/Po2dUVhsmzvpuzJ6JiK7YFcUGLhMuWaD0LyxQFQ==
X-Received: by 2002:adf:e94a:0:b0:228:6aa8:432a with SMTP id m10-20020adfe94a000000b002286aa8432amr4657653wrn.567.1662412150815;
        Mon, 05 Sep 2022 14:09:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d22e:0:b0:225:26dd:8b59 with SMTP id k14-20020adfd22e000000b0022526dd8b59ls198138wrh.3.-pod-prod-gmail;
 Mon, 05 Sep 2022 14:09:10 -0700 (PDT)
X-Received: by 2002:a5d:47c5:0:b0:226:efcf:49a3 with SMTP id o5-20020a5d47c5000000b00226efcf49a3mr14768250wrc.174.1662412150244;
        Mon, 05 Sep 2022 14:09:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412150; cv=none;
        d=google.com; s=arc-20160816;
        b=tglmhnXh+X+DR1u5Vj7yrqEotGscWRSdoritnLwLYEJ4TULPpVIR4bInKZY6Ds7qGo
         EZjY/HBixhhgnuUI9Uf8f/b04NLdjeUIDXBHSykhoU7q6cuMZtRr8wgJBs2Z2imfROtk
         oPG4v+dID14UEecsIF92KPND5iky8riZ8w90y9wL4ooN7f2GB+v+FQqdmgEe6CMCXlfS
         aEnrPGD54ULfFAiOfq71vH3n+JtLKnYurIQa5hzOdZ6q9eM7QYV+Rhh1Lmkqp5Qll2mm
         HRjw/Y/bcwa3uAtONlt6v0yITzNXs2Mj5X+WgtdZX/kFj0SNp4KafeFzQpuCrRGnwVUx
         KzHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qJDP/1jiRKwrY7zySgQrX51mUWY0nGK4OrCOZF2ILUE=;
        b=izWHKjh9OKoSTIN90UFHVEl7nkmJ3tLn+g6L6Ol5hpAVFY0kCE5mJutFSu3rw8VtLb
         3O8tJ7Dj+j9p6fxzw0N9OZyo77h/vCk+72Hdt7fxhXNoxh+Ym99E6X4jfrY77czNK1i8
         dL6YQGjnjCWBONGqmPNbJDaWl5B0sVvQiiZRZCXeFv8OtApnZvzak+5MM4hsXwYMMDrY
         c1smvM4loS7HufqmAXVcb92/fwYNPMeKA3E/1Fm0Kxb1Fhbe2uDeZx4ZMf/7JWVeoDMx
         rmQxTt4rbPnv3LjaV0goJIAFdbCgoifZfxzoTX28SMYOwQmGGm2zUuYK2vk7d4zF9EA6
         PPjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=U0OnRaxU;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id l3-20020a1ced03000000b003a5582cf0f0si592102wmh.0.2022.09.05.14.09.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:09:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 20/34] kasan: move kasan_get_alloc/free_track definitions
Date: Mon,  5 Sep 2022 23:05:35 +0200
Message-Id: <0cb15423956889b3905a0174b58782633bbbd72e.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=U0OnRaxU;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Move the definitions of kasan_get_alloc/free_track() to report_*.c, as
they belong with other the reporting code.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/generic.c        | 21 ---------------------
 mm/kasan/report_generic.c | 21 +++++++++++++++++++++
 mm/kasan/report_tags.c    | 12 ++++++++++++
 mm/kasan/tags.c           | 12 ------------
 4 files changed, 33 insertions(+), 33 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index aff39af3c532..d8b5590f9484 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -512,24 +512,3 @@ void kasan_save_free_info(struct kmem_cache *cache, void *object)
 	/* The object was freed and has free track set. */
 	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREETRACK;
 }
-
-struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
-						void *object)
-{
-	struct kasan_alloc_meta *alloc_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (!alloc_meta)
-		return NULL;
-
-	return &alloc_meta->alloc_track;
-}
-
-struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-						void *object, u8 tag)
-{
-	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREETRACK)
-		return NULL;
-	/* Free meta must be present with KASAN_SLAB_FREETRACK. */
-	return &kasan_get_free_meta(cache, object)->free_track;
-}
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 348dc207d462..74d21786ef09 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -127,6 +127,27 @@ const char *kasan_get_bug_type(struct kasan_report_info *info)
 	return get_wild_bug_type(info);
 }
 
+struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
+						void *object)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (!alloc_meta)
+		return NULL;
+
+	return &alloc_meta->alloc_track;
+}
+
+struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
+						void *object, u8 tag)
+{
+	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREETRACK)
+		return NULL;
+	/* Free meta must be present with KASAN_SLAB_FREETRACK. */
+	return &kasan_get_free_meta(cache, object)->free_track;
+}
+
 void kasan_metadata_fetch_row(char *buffer, void *row)
 {
 	memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 35cf3cae4aa4..79b6497d8a81 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -21,3 +21,15 @@ const char *kasan_get_bug_type(struct kasan_report_info *info)
 
 	return "invalid-access";
 }
+
+struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
+						void *object)
+{
+	return NULL;
+}
+
+struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
+						void *object, u8 tag)
+{
+	return NULL;
+}
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index fd11d10a4ffc..39a0481e5228 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -24,15 +24,3 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 void kasan_save_free_info(struct kmem_cache *cache, void *object)
 {
 }
-
-struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
-						void *object)
-{
-	return NULL;
-}
-
-struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-						void *object, u8 tag)
-{
-	return NULL;
-}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0cb15423956889b3905a0174b58782633bbbd72e.1662411799.git.andreyknvl%40google.com.
