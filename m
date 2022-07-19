Return-Path: <kasan-dev+bncBAABBMHO26LAMGQEFH3AT7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 1459B578EEA
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:13:37 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id e14-20020adfa74e000000b0021e18a1c29fsf667440wrd.22
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:13:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189616; cv=pass;
        d=google.com; s=arc-20160816;
        b=hwPqsYqisFGQoFk2rFyXEl4WzcvIEwvoEYusqGQfvojCXBjgwEyOt1rIT/d0ouvK2g
         +OztnCSTPTlkvPIILq1f354cICsJZTj8xm+l4F/i8nfk7KFG5WTlbhwdhhxLyng1/rwL
         glD/Wa1gU2tqOwerv7t6EIah1YoQ7QsZaGdCZjX+/6VXwB0nyu+BxHUr2C3kZm5Wb/+d
         QKRbeW4b9pNgQiC6cvIUsShTX6PDnKq9dMOrmTGpkAoYO3dXW5zjzICoHwaj9n4MZViX
         U1OOv6oO7HomfCWlFM/YeF9L4krMSNCV2wRVUQqWyq6+zjG7z7rmjZh9xRnLtrifMfZK
         qfwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PKWUmQQic8hYM06al6vdi7i7VOouqdctm8iFdQPeEGw=;
        b=RjaVwmjn+cLHUKSUowUNu6Y0qtkoYB9g5PPndgl5gR9AdtMX+Sa0HKR9AK0vs+jOO5
         wsSfsG5rnEDhRy/AE0QLd0ROSSl6M2OR+Aq3VCKuIgrCom3QWkla3Dasy86v7U6T6lj6
         WseGeplaX8b4xDx+sS/JPTGns7CS1vPBXWgL1+MNHRZhf+dYKwyH91+KU2ueceYKsy5/
         eLcKbn3CCDzAfP82bOyentwVFWLyyiyCFJPFWfBBd+PC6ntVl+KsDKGVDzYREqRjApIc
         Ce8i3xHnDOeZHGHuxRCSveU2hFRTwuJoE48sHN8euBsAVZimgAA9Rdy2t3k9cBlYd91v
         SIxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=m9VfQXYN;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PKWUmQQic8hYM06al6vdi7i7VOouqdctm8iFdQPeEGw=;
        b=MOI2kUo103xEs5z85ULmApaqAnGRTvE3vWrckkrqLQqAzu9TOqaxGhV+Fp/sSqajHy
         lWeLyyNvAFUKaaxc+v36rt48wrg9aBGyNwlQeCJpR0BjrtEn9GQg4zP+I2s4KWymqzVl
         r1PogVzWenroHeI2+aYtccMaK/RNFys9uuhKuSp2M7LwL4VIt40tZrEOswSA1LMTL34x
         jHaxj5rkSYo1blCpiC/P/Pv8BSPqVBgyvytmb2BfHaLe/mnjRDczbKEMLwcBKwiBbVT0
         9hQEYyDx0ypgG2Sb1TUFGftvrKsG0vH1KLdq15Mt+nnwboc1Ctkr+0eJcQV3eJ7UfYc7
         kbrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PKWUmQQic8hYM06al6vdi7i7VOouqdctm8iFdQPeEGw=;
        b=skamHlknR7/lKj0k53MYnoXSMpxB5D1y/YCODZOEuLK/jh0rqtBnxPES41M9eUbt4i
         rcry3SG0JvoroZiUeva2FulfPtlDNMtJkG+Mp8sQ6am9UgrsXqW61l7ckBTYhevpvku8
         1l319azK5gkCoIK4gSKmeKi07DdlXP0S/ftrjlpW8g9kwSazPwncTIgHljMVbOTbllbC
         ke6hnypAjIu1QZ20yAhd+BnKjfU3pHmQ+j7jTp2CN8aDt7BItFc5G0aqZSfNdkwBPCL6
         91NJRw+0McYieFGbYH6rMzq6g3OUtFqbL/MLFYPg59G+FIBdg9XPJFKLrJeJI1lEglUC
         xu1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8h2CUvyH7s6nIiwNywkT/YgPXmCu85dIcoT2aSj2rzETABVI7Q
	5TfRZK6PvSkUnEZD344Fn1s=
X-Google-Smtp-Source: AGRyM1sxCl0hc/QsLQ+YSsDTt0M8mNSjI5He5c6WzX6mCHIVThdMGveCg1CC3Wq6aHx3yoc65xRQLA==
X-Received: by 2002:a5d:46c2:0:b0:21e:2952:46b2 with SMTP id g2-20020a5d46c2000000b0021e295246b2mr2737284wrs.544.1658189616571;
        Mon, 18 Jul 2022 17:13:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1e11:b0:21d:934a:17b with SMTP id
 bj17-20020a0560001e1100b0021d934a017bls12628wrb.3.-pod-prod-gmail; Mon, 18
 Jul 2022 17:13:35 -0700 (PDT)
X-Received: by 2002:a05:6000:1a4e:b0:21d:9451:67ec with SMTP id t14-20020a0560001a4e00b0021d945167ecmr24883953wry.279.1658189615898;
        Mon, 18 Jul 2022 17:13:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189615; cv=none;
        d=google.com; s=arc-20160816;
        b=yvYrKQTFxn351XNy1N0K4qBw3Ud6GSRuMkzCaAdnM6YBFN6CwfKFL8rh2LCPB/COV4
         W1p3DGLJlmIdlhUbWXVZeUTDdLSsWcFponLmNOYpZydAd8MmOl7lqMFOz/Y8ZsnugosU
         teX5k/KIPhnjLBQROU00Xj226hYsT9rrHKvtAfXvmsUFEQhGHewhaydLTIY7D+dhGXMU
         UoZ0puD/DYrU6x73VoX9Rr7YbIv7d1dpF8ErQUjzDO8FFpFQzUdoswjvsGuTVSWgo4qL
         kA73pKooaBLS6u10vj1AcepPMiesgahliOMwqbecrzeb5JgeT4rJR34l6RaSLcooMHAH
         jzeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=T+1jiBrKGTOAkQ9I8eaP4PIHMCNWMSHqgu/PvHey6xE=;
        b=O2kPiqrSvoLCQ5zybW8auFfK1hfs9ZivALBC3KzWN3N4OR5lTtMxAkD9UE1m/ODoQX
         dWNSiqQgN6vSRJ6hvGY3B9VxwwbiOrMKIiPkTiHLF7QrLgqdr8L5nz+1I1ZkM+xYSevl
         +zzvA11K/Y8e74NdfYbotsnIZT2c/UEB+kveLU6YpCzAku1PP3ukuoR4mgrBd7aSjThC
         O6deDTFThs5JHaDKaVmeYkjNoXTLiVgWv7/PtSRHDIutSxff69CwZnuKCGvxJa4VCaoP
         17NENic3wEK6Dri0AVj9jSZjg/XZZzgUNW+sSDmjV3wjQI4bNFWv/DYNJSg4qbLH6Fmn
         emYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=m9VfQXYN;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id u3-20020a056000038300b0021d9c42c7f4si300775wrf.2.2022.07.18.17.13.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:13:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 20/33] kasan: move kasan_get_alloc/free_track definitions
Date: Tue, 19 Jul 2022 02:10:00 +0200
Message-Id: <4d5d13369338e964d15ee7e378b543c1c00dc2e2.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=m9VfQXYN;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4d5d13369338e964d15ee7e378b543c1c00dc2e2.1658189199.git.andreyknvl%40google.com.
