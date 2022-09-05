Return-Path: <kasan-dev+bncBAABBNGJ3GMAMGQEKQ26TAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id A640E5ADA89
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:05:56 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id w19-20020a05640234d300b004482dd03feesf6326076edc.0
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:05:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662411956; cv=pass;
        d=google.com; s=arc-20160816;
        b=VeCdS043LdvCsTuCk0Y2O28+hoLyijDKK0Czt3lCxJohyNdIqsGxWItdpQpzO/niRN
         AWEbxVtSrMNEd7nTTuQwRqG4m3+EiKs9Zp0ipbU0LQ5pOZPWnSzc/8xCkLWHwH75U4+O
         zWIYSuWYcDfFqzrxFqNcVnhc8Scyrk+ScBSKPXWa8Vf+0/K4OnVAI+oyHtGmxQcVZ0lO
         IjEyiqtoFdTJuavL3IYrIFgTmoi0Ik6OxGVIUS/cjB2pknDDIPIcPE/jABKVixZWNGST
         TnQd1VEfb+v+U1+8EJsknBwcYbe4YFOaPZE92atOpR9TV6OhBwwQQz5/6rnxyBvXljZq
         +umg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=lvvlhJUJsSGvHw3i73MImey+knE5GtfUGui8Zk1Crdk=;
        b=DIID8XpfkXL4BEu5ZD/0pSoTz5HHINa/Va76BlPzQSh9g4vQ6srsl70wUl+zy37YKn
         TVLnUsBR6AAc1KM18r+mtaykm5nN3ea+iUssEH5D+LNL0SPuMHK54kHEfAQgdYdl8W7j
         KibwrQ3PrPoKTwf7IxX1C9y/jquzVdf5qUIYxR+6H9D/fFAly+tXECf8B/Sf3hHGQcvJ
         EHPBpPCp6i+sY5A9bi7lRnWCOFxqkyvq/g6UP57hRZ/A7iJwZvej89GUjdzTi9D9jzFc
         qkTC5K+toX8Zewh+D+vzVpzSmr4hQF0vyf7Ng/bico/66x3+fpsjtcw9QijTnoJUIlTw
         v1rA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xXX054y0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=lvvlhJUJsSGvHw3i73MImey+knE5GtfUGui8Zk1Crdk=;
        b=A/jFb+jvu6UMGPtsZxMH7l+vdiqTYZQD2I8REycHfpP+pc4Q02YomDZ8KNGw/XmGrT
         PnGLPrtIPARCp+cnVltfxmjluoSZYJ3qhw88jNzoVlWVn4dyZ4bxk7TWF8Om9fd7//3F
         CKkyBt+HImrgT5Lh/IQv0iuDAMoJCB2+AEUIB3l8ATc6raX4OqbL7D40m+LGSYGWB+Dj
         BPBo1ux4P8i/KQnoN5aby4aUfWTU/M52+mc4nbBucsfYRnaAFDkab88ZmMEPj7HgQNPi
         cE6RmGhCEohQTBbAvklDYb5j1RIwv8MuKHm1jPjCMheJNq628pf+OH5JPacdjUpUCBaX
         6E/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=lvvlhJUJsSGvHw3i73MImey+knE5GtfUGui8Zk1Crdk=;
        b=A9TyA4Kaq0mE4AWplB6kqj8hvzY3erfHQFSyYdb2DBGRQ4eAggdhy4kketQDKXEIGv
         q8HmcDEaCStquLoxjrlkIfGxelSPK51ePFfaMktkgMMu0TiIY3pGwECmFxXFcjr4oPKK
         7n46HcpX+OKasBtsN+2ceTrG48mpGmfsRmkzqK4ORd/4Y/mWxgEjmcPC5os98IkHSBbn
         1txRFq+rNf3ysvysUDuK8a7+EOrkcmt0TKXWNCFR7dmpRgd0dyFHn7Tehu2UERAVgOKl
         FhvF1N47HRDGpCxgiRIM5RuHWmyxbeqKHuyfPK/Tlw3yDK0+u/1Xt2g9uX0TDQ0werb/
         1s0g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2SD6UUMlQDNXBVHqiviLep655006niojylP/31qhcVg7L3n7KC
	ojx0lAKFl8pYJM/ObYv7Fbs=
X-Google-Smtp-Source: AA6agR5C94Vx7fg8PsW3QdGUpgimL8rnmekQgxcwHUB/hlOahKm5r/Rs8JfHbClokMnbSdwtMD2+ww==
X-Received: by 2002:a17:906:ef90:b0:730:9af7:5702 with SMTP id ze16-20020a170906ef9000b007309af75702mr38308436ejb.107.1662411956315;
        Mon, 05 Sep 2022 14:05:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:6553:b0:73d:704f:9649 with SMTP id
 u19-20020a170906655300b0073d704f9649ls3990722ejn.5.-pod-prod-gmail; Mon, 05
 Sep 2022 14:05:55 -0700 (PDT)
X-Received: by 2002:a17:907:1c01:b0:6f4:2692:e23 with SMTP id nc1-20020a1709071c0100b006f426920e23mr36782534ejc.243.1662411955611;
        Mon, 05 Sep 2022 14:05:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662411955; cv=none;
        d=google.com; s=arc-20160816;
        b=H4XBNhtg4FRfXZtLvm5sXZym7dbnNlXbp6i6DCehwXSMAAZhGjdXIkVcSeF5+jxdd1
         VhWavLp3FCY1oMPX/8n16HummLRKgacp6PRGq+W5nK91l1M8Ei40WOBrBjqHv39nbYCN
         OiOHKOsErYodWL/hEKAMaiOcZGZfHOs928QDXifE+tW6vayIQCewS/9a7pgkeuWClJrU
         iJOIUC2QrEdbkaw1mcCz/MKm2z+Cy074piaUbwcki4jk5+uajmcL6MNGR3Xkh0Bqsz+y
         pjn4b9cLNSEzvOGjMhcvOjzVX0Jf7ciNuhh+P3LPJY2rUB6gY7HoMd2DTHGHjF8oJbBJ
         NZkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FRkYVowObuO3yDrt4EDyhkJ3yebxJfyebNr4InttO9I=;
        b=tV47i7cGfE/DOa86h1EodIfaDsAT+1s/vEp+PTryjHT8HE9ZtRf9OmAte86XYJPQjk
         1UfMLl5kGHEcdLTP85mSA5hpGrDNMGCLyh+x7tusXCbxkQoFXf8ToEPw8TjL60rLNbcL
         rdIKl1NBK/6AnDblobyMgdCfF8shDrj7IllZG0ZmyUpqo87WL3zrlzAXaLAmLIvYT6Ch
         NxU7FtB5AFedEy52VtjDqscUcjMFpAp672FaZcFwgWF+dJ2UIqSqf1vU8L9RF5aOm9zH
         4lmDe/smYgXV7bN1cm/tQTHK/F/q7fEcxqs26az4IR3OdqsA+VbaHi/3pqiT7KIiyPCH
         zg9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xXX054y0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id hx8-20020a170906846800b0073d9d812170si466991ejc.1.2022.09.05.14.05.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:05:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
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
Subject: [PATCH mm v3 03/34] kasan: move is_kmalloc check out of save_alloc_info
Date: Mon,  5 Sep 2022 23:05:18 +0200
Message-Id: <df89f1915b788f9a10319905af6d0202a3b30c30.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=xXX054y0;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Move kasan_info.is_kmalloc check out of save_alloc_info().

This is a preparatory change that simplifies the following patches
in this series.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 15 +++++----------
 1 file changed, 5 insertions(+), 10 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 90b6cadd2dac..6a75237ed308 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -424,15 +424,10 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 	}
 }
 
-static void save_alloc_info(struct kmem_cache *cache, void *object,
-				gfp_t flags, bool is_kmalloc)
+static void save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 {
 	struct kasan_alloc_meta *alloc_meta;
 
-	/* Don't save alloc info for kmalloc caches in kasan_slab_alloc(). */
-	if (cache->kasan_info.is_kmalloc && !is_kmalloc)
-		return;
-
 	alloc_meta = kasan_get_alloc_meta(cache, object);
 	if (alloc_meta)
 		kasan_set_track(&alloc_meta->alloc_track, flags);
@@ -467,8 +462,8 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 	kasan_unpoison(tagged_object, cache->object_size, init);
 
 	/* Save alloc info (if possible) for non-kmalloc() allocations. */
-	if (kasan_stack_collection_enabled())
-		save_alloc_info(cache, (void *)object, flags, false);
+	if (kasan_stack_collection_enabled() && !cache->kasan_info.is_kmalloc)
+		save_alloc_info(cache, (void *)object, flags);
 
 	return tagged_object;
 }
@@ -513,8 +508,8 @@ static inline void *____kasan_kmalloc(struct kmem_cache *cache,
 	 * Save alloc info (if possible) for kmalloc() allocations.
 	 * This also rewrites the alloc info when called from kasan_krealloc().
 	 */
-	if (kasan_stack_collection_enabled())
-		save_alloc_info(cache, (void *)object, flags, true);
+	if (kasan_stack_collection_enabled() && cache->kasan_info.is_kmalloc)
+		save_alloc_info(cache, (void *)object, flags);
 
 	/* Keep the tag that was set by kasan_slab_alloc(). */
 	return (void *)object;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/df89f1915b788f9a10319905af6d0202a3b30c30.1662411799.git.andreyknvl%40google.com.
