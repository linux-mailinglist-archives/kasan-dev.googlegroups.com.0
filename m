Return-Path: <kasan-dev+bncBAABB3PM26LAMGQE2DCOTOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 75C70578EC0
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:10:22 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id n19-20020a05600c3b9300b003a314062cf4sf204648wms.0
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:10:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189422; cv=pass;
        d=google.com; s=arc-20160816;
        b=SFBF4By+MlpFxwBdyUX4fcgLJGFpBCcvdixV1jtg7yE7i3qVnlUWTU2vhAP9LPtVUf
         kWz+J5XpSabjKw+Z4j2vy3ep0w4c+IJeUYb4rbFRjjCLK7xMXGvccPeznPmd5NDPQRAI
         OOOgaRTc+alaiww4l+kelVmIjCcLSQsJMfEq45aQT8KtAzW2WLpgZNXqVyw+4ItFHx6o
         ooD01EXq5r6SFpRE/n2s104wj7B/WjlVymdWePiHcDuoxVW6Pv09yHAq3a0okYSHoce1
         yDp2EdgHNq6x6hEw/20DByn+fyAdJ5yc/fFmRGWfgZOdRS4QGv9avZzmcelXh471BSSo
         njxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=t7BCOkCnjgey6O1Exsvn6P8mGVkeiuLQb0DDrz4ArBU=;
        b=KI+nxvfr5dTl2wXP0DNqpxd9iP304H7D9j3ORHVxmlocmz79uvIHjmXaa4m6qrkMhJ
         ti1OHZjvqw8AjWAcOOLLcpGN8+cQgtKzur35uJkDMbQ3ogauSYS70g92lNFjWmnp54kv
         QV8iWvCIQI4WgqnOMstN+muzilTOf9S7UBHefYh9pVD1BX3+q224yPDiTmls2+JLHZR6
         71O+aCNxN9o6+xjZxABBcO+bRqk5iDtpzX5cwWN8wOoM2EyRli1KXGGlEEYBdrBCsbOR
         EHNK/qu7WlcbVdQOQJJ2tK8ub5jnCuESvJuof9MUMbGDGMYZ66Ri4p3J2ReThFKEYfag
         ySTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mN9bAq9G;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t7BCOkCnjgey6O1Exsvn6P8mGVkeiuLQb0DDrz4ArBU=;
        b=rekEkfAnm53B/a38n0F2UsEVvyPWBYQEJg0qVJmK0PdnWa5dyB3YTbT+iSTogoK9gw
         4w/hVGlMFDlrocU0mt8sZUNmxx1VHVLPzaA/ETbhiRgFDU7Ew+u9AFpesKzOFFTDaZMV
         pvqQFIcNvOZ7V4eJjTJqYS6GMBU4EWJBASandlM0h4Euq33CzYBzGh80Yxe2xbpZVY/x
         uww3AFFPwloCeTW3NZZjmdRJT7QN5j9hcZ+pcV8rN21vYOI8lGVOqWiE4OUJorQhyT6w
         +2bQ2HizM3iCkS7GZW9IyKWHT2YEkPkTNhD2TLsFej7wE9OsrPHTuJn+gFqdBSdMwOGY
         jbVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t7BCOkCnjgey6O1Exsvn6P8mGVkeiuLQb0DDrz4ArBU=;
        b=ZnInXbAefZkX5tZu+X6RSr6t2hVJgIawUcqKc2jrz77D10Jww5OOEpeRc+fnakwALU
         qZ1mZKxo8Fkc6IFgLyV4jYJg6ZaDhreeyALs1D/gWeja9jq9CLiQ65Hf9cTIIxp/6BYd
         t0e3tt5dItBkNQfpPEgovfP3m59GEkyL4i8/rIiQgBdTJWrZN1N49R2DwVVgqwLByfeL
         PiUQvHgi7+feukOz6kzjia6NtFzIs4QRBfErt+/YeJzfwCRNdWm6X6U3iD/XCrgKkCjL
         grNQXOeD4XHYCdorRY6eJxIgP4Bk+kCLvbWpRDELTjCU5h0A8fKhlX45kC2Y9jERoVN/
         fFLw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+IlrS87ToobbFktCfn3Mzsh3Tqwu8UaBPXh6hvdbpkI0bUT3xe
	+RCbM7Deqsv3sy3br2s02Hc=
X-Google-Smtp-Source: AGRyM1u/5IsNnra4vLkitIm7Wj4GrNxhtPgYx/965GgToMopMF09DQxzBIcdv2QWUDqQwE69UZqDtg==
X-Received: by 2002:a05:6000:2a8:b0:21d:8c81:7eb0 with SMTP id l8-20020a05600002a800b0021d8c817eb0mr24197624wry.460.1658189421906;
        Mon, 18 Jul 2022 17:10:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1849:b0:21d:9b2c:2273 with SMTP id
 c9-20020a056000184900b0021d9b2c2273ls471882wri.1.gmail; Mon, 18 Jul 2022
 17:10:21 -0700 (PDT)
X-Received: by 2002:adf:edc1:0:b0:21d:7157:f4aa with SMTP id v1-20020adfedc1000000b0021d7157f4aamr24896949wro.454.1658189421227;
        Mon, 18 Jul 2022 17:10:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189421; cv=none;
        d=google.com; s=arc-20160816;
        b=swr87+uJVqNtdElzIT7FGFmSzYuzMUwScK03cxSfyK0C4UI3oWydIQgFhO1CkMBWcm
         kOT0SXLuO5JF8KRwUKX9XQsAxQtoZO+Xrwa6wDA2AzIFFqoMF5nSK36ASIJ91kDi4up8
         XbKw2RG4/a2QP7PoyVANWrYV86FkPl6g0zJf1HgXWUGTkx6+o6AanNtADj1IJffM5GQi
         pZQl2U9D+R3CVKM7ED5926QrC2QnWv7bRHdIPzjLbnefG1KrqhPwOyWBZcGb0UeSNmxZ
         mHDbMyfB5n6twN1ojFhLU61aTZlNlPJxo74E1GaNMgR5KAppAzaO2KUDRG3K1MRXHMmC
         zufQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GtkG5Wr6mLxaj0KDnAXzT5VwvOshmWOEVZwvcH5Zewg=;
        b=erg6xBi+G965GMJ0AnrXoBwLw4uIdFBlkXwQtxBg6izi2E/mLoxZAmstdjfwuRpK/6
         hqgBH5cb0EVg14Y3lTf+epx9R/0Mr9MiP3ziAzr7EvAEF8WXJmilf57At+EY1n0gzt7r
         i2/LQd6FrtycRLCwJVwe24q04wAa3lSK/zgPEm9VOhm+rBG43quoVy97Yx+A9TJguCs+
         JiwF2mYLujtI0J+Q7U5WSlHVYYqJURXbJX1p4z090Gl/FLqV2SAyW/jbwbCaTWwMYbU1
         bXwqfs9a/U2yHESnj1omfy0I1GUT8CP7IMipR8Kl/HudcyO5SB1RnWuxc0uXo9Ka/KXJ
         1ntg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mN9bAq9G;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id bz9-20020a056000090900b0021da74303d2si486102wrb.8.2022.07.18.17.10.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:10:21 -0700 (PDT)
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
Subject: [PATCH mm v2 03/33] kasan: move is_kmalloc check out of save_alloc_info
Date: Tue, 19 Jul 2022 02:09:43 +0200
Message-Id: <52c77b163f90a7d24a0a38f713b3849439387431.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=mN9bAq9G;       spf=pass
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

Move kasan_info.is_kmalloc check out of save_alloc_info().

This is a preparatory change that simplifies the following patches
in this series.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 15 +++++----------
 1 file changed, 5 insertions(+), 10 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 4b2bbb6063cb..a6fd597f73f5 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -423,15 +423,10 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
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
@@ -466,8 +461,8 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 	kasan_unpoison(tagged_object, cache->object_size, init);
 
 	/* Save alloc info (if possible) for non-kmalloc() allocations. */
-	if (kasan_stack_collection_enabled())
-		save_alloc_info(cache, (void *)object, flags, false);
+	if (kasan_stack_collection_enabled() && !cache->kasan_info.is_kmalloc)
+		save_alloc_info(cache, (void *)object, flags);
 
 	return tagged_object;
 }
@@ -512,8 +507,8 @@ static inline void *____kasan_kmalloc(struct kmem_cache *cache,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/52c77b163f90a7d24a0a38f713b3849439387431.1658189199.git.andreyknvl%40google.com.
