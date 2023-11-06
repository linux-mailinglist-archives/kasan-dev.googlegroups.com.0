Return-Path: <kasan-dev+bncBAABBAUSUWVAMGQE3TK65IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 498317E2DFD
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:13:55 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-357448d5409sf47447955ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:13:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301634; cv=pass;
        d=google.com; s=arc-20160816;
        b=eOnRs4B/UkrbX3IV6+sdot4vZSDQTx+fe12TvpZWethLQAPMpqKIUgTcdqfK30anhD
         d6ctbx0Bw92zw6lbF4oRcdsNCG43CdOE6ofXRtxMHMqJydqFG5T3q7G5SPYG0cHGkjjr
         yOOtAx/ZL/85pABj7G/P7SLkomDOF/egGFAsu5bLz6T1/qsDn4Gc9+TTaw/8mAVNMzAS
         RatMRMBZ6Yzos0WCEBVDMaI1iJIQUBSjSoERrdlon4YvM0+NIuEIfc+pvMUQ9SWVq7S/
         WPaQWlpvDUZTLnkcXYmBIJjl31ijHvo80lvanchz+diwVlBiIVtW+yuAWp5sylDXAnxN
         RrtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=emSwW5ixizsOly/Cawma0tJSrCO5q95gx+OjJbja1CM=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=ZLflcM7IUfF0i4VQ6fK53HKJXVcv/dQdN5KT8cHzUu4AHxf4b1YSF1aTnOhyfLCSag
         7mMsBdXBYxxiRnylyJZfIHAh13fjK3edukvMW1LX1tgUw4NrI4EPgwJyLUHnDC/gNWoK
         rHe3oBLIY7nau6RZHPlL0iKxcHoUtI8JbIPMuVomvMcz90Wey50jLTuW7vqbeqxJm325
         wFYS4IrlMOREVWxhJ1OWN4MpzULBluR3vGsWOYu3+OEM9I5h+nD2XYEYz7IgCjXaD4ia
         dPkN23Ka7bbaJbUrTlnQ2ZUisEvIj+tAyf4SY9mOAOrGDnmtvRb5fA7mcbnLgiuTcuOe
         tSTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VvwPI2ke;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::bb as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301634; x=1699906434; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=emSwW5ixizsOly/Cawma0tJSrCO5q95gx+OjJbja1CM=;
        b=JzWU6V+hH5RfBFQeLqXhT89mR90vKC0mK3y9wO+Z6yAzBqzs0kjgUt5/t4qDY/8U03
         MFPibJmLrCUqHp9E1eYVFYoED55nXjp0y9PIubGooizE0nw9/XSyLcJfzsIJEPYg6R2w
         fhWKy3zOIPPxXXnGReR1r255HjcPWskjOqWqwJkaELdz6h7dO3PfwyuHWOESKlkeZUmk
         +DNRQGpzDB5lSX24qG00xn2lg/qUOLXddtxDTcjkkIwY37i/FnU9rAQhTT0jcdckVxLc
         +wOIgbn1d1RMXKmHQbshPSePxJeRt4ss14nexMiDzV3GbCfZqd6RZSDBwORoq2VF2o9i
         rYOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301634; x=1699906434;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=emSwW5ixizsOly/Cawma0tJSrCO5q95gx+OjJbja1CM=;
        b=vn6eVMIebz1YhhE+755fR5uB1ly9ttcxQ12joPiKFxORWG72RAqeyXRe3w+SR6OrpZ
         2cLH2ZQ9cgOskF7gMsn+J0wGlRTYNGlm3q9oZi1UaW6MTOizw9v9zrvAm8XIOm9QOZd6
         8rXv3NpRGB5V3WsA18uGNVjxHjOEfU217Ae5hI2TJwrkSW/UIEhnSQ57QU1VwOS4Udnu
         3nDAhNC7ZHcR45kaNuL1vPEerZUqIPIlulH7D+QZM9vBW/WhFAYJ5cajaLCcqs0zvUDf
         LxIMuNhEauoRQNmy3eUsPo+JFbNc7gFS8UV+o/BKPbr4GD/GL+buvqP/Wb7TLRynJcM8
         ld7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzOyVhDbxQ26JntmIgpUKvho5uC31HkDq7kGMSUFik4U5V76Dip
	IcTyG8Q6Ifi/8zn7vWfzhMo=
X-Google-Smtp-Source: AGHT+IGfYq9VZobwZyu7mwlEwXjcVWbbHXIG00NRpt8iPyA4mA9Eudli5F2gTiHgQx65/GE3uxrDqQ==
X-Received: by 2002:a05:6e02:1c0a:b0:359:3ee6:a909 with SMTP id l10-20020a056e021c0a00b003593ee6a909mr907033ilh.13.1699301634109;
        Mon, 06 Nov 2023 12:13:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2191:b0:349:17ee:89a6 with SMTP id
 j17-20020a056e02219100b0034917ee89a6ls2679933ila.1.-pod-prod-05-us; Mon, 06
 Nov 2023 12:13:53 -0800 (PST)
X-Received: by 2002:a05:6e02:1bea:b0:357:a180:6b74 with SMTP id y10-20020a056e021bea00b00357a1806b74mr851919ilv.27.1699301633585;
        Mon, 06 Nov 2023 12:13:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301633; cv=none;
        d=google.com; s=arc-20160816;
        b=Be6HuoaEtYLEQhqqx4EhPkJ/ixkTpcgV77mBKDCRL5oQXmXplesGw0BER2N2n2aNz2
         mTNNAJsAXSHCt3tK9I7g/+MCfttIv/TEEgzJu8SHj239v+AXEXBqLXsw4Mva1O73qQks
         MNjcNJURdprwyh1LtoFod5Vym+LLVhJQV6VsxEpxUv/UQy4AV9BykMmpAWGIh2MFaDVw
         2g/OXslOJoj1aYgQaebk3WNfTsjByWeoOrJsj4pLtAGWvHKNu2SAruUsYnE4zjWgahF6
         PffdqJ23SP3V1fpV91xBEj6GjmQTjoDWK0OO5cU9cpMN1IZczEAUTMFFW1MWk0x4omtm
         Ex3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EPGVjwO+qP/d7FcuwPK2D6CcDKWjvT42oG4AsVrb0Go=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=xN1OFlSq87DhJBtqPwizQcPM+1d/Uqt7mfZFwUgQSilvTdSp8UacpovE0ZZaH0AXJw
         y8BojdSCgEvdzvGeiBWDls8jnV4wElfeSLeYC5rtJh0TkwrfgpppiaWYlIxSx/d8P/G2
         T9RWaW+5Ne3s/JxyDotQUCkqc4Y6GmeE+DerTdBqNI3ek8G6rg4ysCNiPgqYUPbpB/kv
         vICG+tEQ5kQ8SID7qsHixXiOkl79uJ8hBpIA/vhf6IbXL9B34TCWKLoRhJEN4XEyZf3c
         eb8SecCDvNeDfg5F9dijK/ADamiPvTIhVM3ZxSqqOyHENNeHvAslA2gvxde6GpkHBZs4
         ifAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VvwPI2ke;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::bb as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-187.mta0.migadu.com (out-187.mta0.migadu.com. [2001:41d0:1004:224b::bb])
        by gmr-mx.google.com with ESMTPS id d4-20020a928744000000b0035250544598si797338ilm.1.2023.11.06.12.13.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:13:52 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::bb as permitted sender) client-ip=2001:41d0:1004:224b::bb;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH RFC 20/20] io_uring: use mempool KASAN hook
Date: Mon,  6 Nov 2023 21:10:29 +0100
Message-Id: <4f2fc546ce7b494c99c08e282c4d697d6dd58a8f.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=VvwPI2ke;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::bb as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Use the proper kasan_mempool_unpoison_object hook for unpoisoning cached
objects.

A future change might also update io_uring to check the return value of
kasan_mempool_poison_object to prevent double-free and invalid-free bugs.
This proves to be non-trivial with the current way io_uring caches
objects, so this is left out-of-scope of this series.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 io_uring/alloc_cache.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/io_uring/alloc_cache.h b/io_uring/alloc_cache.h
index 8de0414e8efe..bf2fb26a6539 100644
--- a/io_uring/alloc_cache.h
+++ b/io_uring/alloc_cache.h
@@ -33,7 +33,7 @@ static inline struct io_cache_entry *io_alloc_cache_get(struct io_alloc_cache *c
 		struct io_cache_entry *entry;
 
 		entry = container_of(cache->list.next, struct io_cache_entry, node);
-		kasan_unpoison_range(entry, cache->elem_size);
+		kasan_mempool_unpoison_object(entry, cache->elem_size);
 		cache->list.next = cache->list.next->next;
 		cache->nr_cached--;
 		return entry;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4f2fc546ce7b494c99c08e282c4d697d6dd58a8f.1699297309.git.andreyknvl%40google.com.
