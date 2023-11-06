Return-Path: <kasan-dev+bncBAABB74QUWVAMGQETHA5ABI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id A59EC7E2DCC
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:11:44 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2c59e2c661esf28248241fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:11:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301504; cv=pass;
        d=google.com; s=arc-20160816;
        b=j84lHg68otteOH5mOgEcYOLr/r3bCXWqpoKsPaMej1mmY63OGYR/KBx5NEPNHu+d8w
         OiUg5SqLs+9XTGU5he1MW431qUgo744tIwlH3ximSIBrIHy1oj4LaEGz/vst+4tCbhuE
         HZCQjbvUVNIoph9oW9XOlN9VPPZmIzgkVjcLzMep/EmuOzkQHl710lu+zTSx6QNS7R+y
         cP8E7lLvDdQa/yYC4vQNyh1/eQon6W3mgqSfA0OabFPzwP0lweShp+KJTYIddBsL6aKd
         qWCa9dWQ2g7MIwmkgjFpiSG2MlGAmirZHbU4UE3kM7RGI2VMdOXymLU/j9TPflpdhZxi
         vrRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9YpkU7bIHfkftAhdAhA6PSuuEhTZE89IZT5Y5iPMMZs=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=IVZlxpi4c39ZqaoV3pfAPJjh7QamrSW1uwhj4AwX+Hagl9NYah0vujIT07cOI1e4Rr
         o9czI7errqJHDSCc3eNXTcLVzcD8bLByK1qmatuYy3O2zt59yjnHgzVnk5VoLgf/vjDB
         /n8mmc8QLY7YZ10I9e07VudKn21X32oa6JSSRbT18wY9VoGq0KoMk3lG3MSWfjOCNPwL
         imYesTwPmOW5TwAzW3cfj8DK570IFwkFN388V/+zQjdLp9Ei6QZQF0w54Cq33r+jwIiy
         goWe4pnsI8WN70KPy/S4Z2CVLHLJlZIAeSUWsjE3uiIZHyjgiZSFngPQIu2JDPgGRtqY
         VmUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=d537NTwR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::af as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301504; x=1699906304; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9YpkU7bIHfkftAhdAhA6PSuuEhTZE89IZT5Y5iPMMZs=;
        b=xtfglwz/ZLcFH2iyatDE5Ihvxoe52AzgZYXntk1SRfi2euHFJMDk8fDclIrZiNFaoL
         QuFJWmT5tgTrcHxOcg1xFY02Ryx2sS1pT4C61QJGculVEWp9tqEEhEpLcvOoehDXaz7t
         7ysMz7BS7HTYmNHxOR4TC7D8BG4BTPy1z3xO4cYyGxMTR7ytn11O/hPLTF2erskBd+yb
         DUwodNwhICtczG44cK60D9kIuiztX1PkBRLf+8wAJ5RydDEOl32I4gwf+oC0UwdaQMi6
         NeBbowab6uIXDEXOSmlIJQsFBeoGPJtVSzeblsWzC/SDyTx7gzGdTHDDziJZ4ewC61an
         qZ8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301504; x=1699906304;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9YpkU7bIHfkftAhdAhA6PSuuEhTZE89IZT5Y5iPMMZs=;
        b=IFh7xcdPf5ced5Q/741GJZ7E4Gr0fe/lY7rKUbhRfT900d5/Pmi8uq1yen9t7xaV06
         FFqA1bUBgeMVZd96sQRZgQ4A3s8mBc1Bt6bnG06G/kJkxofSBjZYvd/Uxhbnn0HgOUk1
         GS4k1U1f8XigEAg0pm9OGjauBQVa5X3Z2Rty4HhHd1DTOmvB5hYLD5w6rR9PAkuFkrxW
         jad9X1S8GeT5BqZg0cR291EeDKhrpaxVWAKFJRKnYYs231tHATdMUhgKRGSD+JuusgDN
         EgcSCf7uOkY0hHndxtampEpoQgg3489ljUg2P1evzeWrRzoW2QjG5AKnDZ3sixDKRWyd
         so+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzC95Wwj9qyH5rklkuIEGduIs9cJ4XstzvsDFDkWDtx0Uhdamwl
	SdX5YjCbhefb8LU6op85Xzk=
X-Google-Smtp-Source: AGHT+IFtApO8XlEQ+EwOH+BorGn6y5BZvE+g6NECxK7ageLhMvf7WRWUti3wZRSqigQrhN0o+GKuoQ==
X-Received: by 2002:a2e:aa19:0:b0:2c6:ef9a:f265 with SMTP id bf25-20020a2eaa19000000b002c6ef9af265mr164266ljb.1.1699301503641;
        Mon, 06 Nov 2023 12:11:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:beab:0:b0:2bf:fb2c:fd70 with SMTP id a43-20020a2ebeab000000b002bffb2cfd70ls183146ljr.2.-pod-prod-00-eu;
 Mon, 06 Nov 2023 12:11:42 -0800 (PST)
X-Received: by 2002:a19:381a:0:b0:500:d96e:f6eb with SMTP id f26-20020a19381a000000b00500d96ef6ebmr142412lfa.19.1699301501882;
        Mon, 06 Nov 2023 12:11:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301501; cv=none;
        d=google.com; s=arc-20160816;
        b=iMOhrbECNDHCwazcGdGFZKNhCKdQxtElE3DQ6CH2zlSW3af7hNzA+IhG5HC+xwoxYO
         GTlj4kgRWb0BrkATqebkbpiMwEg19LYYPa8DtxuYsRsXo2XdQRBimYz/78t9vHRwVpiw
         sbj6swH1FaZQyj2KTHeaNssPEyrsrj0jvo2UFTjG++iCfIkMnYZAqYkY7fgQDrRWapG6
         ZpGfuq1I22NMVdXCHrcpFsYnJm/v7yymvv+WGsNaZPYlM9vD+x3DWoo8r9qMWrqGcf9Q
         k8CLxQrUuOV7wUCXCYxtjVeihmF2slF1fQS9bg4VmUzXobVh0BeRSN2SNJ/55S29wsdH
         RhQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mCp2zVxGwC1RwRlWPaWBJT09DIYULTSyRat3kYinLuo=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=EqO+H2JYJGMkcTsRbK8i7mb/GKIhFNOn0Ny6Z/z+I6AZd+WiWKT1S+SvCSuyF37Aj8
         0PCRTJlZv5YKUFfOjoG8PedGC+VUB9bLBDLxlfAW7IjLawFtxKasYihTQ6FEZo3tDO62
         sH8U4iOy12CPHtkLxhY70hZ4rtL6pvCuXBWzR06WAtPpxjElq9yMW5gO8/1ivXKd0rD+
         8KxPUXhY/YSdEWD/sCU77UhXqPLtBq3oWT8CTPE2Gh7bx11T+IwB+tXWEbbvGk6qa0kO
         J+LGfXNuQ6MOrjaQgstVVb61Kyc+YPIHaU8Sf9BXT9+9faJh1WO9Ee5GLxnxCB1qgbaz
         6ezg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=d537NTwR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::af as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-175.mta1.migadu.com (out-175.mta1.migadu.com. [2001:41d0:203:375::af])
        by gmr-mx.google.com with ESMTPS id b14-20020a0565120b8e00b0050946d339d1si552547lfv.6.2023.11.06.12.11.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:11:41 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::af as permitted sender) client-ip=2001:41d0:203:375::af;
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
Subject: [PATCH RFC 10/20] kasan: clean up and rename ____kasan_kmalloc
Date: Mon,  6 Nov 2023 21:10:19 +0100
Message-Id: <ac4e6fd5fde6f8d87fba1745860d93087c53b2cd.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=d537NTwR;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::af as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Introduce a new poison_kmalloc_redzone helper function that poisons
the redzone for kmalloc object.

Drop the confusingly named ____kasan_kmalloc function and instead use
poison_kmalloc_redzone along with the other required parts of
____kasan_kmalloc in the callers' code.

This is a preparatory change for the following patches in this series.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 42 ++++++++++++++++++++++--------------------
 1 file changed, 22 insertions(+), 20 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 683d0dad32f2..ceb06d5f169f 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -302,26 +302,12 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 	return tagged_object;
 }
 
-static inline void *____kasan_kmalloc(struct kmem_cache *cache,
+static inline void poison_kmalloc_redzone(struct kmem_cache *cache,
 				const void *object, size_t size, gfp_t flags)
 {
 	unsigned long redzone_start;
 	unsigned long redzone_end;
 
-	if (gfpflags_allow_blocking(flags))
-		kasan_quarantine_reduce();
-
-	if (unlikely(object == NULL))
-		return NULL;
-
-	if (is_kfence_address(kasan_reset_tag(object)))
-		return (void *)object;
-
-	/*
-	 * The object has already been unpoisoned by kasan_slab_alloc() for
-	 * kmalloc() or by kasan_krealloc() for krealloc().
-	 */
-
 	/*
 	 * The redzone has byte-level precision for the generic mode.
 	 * Partially poison the last object granule to cover the unaligned
@@ -345,14 +331,25 @@ static inline void *____kasan_kmalloc(struct kmem_cache *cache,
 	if (kasan_stack_collection_enabled() && is_kmalloc_cache(cache))
 		kasan_save_alloc_info(cache, (void *)object, flags);
 
-	/* Keep the tag that was set by kasan_slab_alloc(). */
-	return (void *)object;
 }
 
 void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object,
 					size_t size, gfp_t flags)
 {
-	return ____kasan_kmalloc(cache, object, size, flags);
+	if (gfpflags_allow_blocking(flags))
+		kasan_quarantine_reduce();
+
+	if (unlikely(object == NULL))
+		return NULL;
+
+	if (is_kfence_address(kasan_reset_tag(object)))
+		return (void *)object;
+
+	/* The object has already been unpoisoned by kasan_slab_alloc(). */
+	poison_kmalloc_redzone(cache, object, size, flags);
+
+	/* Keep the tag that was set by kasan_slab_alloc(). */
+	return (void *)object;
 }
 EXPORT_SYMBOL(__kasan_kmalloc);
 
@@ -398,6 +395,9 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 	if (unlikely(object == ZERO_SIZE_PTR))
 		return (void *)object;
 
+	if (is_kfence_address(kasan_reset_tag(object)))
+		return (void *)object;
+
 	/*
 	 * Unpoison the object's data.
 	 * Part of it might already have been unpoisoned, but it's unknown
@@ -410,8 +410,10 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 	/* Piggy-back on kmalloc() instrumentation to poison the redzone. */
 	if (unlikely(!slab))
 		return __kasan_kmalloc_large(object, size, flags);
-	else
-		return ____kasan_kmalloc(slab->slab_cache, object, size, flags);
+	else {
+		poison_kmalloc_redzone(slab->slab_cache, object, size, flags);
+		return (void *)object;
+	}
 }
 
 bool __kasan_mempool_poison_pages(struct page *page, unsigned int order,
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ac4e6fd5fde6f8d87fba1745860d93087c53b2cd.1699297309.git.andreyknvl%40google.com.
