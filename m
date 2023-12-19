Return-Path: <kasan-dev+bncBAABB75SRCWAMGQE7Z6G7CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id E8B3681938D
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:30:24 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-50be5bdae9fsf3934088e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:30:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703025024; cv=pass;
        d=google.com; s=arc-20160816;
        b=OtauCoDulJxsP5qhfKAK997eCFHULHjz9ijKLwZC8biqCs6G+gjyEWt44X0DlsXw51
         +eR65nvzBhFNDjj+umusmmeIT4Zem1owtuweRvd9rveWfX7znYdQg1/UyIC+oAV4iyHu
         KkXp5phfg556b7aKEgO/4jgi0svgnk7NClxSUmdIHq+jWu1vTbnh8GQN+7LrArHHZYBQ
         ZyWkXIOUv4w8BeTR0edAcauUdWDB4aUMY9qTrlZpeOFl2RhDNL9ohQmTB+WwaSvKSHWD
         3vwi6w4ml3+2XdUuEBIw2K35RtgtSoyJzchVbfTv6u3caRIr8zktBdjCeY3O15mJcIR3
         T3NA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+xYXSPSdr75BOeXwLbbQYpp/U5PHACV16nd9Mh6bBHM=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=HBhWd7WAUPwXL3UhbjfFAxzGb3nXM3DHJVEsIEduR+98fsXRchShRfmjBS1uA3iYv4
         BrY5rqWZS63lh8lPKF2sEUgV8r2L+THs2X1X04zManJ9e9MSMhHsCa2K0aDQ+LRIb+LC
         F9Qw5S3q899JoJT9uoekfyLQTu83avkFCyJz2m4n/9sRqH10/VulR2sIy40bR8RQO/Mg
         x+1xpxdgcQ0BiqDB3rmXbsDPv2Bb5sfjSqE+/4BQfoq3JzQFht0CJ68hrE0ayMSztFGE
         2v8Gc4l3JCBuWQYc6OiDUmHHBKWVfW14zZ2sOpmu9T6684RgaR+KoD/oSCXKQOtF1A6b
         xbYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=SkAJqCw+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.176 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703025024; x=1703629824; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+xYXSPSdr75BOeXwLbbQYpp/U5PHACV16nd9Mh6bBHM=;
        b=uY7CdSj61MT3kSlbLn5b4CVB4MU2nvcP9cDwgd9Gyix0+lImN+7+dIRYLwEVB3S0DQ
         2p9MN8ay8TMfjeWvGCYzRhlFpdeRxvVIh3J5+cWBOkMorIGJuFsmBbgPPUafGKLDypXN
         JYBTlPrcfZh6cGPE1ALsEGhx0nodIH9FvRhLMNg42s9WfKLcWym/CLioquOpnYShEZnO
         ysBmFJXO5j0ikbTB17oxXDjWPIgxqqsMasMm6EuIwd1IbkfPxjsiTLW/lRpk03ISPiK8
         ldFWoZgs+DnkvYi0gaN9TKjTJe8V4lG1RwzU9TAnvs2i8bGW/leGwwa32rbQFpv4THlY
         aaOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703025024; x=1703629824;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+xYXSPSdr75BOeXwLbbQYpp/U5PHACV16nd9Mh6bBHM=;
        b=XK60utc6Z42tinAlhseI0hsen5ypWg/T9Hf/+M2yxosi0TvWKv01A0fcCLR1VMx3lt
         AyK8/MmNqGVa6sAXpWRc6uTk8h8RCZp5TdmiystgqH8xcekD9m9oGSt9tH0QbMLJQel+
         x1NlNfYs0CBtKxKlEWwtFq2tRgeGYTyhd2EHOtuc/g+BxPZfwOup5fo/H8wImLDLtvO8
         kqb+xi/jVfqVUh3HmBR8W2PwkWe7pOLIKPSW3Yn9MKMvO/slG5jxwAeWXPV6b7cYVbQE
         HFI0moWdXQMJbdp91BLtIHitlVzRn0soMnelmK3iOIyMFiUjtR+uA9PD3/0rUWSpfG8g
         qIfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxh+FIBDUiT2QTUvxBNPkNlD285WMkOyxuY3r3XL5b1huUxs+iA
	el7BivHsmT00Zbmkiy8rnsa/VQ==
X-Google-Smtp-Source: AGHT+IG0BCN7yS+KnLEt2yrv0Q4pcxNcwyFqMdMeD5CItOh45B2+165phofP94dC8LeYuStqFtNIxw==
X-Received: by 2002:a19:911b:0:b0:50e:4fa2:5001 with SMTP id t27-20020a19911b000000b0050e4fa25001mr171507lfd.71.1703025023952;
        Tue, 19 Dec 2023 14:30:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f45:0:b0:50e:2ef4:2bdf with SMTP id 5-20020ac25f45000000b0050e2ef42bdfls1348516lfz.2.-pod-prod-03-eu;
 Tue, 19 Dec 2023 14:30:22 -0800 (PST)
X-Received: by 2002:ac2:4f8f:0:b0:50b:e810:3206 with SMTP id z15-20020ac24f8f000000b0050be8103206mr7835539lfs.110.1703025022280;
        Tue, 19 Dec 2023 14:30:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703025022; cv=none;
        d=google.com; s=arc-20160816;
        b=p1SiU0HUgdXbzVb42dpQh2gJ40CHi+9lrvALuVotLyPE/7BtDq8wceySip2W5D6X0J
         YE/fLTXV8DD0aet7ttlxiGlTNfVFZlQj4kPPdi1uTURZvfCAT472Z5MNO+SpA2XE7Meb
         4lHbHwmxm7Qoadb5c/Z8q+8mVBZ7fTqLI2J2NiQ0VMdXk3FrpgeuD5chAlIsjNdofZeU
         5sw7Eo4SDvClwPF0XpDLeJh6fJx3Lfy+/e6VoEMy4gbj1Eb+XMaG2xYoOH0CDR9AF9AB
         p60VWjr/+Jr2RFPHrKjmDsLh/1RDcCgfEVl8lL8sQLvyD6JVlRWqG3rTmfyIoCYlFRAo
         j7Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+EoZxIVuEAKv7x5FH4zs492QikDHeQQIvGcyYCPoQRk=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=Dm+RvaTlgE/NH7hmt+sTRE3jE6tEBxDHPeckWJ/xVvmXlTrz/Tz5FSZGiRZV/kFiwL
         tO9v2Ow2fSzCA7NYbM/C+vYaohPct1m5FWFGmTFa8Moxo0kU1EkeR6O/Hi1IjNKHV3Ix
         IXF4BwFS3tcnSBICk5mN4ly3nQMCtnrwp59Fs1pyqXRwJZfKYDYD+X7DsKFC4aTLRxsn
         /bxfzQZSNNTVmej1jvOs+MG5KUPOkW5rlo4F1aSUit2eqfPRqAwajAzA9D4470huyTWy
         dffsFsZliw5ahgjz0KrA5C5GBzUCLgGRAOyHAU0J6RBAw96QaVTawq4j+Q+kJjlBQgA6
         Fozg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=SkAJqCw+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.176 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-176.mta0.migadu.com (out-176.mta0.migadu.com. [91.218.175.176])
        by gmr-mx.google.com with ESMTPS id p14-20020ac24ece000000b0050e1c5be1b4si108965lfr.6.2023.12.19.14.30.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:30:22 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.176 as permitted sender) client-ip=91.218.175.176;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Breno Leitao <leitao@debian.org>,
	Alexander Lobakin <alobakin@pm.me>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 11/21] kasan: introduce poison_kmalloc_large_redzone
Date: Tue, 19 Dec 2023 23:28:55 +0100
Message-Id: <93317097b668519d76097fb065201b2027436e22.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=SkAJqCw+;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.176
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Split out a poison_kmalloc_large_redzone helper from
__kasan_kmalloc_large and use it in the caller's code.

This is a preparatory change for the following patches in this series.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 41 +++++++++++++++++++++++------------------
 1 file changed, 23 insertions(+), 18 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 1217b260abc3..962805bf5f62 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -363,23 +363,12 @@ void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object
 }
 EXPORT_SYMBOL(__kasan_kmalloc);
 
-void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
+static inline void poison_kmalloc_large_redzone(const void *ptr, size_t size,
 						gfp_t flags)
 {
 	unsigned long redzone_start;
 	unsigned long redzone_end;
 
-	if (gfpflags_allow_blocking(flags))
-		kasan_quarantine_reduce();
-
-	if (unlikely(ptr == NULL))
-		return NULL;
-
-	/*
-	 * The object has already been unpoisoned by kasan_unpoison_pages() for
-	 * alloc_pages() or by kasan_krealloc() for krealloc().
-	 */
-
 	/*
 	 * The redzone has byte-level precision for the generic mode.
 	 * Partially poison the last object granule to cover the unaligned
@@ -389,12 +378,25 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
 		kasan_poison_last_granule(ptr, size);
 
 	/* Poison the aligned part of the redzone. */
-	redzone_start = round_up((unsigned long)(ptr + size),
-				KASAN_GRANULE_SIZE);
+	redzone_start = round_up((unsigned long)(ptr + size), KASAN_GRANULE_SIZE);
 	redzone_end = (unsigned long)ptr + page_size(virt_to_page(ptr));
 	kasan_poison((void *)redzone_start, redzone_end - redzone_start,
 		     KASAN_PAGE_REDZONE, false);
+}
 
+void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
+						gfp_t flags)
+{
+	if (gfpflags_allow_blocking(flags))
+		kasan_quarantine_reduce();
+
+	if (unlikely(ptr == NULL))
+		return NULL;
+
+	/* The object has already been unpoisoned by kasan_unpoison_pages(). */
+	poison_kmalloc_large_redzone(ptr, size, flags);
+
+	/* Keep the tag that was set by alloc_pages(). */
 	return (void *)ptr;
 }
 
@@ -402,6 +404,9 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 {
 	struct slab *slab;
 
+	if (gfpflags_allow_blocking(flags))
+		kasan_quarantine_reduce();
+
 	if (unlikely(object == ZERO_SIZE_PTR))
 		return (void *)object;
 
@@ -419,11 +424,11 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 
 	/* Piggy-back on kmalloc() instrumentation to poison the redzone. */
 	if (unlikely(!slab))
-		return __kasan_kmalloc_large(object, size, flags);
-	else {
+		poison_kmalloc_large_redzone(object, size, flags);
+	else
 		poison_kmalloc_redzone(slab->slab_cache, object, size, flags);
-		return (void *)object;
-	}
+
+	return (void *)object;
 }
 
 bool __kasan_mempool_poison_pages(struct page *page, unsigned int order,
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/93317097b668519d76097fb065201b2027436e22.1703024586.git.andreyknvl%40google.com.
