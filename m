Return-Path: <kasan-dev+bncBAABBAERUWVAMGQEUUE7GQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 948177E2DCD
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:11:45 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2c50dcd377esf48984791fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:11:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301505; cv=pass;
        d=google.com; s=arc-20160816;
        b=A9/NmUzXECA7LBE+d8PWrCjKk5oRk45O0Hw/ZUEfuqvouiwkYIf9a6JNXKAXDCinmM
         yq1IJcrwca7kIDH6bfT+/QRTsyRw4or5+we4ccmwpo4+bnYBTd0PspdHSqZkmsvxAOqC
         1aF1H/D8hHciH8CrZDLelxytSsfMk6+ZqnWnAe+3Pcyjns6mn7zR81oBox96ce/3vID7
         opxLDOZ7v8PsN16kd7OKgJ8b2uLr8DT7ZqM+uX5QHbiJNQzsu2rlYmKQlNDufvf3i1PD
         7qvCmpzfQVi1kPOMQwWGr05uDP0i3YLgj8tnp7b17rN/QY8W1Cf4QIljsIFTxsBem51e
         KuGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=k0nXbPYGrUGtUDaPl874ul5b54t0r1I9JMqAm2j2fmY=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=iSPHx6L/pqqQ1CXTxAkwYX+Ov7czG8W4ece/audvjhO/o/ww+y9FgiuTzpkGsftGyQ
         4UNqhkJXx2SEQuULpnp9NfMEIGgtvmxpJOrXnZJ9Ayaw7NRMEhYDs0n8OLSK1+SzQKfj
         fAcWBBqVIvFanxc4lm4BZ/iLih5XHSU5jXr9iJtIkDOfnVgqKCt4+fvYOtQxijlvJm3/
         /3lF69iHHQtjmSaVBCt20f2b12Gg7NUcHVNV6rOll/AI7I+gtA82gDPFl5fpsUxo+m62
         9kVYesGAM+JWQSp8HXXzK42UkLX8g1tcqESrVYZBXGTbefdUN59ZulEGTBcKkQbmX1rA
         sFxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=RItIssP+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.173 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301505; x=1699906305; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=k0nXbPYGrUGtUDaPl874ul5b54t0r1I9JMqAm2j2fmY=;
        b=gwZQ34aZ2QIqkqWvQN3/UO6/gFYHmYQWb5J68Dk21o96NZt5VX8QSzVkE3ECwB+HG+
         /oaKCwPl1UVBmWN1le4smf2GxMqRSM8NghPRHEPU1mIiI8z6jrq1T/FxoUff4pMxVzRN
         0kxH5Pc18PRRIyLdoxMlwGWtUIPabCO1l4CByDzKOyG8ED1wR38Cwzt7hGVaIUfcmGB6
         rP5QN4ZAVHiOV9OVHKtclZm7I4w2hraN5j7gAlWCwppeiP+ZPVzogL1gA4YHjXog5ca7
         9jqEhgVnqrr0sgol+zGJOZKpe/OGzqxxfhIcYKNJ2c5PzXZstWV1LthmIftma2o7rQfh
         CyEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301505; x=1699906305;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=k0nXbPYGrUGtUDaPl874ul5b54t0r1I9JMqAm2j2fmY=;
        b=mFwVuh0rK2LMfYpbSPEdr+EyOuTVr8D3QD54AY15Av23VByPu9FssIzl1Xmy+ZooH3
         Cp68XsDU4HD2h05aGuMnO3aMZj5Ue+j/yiWCOF646ykhkSci/d+7iwPuUdO7UBeb6Y/B
         8H33LClPyaFg1FS6qypLRr5Muxn8w65ylOeRKpjV7XzjzjKnJXOx5IWqULqmzeLzmf+D
         qFHD7/fimIyL5vrvJ5FEr3usXlnV/lV/FLAWXZppbNgQWOkiZS3nijzbuHQlNdcavYbi
         osydnblermsgS0NHjVeYJazadRZ37wV/vGs+7+/yMupXk+uR07Pox22sgkLxAYChsO/J
         J4kQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzVQrTeoKA2AiwSJ7A1CMs3lWSVnVk2rMIHReGm630Ci+3R66D7
	x1Gvxxx2KDQ97E3RgxTgzxgF1A==
X-Google-Smtp-Source: AGHT+IGeEdZ0Dp2N/Y7/zxUWEysM3dGbC86aWP/kochCyNyiXbTV1yOWeWMIBkSWgOhoVCFjhSl15w==
X-Received: by 2002:a05:651c:c98:b0:2c5:13b1:b450 with SMTP id bz24-20020a05651c0c9800b002c513b1b450mr31490533ljb.26.1699301504474;
        Mon, 06 Nov 2023 12:11:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2115:b0:2c2:9016:aa8f with SMTP id
 a21-20020a05651c211500b002c29016aa8fls74559ljq.2.-pod-prod-07-eu; Mon, 06 Nov
 2023 12:11:42 -0800 (PST)
X-Received: by 2002:a05:651c:1a20:b0:2c5:1808:4aa4 with SMTP id by32-20020a05651c1a2000b002c518084aa4mr27977863ljb.12.1699301502577;
        Mon, 06 Nov 2023 12:11:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301502; cv=none;
        d=google.com; s=arc-20160816;
        b=MCVENal4buCMqLjcP6V4D79EbaBLw7EtaPQdbxOKa/wRNdYFJmPOT/guKODacWnV+0
         /YwMgWS/UoRpXxp+uVUh7wjioZ+rhYKXZbkF3qvRy9QIi0/6j522sF6tZCcuH/JLCleU
         ISLWQ5yqYlcSIGF31mOTEBCFB7xiADoFOtU1PG2HWQYQrM+yki+c0e8E9lBE+ffeWFKe
         9cur4PBFO9N0d1CFOKxGdcT2NOgr8T9XSenJDckRcKInlMAKn3awxdJsNHnUOMAVl19L
         AcHXNiu6ybCC0x5vbwqxmqzX1s3fwJ/RlYsfGhLcrZ6k2IObYIttJtdr5RVX/y8p/nY1
         saXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CJgfMj/P7YPw/LlXCqtrAgQfJMC0kIuIB9F1taTDejA=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=kvmmOclHrbvcdFt+wNnETpVj2lJzi+f0QY/9vXWa1wDFfIyx2dolYpYc/BvKPXOcdn
         BuObONn789dSw4ArnuodrgrzdTYGnIlFac5RDO3cjM5f4PvTMARpWNnSSXSTZpk8XeS9
         /d+3jxYZX8N55Zun0Nx+X2gGKZZYTPZZgGtlIFZ2UWbpNr3/UBf5rSlttYO/V3C+T8Y6
         JoIQ2O0QOKvmdnUY1W7R1mjXs9YLj/fe3l4u0R58YhxzVL+t56KpycXTmILG9NsbvqM+
         6TgEV0mbT9GS2ltotQKPa777E0/iQCKdakkmtl5UusSd9rDaTRcfQbnpFE6z6oBFcLr0
         T6jg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=RItIssP+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.173 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-173.mta1.migadu.com (out-173.mta1.migadu.com. [95.215.58.173])
        by gmr-mx.google.com with ESMTPS id b27-20020a2ebc1b000000b002c6ee044be1si480273ljf.5.2023.11.06.12.11.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:11:42 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.173 as permitted sender) client-ip=95.215.58.173;
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
Subject: [PATCH RFC 11/20] kasan: introduce poison_kmalloc_large_redzone
Date: Mon,  6 Nov 2023 21:10:20 +0100
Message-Id: <79f306b7713aa06876975bbc782c392087652383.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=RItIssP+;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.173 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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
index ceb06d5f169f..b50e4fbaf238 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -353,23 +353,12 @@ void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object
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
@@ -379,12 +368,25 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
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
 
@@ -392,6 +394,9 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 {
 	struct slab *slab;
 
+	if (gfpflags_allow_blocking(flags))
+		kasan_quarantine_reduce();
+
 	if (unlikely(object == ZERO_SIZE_PTR))
 		return (void *)object;
 
@@ -409,11 +414,11 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/79f306b7713aa06876975bbc782c392087652383.1699297309.git.andreyknvl%40google.com.
