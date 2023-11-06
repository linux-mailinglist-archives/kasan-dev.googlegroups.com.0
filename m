Return-Path: <kasan-dev+bncBAABB7UQUWVAMGQEDHP5TUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id D2A1E7E2DCA
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:11:43 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-5079b9407aesf1356e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:11:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301503; cv=pass;
        d=google.com; s=arc-20160816;
        b=iZQBAMsc4BcB22ivzXBhZZbyyrmx4jGUGXh+ONOlzhL8Ymno8wgPr4a1I8rIfmbq5x
         Y/MZH4z/MlrlTg5mPk9pWHDrMsMLEBPLZVbMlZbUNGI3hXJd0nnIbso3gho+u7ogKcDc
         23OQz/ZMVz7SiZtUBTAxlrfNXA3DPxqFES/PNk4cZAiQ7jflEirRa5b6oKApx5DtmLqo
         5jZChJIWyrgL88G9qQiXPZU9Enk8Qg4gKIhy4iaA5UggHNp04yB0q/2vQ3+3frxKFelO
         U/U2FiSa7Qu1KMsu9WtLWIGKLa5NgT3ziBepNZpeTPrvB4sYuLZV8P3olhAm6ahrLPMd
         XReA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=nbLLRH4SpKQWkEcRCTKvvpHQKUe4YIfechExNAKCszA=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=T3NkWrP1PdSzM6HZIOXFcBqxo1lgm8xHhMCNprwc2sIhsEDlkkslE0pFCdtSzxlw4b
         wll1Tu0ODjnW4YgjnxGAfpvLzLoPPLo7mjk8+2oedW9vkd39oCLj4D0HtDdR3nWiy/yf
         PQCt8BZt/gae1h54tgWp4OHeu+VKwNd3b9VKrnbsxMsq7eT7MLf6Xt8knd24IeOGkZv8
         0Ny8XuoVbvNJ/ezyjC41eo4/MUmsP2TdLP94Y2Fj8saBL6TDQxlBq8SIaaN5vBxIj1Ru
         T+BBZ+JsTI4Bbpgj2A98XtD6ksn1CebZwOd0h97eP5Xq1bRyCN/fUTiyNi+p364hyh5L
         6uAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=vvDAFFN6;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b1 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301503; x=1699906303; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nbLLRH4SpKQWkEcRCTKvvpHQKUe4YIfechExNAKCszA=;
        b=lTSKYH/nuTcj9bw8DjUzQdfXUDIHDzihbRu+euXrKoqxrUPtYAruKY6vZfikCObSkb
         69Ipwa5k3NRgurJBIXfIu1jboI1+oQ59T3f5R05BazzND8YDpdFjwSTYLYA1/k7vdF1l
         XYtVHZGxIhqhCaQL6Ewc99WPVkABoCZZzjp9+QwqXDxa8QWFjNvZtCVnklUHmJ55Db8K
         KnJ4g5ImQZTcV0+0XXbFGw+9KvLcVRIImB+c7+oAY+vGgPsmZuEfsf8bn1ER6VBBCetM
         ZMLoqEP+ACdO3/oR7kOwtKjU+lhrGbwxuxGtEtq+KeNOUDIttt3W0cqlL4eyYp9rp92E
         AtBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301503; x=1699906303;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nbLLRH4SpKQWkEcRCTKvvpHQKUe4YIfechExNAKCszA=;
        b=aO5TX74n9WpyneQU/tteCRYp3Tx7mcQpf5aTbjlQiwmi0eVSE3WDsm8dezCbJyJlto
         gn3bA8HLno7CdujUTu8W4OduOehW7Qtwz1XuVJHsAbZF9nWHdSkDeu5jcDWOtaqlJuQQ
         nqZsn2x5d8W3CCV/WEaJrWOVyr1w3h+u2LprbzA246X/pfeSaFo8aFofrUyK8O/SwzqP
         AYDQhLX1m6MyJAAmO7R+sQ7ep3dg2k1AZ9IzVxXglA0gcP639eAvP887k8skaQfXBoo8
         NkM32S4fo7vZIiK0uMka6RVS8A2zIbk2CBgAkvmFSSE2u5eh2iV2bob9XWBvfDKP8cFF
         brcA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwxLDG+ZiOouvJ8BMAagch/FF1fyzMDXU87hlLR5IXS2JO0L/te
	WWGLoq1FOX2P/zODQC49fwQ=
X-Google-Smtp-Source: AGHT+IEMWunOpvJYzBy9tALYJPY+hvH/Gb+X+0Ejti9Os08+ocB7jtMihSznUHIPwWMeBT8hEIOuyw==
X-Received: by 2002:a05:6512:3083:b0:509:48d1:698b with SMTP id z3-20020a056512308300b0050948d1698bmr27284lfd.4.1699301502599;
        Mon, 06 Nov 2023 12:11:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d08:b0:507:979a:7f48 with SMTP id
 d8-20020a0565123d0800b00507979a7f48ls400736lfv.1.-pod-prod-04-eu; Mon, 06 Nov
 2023 12:11:41 -0800 (PST)
X-Received: by 2002:a05:6512:3d8f:b0:507:b099:749d with SMTP id k15-20020a0565123d8f00b00507b099749dmr28019409lfv.15.1699301500755;
        Mon, 06 Nov 2023 12:11:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301500; cv=none;
        d=google.com; s=arc-20160816;
        b=ALiJK0KcSvF528OdM3SO3cEjzkmjZkUXQCabIexRurJIL93zErezwrBBOZFtZeT7iJ
         eBwwOepuCMVLXScI4xs4qX54fLtLYP0eKKN5X7W6jbpRpCxEoa4yrgXKKLhc81DEN/Py
         JqCflHvOAAouGDPvH+S3kSr067DxC0RN/B4Zen2CQURk3N+qzjBCcBRiMHP4LfamAmLN
         9mduG+v8yL/OiS3ieE9dMQzT1+GzmsvksEbZHO6vSTN9VDr1rkL1nnOC60Tj3J/lzWhc
         0XeLGxH1PFbco5hitRK9eXopKZcWVW/kEWYw57IM+sO428qPmJqQUqiw3ryNXeGdvDR+
         YiMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XVuFmnWl7Ai+GOwJv1yuDcJd9SrRUciNhjDptmGZnZI=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=ugeI2Uh2ob4p0pUwJ/GPas5LxlGtcX0jiBAayZEArEC83sE3ekPy7Oit6pLCmNK+lO
         OwTp8Se56uTS90LzHIcUcAi3tzujDTcRVjzRqfWQciPC1j0XOjbQCi7RHO/SqL8xYH1b
         k9IG6YuZEyv/BM5tYntmKUNRDI7S2+x8ukHOWYQIK3qZoO/lm7FioIdzJGRoUuQV54mg
         ZWEN7qLFyJRvIw49hQrNpq/KJIRZ5V/YbNJal31fnZIUSRls9Nm8hjQL508+Qz++TUQH
         pu5gd0EBAI0NpxYEco9F8oEGt9QTolr8vqfND514R/9+QNxBWtdv7dAqpl+Bd9B87leL
         RtKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=vvDAFFN6;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b1 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-177.mta1.migadu.com (out-177.mta1.migadu.com. [2001:41d0:203:375::b1])
        by gmr-mx.google.com with ESMTPS id bp17-20020a056512159100b005068bf0b332si506485lfb.1.2023.11.06.12.11.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:11:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b1 as permitted sender) client-ip=2001:41d0:203:375::b1;
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
Subject: [PATCH RFC 08/20] kasan: clean up __kasan_mempool_poison_object
Date: Mon,  6 Nov 2023 21:10:17 +0100
Message-Id: <c64f3612c31d4898011a22d10d889730a2ed754b.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=vvDAFFN6;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::b1 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Reorganize the code and reword the comment in
__kasan_mempool_poison_object to improve the code readability.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 19 +++++++------------
 1 file changed, 7 insertions(+), 12 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6283f0206ef6..7c28d0a5af2c 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -447,27 +447,22 @@ void __kasan_mempool_unpoison_pages(struct page *page, unsigned int order,
 
 bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 {
-	struct folio *folio;
-
-	folio = virt_to_folio(ptr);
+	struct folio *folio = virt_to_folio(ptr);
+	struct slab *slab;
 
 	/*
-	 * Even though this function is only called for kmem_cache_alloc and
-	 * kmalloc backed mempool allocations, those allocations can still be
-	 * !PageSlab() when the size provided to kmalloc is larger than
-	 * KMALLOC_MAX_SIZE, and kmalloc falls back onto page_alloc.
+	 * This function can be called for large kmalloc allocation that get
+	 * their memory from page_alloc. Thus, the folio might not be a slab.
 	 */
 	if (unlikely(!folio_test_slab(folio))) {
 		if (check_page_allocation(ptr, ip))
 			return false;
 		kasan_poison(ptr, folio_size(folio), KASAN_PAGE_FREE, false);
 		return true;
-	} else {
-		struct slab *slab = folio_slab(folio);
-
-		return !____kasan_slab_free(slab->slab_cache, ptr, ip,
-						false, false);
 	}
+
+	slab = folio_slab(folio);
+	return !____kasan_slab_free(slab->slab_cache, ptr, ip, false, false);
 }
 
 void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c64f3612c31d4898011a22d10d889730a2ed754b.1699297309.git.andreyknvl%40google.com.
