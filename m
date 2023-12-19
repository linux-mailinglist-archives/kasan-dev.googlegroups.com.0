Return-Path: <kasan-dev+bncBAABB7FSRCWAMGQEQYPYD4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id B6BCE819389
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:30:21 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-40d2f0a9635sf96725e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:30:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703025021; cv=pass;
        d=google.com; s=arc-20160816;
        b=e2KscfMfrrpYVtkHhYLnpVMEg3Hw4hmvwU25MZp5EAgA5PPGPjblzXzSH27zY3zH/n
         nCUC8+7IkmAzyfvGMcLD8YW07YOVbXsnmmWkQBVh/hjIeFDrL3PP72ZiGvPiLsecBZWl
         g82bnBptuUuXhXzEFye050orUPc+R91toagG6Il6kKeamTKZs+lfqKJ6Kx9nWU9Sh8FT
         h21bEINI2xyDWS6ISTchUvmziBjpGN9Hg5LBZ0uwkfjY0YaJ4qzXhcwxlSvn/eoT8ksp
         71nSEyhm+p2D4rkYzSUZx5qZMtbidc0jnAZV+OujZAp1BaZf1Cqocmqzz+OJHjzKZbxS
         Q4ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rqXAwsLXb9pFND2Tah8l+ru1ViikhpxerYJYIr7MtLk=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=puPUKU+tQldgUWiiFYJkBh0ehmXrStq+5ywlNsgB5ibFLYhHvyCcftQOr1fNkacYnV
         ARQ6xsNCXudSt3+8HChvjkog+dc9PlNh6y+ojoNDsl/F8qkS0ll4kPmUkkPvFewvN0u/
         4cen/wsxUUysWRx44BqJ9/SVQruXIDXNK8tMjF4Wk8X5+UQE0EuHyGqBPluykw0Ed8iR
         SRmiUYjZRb8aHdD/MTeacqskgd5DNuskJeX3OnCRVngobI7IbuWHOkhdiC3nJnFFTWKE
         im6FJdIIUWJTA1Wdoh4yN5EHftyOCw1bqBzef28XPHcyBjN492QGbntVeaBuPmKEwyQE
         ev7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=aMTrQUR0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::bd as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703025021; x=1703629821; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rqXAwsLXb9pFND2Tah8l+ru1ViikhpxerYJYIr7MtLk=;
        b=mvNfSXQM7X9r6OHOFHIV00UhRGvrKBHPZAVWMHRSXPjbrc+iSkmQ4MpZCDk4AEscRj
         ulE1b+D3xcod3WNfCl68jp4Q9CAVhF2BHb1RrNnmCKmDKOjshFvCFi9lTp0Vjzz5RS+9
         BDqQora8e7yUJgMxyqcbNMYh6mtcq00kCaeTfjIqkiC2tgK/HXvMVh2DJnWs/tKJzyy3
         sNu/h3YRYP/Ig5RwEMcC6qd9DkfQDJf8c1EICtf58E2mg2w5q3msN7m92KsAKqzsv02i
         hziHaKYL66KK6XrbZWkVjXo+0OLkOHV8RrFueOELeQ6EzdNy8NL0mbC4jM2LpGw8Fm0n
         zhOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703025021; x=1703629821;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rqXAwsLXb9pFND2Tah8l+ru1ViikhpxerYJYIr7MtLk=;
        b=FqOW5dcVTVj+tM9ysHgI5kP2ORmY4e/DqinoLnHh/rg9dXIB6VXd9MEmJHvuXRwjb6
         DhODqSwiFikeyhMsrfs22S6HIesROu2oBGZIvnLFWxWSSo4PqIBdr3eihyH29aBLpj0D
         mm7MJXefTJVYZGMNix2A4YPgWdxCKh/x5W36K1+Ni+IFURYcOP4OBwvptCTDzgDMhVzT
         bGF8fiyong/XbWpMN/IGcex+lskfSUuoln2UCwEepL5jWZVwafWYCe9RbsMlfvB1enF6
         1QgMgQa5f/OjGWJlvnJw4sVSiEIAD5L9SNavaMNJcnH86eSCO6ZPM4Gs9U5feij6yKjf
         EBkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwQgaA0koK7Ixij573XNpH/P2ZpVOpfLZXoR45DNl4UHOuMesmO
	wXh7uXTr+40CN1BAhfmAnOw=
X-Google-Smtp-Source: AGHT+IHhPNSlqHpzRrn/mgRHfsTybySHKGpLkrWnbvf7uL2mdtNTkhMizQbq3UTMMy+9i4p+yUQ0JA==
X-Received: by 2002:a05:600c:1716:b0:40d:27c5:9c16 with SMTP id c22-20020a05600c171600b0040d27c59c16mr61635wmn.0.1703025020832;
        Tue, 19 Dec 2023 14:30:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b83:b0:40b:425b:2bd8 with SMTP id
 n3-20020a05600c3b8300b0040b425b2bd8ls1116077wms.0.-pod-prod-08-eu; Tue, 19
 Dec 2023 14:30:19 -0800 (PST)
X-Received: by 2002:a5d:47cf:0:b0:336:3db1:1c1f with SMTP id o15-20020a5d47cf000000b003363db11c1fmr4589341wrc.235.1703025019272;
        Tue, 19 Dec 2023 14:30:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703025019; cv=none;
        d=google.com; s=arc-20160816;
        b=YN08jfQ8Y+cW3pYPq10i97eJM72pZiHJ6K4cddUm81PU0tcMoPtSdphcTLmSg1vboG
         87QyCsNqv/k0xkbTSS4I9kLF0V20kopqBzd984dG0ltcAS4b2rytYXXvPNgahvOl8Cc6
         F7rn3gOptIillst910Z88bHWupt6+aoKzaPFsY+qk/0qciLUz3Gr84erVU3pkYuZMU6O
         FGgEvpcER1qDeT6ip67Z/nfxtdbH2vqJ4RUxWYC3RIOTW+tbHAnUgK6r0KXNx4+lEStv
         8ysMxW7BuEKpkcyM3qfJFI1oKa/q/1a4TsLibZu737HgLqd6aPJE1OFX7bUAItMMC+u4
         4Pyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xReOl/oREsxJLQ8k6aIhVhARLuZMnM3hsCknlxTDelk=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=fMA+636QZd+Ss4GY8EeLS/8sVPy7nJrsD8OXIpO+hhTWpbKnuXFMehCJc4Ms+5Pj0M
         c8pFPwwjAf6Ql/9HFWXar8BCejBRHfr6LEtsEJytXFcHqIcn4kmjnHy9TLKpu/X/KYPp
         BJm/ey8GYtUOVSa1v9Ng/TcUK8+pi8NnIY3ibYJOWsJg2El6FuNfGB/Vv9QyslXOGogV
         PRwpfONunNKqLXCR2S4hvHDw9UgCx6Ooh3705OYPUrqcPAM1e20F9/ZP76qMdeqWgBRU
         B77dc/I7yxVDQFT2Kt6iGRJnHDtuvkzBm58yGhk3J6eg/G8Pik7DRfvy80unQ415Tktj
         zNeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=aMTrQUR0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::bd as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-189.mta0.migadu.com (out-189.mta0.migadu.com. [2001:41d0:1004:224b::bd])
        by gmr-mx.google.com with ESMTPS id c18-20020adfe712000000b0033666fb6212si263181wrm.8.2023.12.19.14.30.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:30:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::bd as permitted sender) client-ip=2001:41d0:1004:224b::bd;
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
Subject: [PATCH mm 08/21] kasan: clean up __kasan_mempool_poison_object
Date: Tue, 19 Dec 2023 23:28:52 +0100
Message-Id: <4f6fc8840512286c1a96e16e86901082c671677d.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=aMTrQUR0;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::bd as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
index 7ebc001d0fcd..3f4a1ed69e03 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -457,27 +457,22 @@ void __kasan_mempool_unpoison_pages(struct page *page, unsigned int order,
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4f6fc8840512286c1a96e16e86901082c671677d.1703024586.git.andreyknvl%40google.com.
