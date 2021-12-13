Return-Path: <kasan-dev+bncBAABBFUB36GQMGQEAKA7O3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 99B054736C6
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:52:22 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id b15-20020aa7c6cf000000b003e7cf0f73dasf15105970eds.22
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:52:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432342; cv=pass;
        d=google.com; s=arc-20160816;
        b=F1YdTDd3g1C4mlZEMva8JjjeWXmng/wnsyce+jG0A2L6WBg5rytpFngmzuydJfjNT/
         yaVcMVFabMzZJfWeWAhuPkZ2KprEqvpdgnbah8emmxIL1UslFPFgd4/d7OSu0uFmnr4l
         T4CJAtV7r2qjryPWuTCB+bqey+M8qeAkEKf+hbTX85CVitI00segqdpylELfbMJ1J4cC
         YxFnvPKqT5MzzIB+6+4gVB17E0Gdcbqsuk59ryJhrgxzImLIS0kxpm8B+bGatAYLykr2
         riDS3rH0U1OhSUGUy9zzcpeYj90oOHVqPteaV/U92/QJ/q/RO2+HGtki0sQcA1unyzj2
         gONA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Xvf/VcYBtVS4D1NsHPaRmdipdgphfyYDbZsv3zrBRUw=;
        b=Y5SGiCOYEdgiUMwqdQUQv4O4x7m5M3j5UqeGwmlDbFCnmZLuswO7UUxm71dYrQl53r
         lqMa8S8tjfMn3GDIG5+DudZH7F4aHo17OP4RBm4CAieDoiBRyPiJdi+Eqd3mfleQ3GEI
         iOHVPLKLnty8uJDE3nNqMNgAZCyyqxcabc545qhxo55No6NU7eIKsxrREkg1ag2lTeW4
         tBJXpod9+T2GCSxU/HdYXHyCFuBPE91Ne5RRc3W9gXZ7xHbGufoo6yTZSbL90RTzV7NP
         rDlts3ewm+pGL2Fc8D6jBighnFUbxBWe6o1Xy1ZtLFimcN3NH7FhJbrmQjIX2VF+DqqK
         SMwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FM4y+aQ7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xvf/VcYBtVS4D1NsHPaRmdipdgphfyYDbZsv3zrBRUw=;
        b=n/3L1A3qLOLW7klBUxGqfcaXXNKESJn6HITfHiLbtINMxNw+1uMWx2GzHtxZWiY5fS
         oWnH0l1jxUkW1e6FgWL/BwmdjoH7MthDYxwVGZDhF3+9wI/kWpr6qj5mYm+6zRq3fMhQ
         oJ2qlqi63anlu2BhqI89FtHhE2wyamGPHtgs8xOZhsQP8cMBnKCTW3QzUoM0uNiKmDfc
         24BSx1evCbGT+NF7pBiButvejDQ5U5DAtfszHMZLny7d/wyUK3NbfBudsPiFs4MiNk+x
         G+7f2GB2MvUPdFp8LdtoZ2e+waRdZu2dNrXSwk34goOUJdO5Aemy6SCGWLDO5ZLD9lv5
         8uFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xvf/VcYBtVS4D1NsHPaRmdipdgphfyYDbZsv3zrBRUw=;
        b=0F9UhsFZ7Izl6eAGXOS+aUOG9BpgtflHAf3BqS4+s1/6/T8stI79VDChIQkIZ40r55
         Q2786Zusoj3+cx7EfWSuHRXAA93TheVwlD/itFSsMnhx7QwiU6YKdJ7zo1WGRpSOYaeE
         9OuWvfBpioztu8vFyI6PPuwqPDhOrKqJmnrqoiM/fHJOUA8TjKLsGnYZ11IF16sOp03m
         WyCIzdfikMYEwYTXuHPT99EgRCoL75LQaqMRbfnKtaoTS7oQ7TreQ8JVvz4+/+S0kCK3
         nUSkqifbczSVSBrF/aBuju6Sa8cXAgNMy22CXzOb1S6dTLXBZCrvhOrFCr/3hKjxIt0u
         rLsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532D5/dLbd7T4mc2jU90lsuVfAqBe2wSwy0EvFUm6WaCU2isrroR
	AvD7hol4CoqrPptl9jcnTN8=
X-Google-Smtp-Source: ABdhPJzVTjFwLlkcjwSdG+JHZEeegfrMkcQaPHlP1k58JIqnXXonmrschnCAxM/Ei6nNUnlF8+tVIQ==
X-Received: by 2002:a05:6402:35ce:: with SMTP id z14mr1989649edc.197.1639432342260;
        Mon, 13 Dec 2021 13:52:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:3e9d:: with SMTP id hs29ls1783562ejc.2.gmail; Mon,
 13 Dec 2021 13:52:21 -0800 (PST)
X-Received: by 2002:a17:906:d108:: with SMTP id b8mr1110725ejz.531.1639432341488;
        Mon, 13 Dec 2021 13:52:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432341; cv=none;
        d=google.com; s=arc-20160816;
        b=hzDzrL/yJ2p5WOQllh/dnqI1X7n0s8MRN1p3gTh5q9z89/mXwCk+rnlnguOy66qaV9
         CVrltM8mm4b1rFqhSBdw9yn0WeyhcssDzi1Y9y5XW8lLDi6KDehwv37J7RoEkgkbcjOO
         VdBEG/cNNlvfwMGWzTiixMJtrQkLO8+z383mGqBR3jcVv4yWwMz0fl8wYASNMOSPlBfM
         Oj9u7pr4Hw7gkqs4QcLQh/AuzlW7HCgR1Y2N3qe+8nbY/IHywHK+mSogoT6a+YYKD9ab
         bMUaZeQYkIU9mmtqiErXVVzFehQP045GPKgYAAzzQjDZQtJ4zBNqjIkP5PZSOoWBnAUL
         I8Mg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gqcu4c/qGBfU+tcfxtJaqCDYtMZ1wQFz/z4e7pH0AQw=;
        b=PKWBuB0aukaUD14y0Mue+RLfeNgQSZzaQwj7c2rP8pcwzT2WK1yi4uC4AsDt6/E5nV
         YjiarMxBzoHRhNnqW6TlGmxJ7oT2xJWHswBFkC/mhXDJVTToPystfLVp5HKcIInTLRjW
         6sPIc83BDFbA0YQNlDUGTLjn9xgxoa6K7F2ZC4xZXtMNxzr3JMqMmWDrKLTWAPj09ma7
         rxjyXD9s8o8OCxjSjmpbX+gxrFT3IxPNYDpesf+oqiLFbL1BqcK2Ixi3RHJ5QTv86ZFK
         ZhpJuceMmj2iF9YxgyLaRZ96/qN/i265HLv3OUp5lXMdEjfLTUOY56EjLiAFU2cATUWh
         OYuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FM4y+aQ7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id w5si520061ede.3.2021.12.13.13.52.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:52:21 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 04/38] kasan, page_alloc: simplify kasan_poison_pages call site
Date: Mon, 13 Dec 2021 22:51:23 +0100
Message-Id: <4b39d778ac71937325641c3d7a36889b37fb3242.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=FM4y+aQ7;       spf=pass
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

Simplify the code around calling kasan_poison_pages() in
free_pages_prepare().

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Don't reorder kasan_poison_pages() and free_pages_prepare().
---
 mm/page_alloc.c | 18 +++++-------------
 1 file changed, 5 insertions(+), 13 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 740fb01a27ed..db8cecdd0aaa 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1301,6 +1301,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 {
 	int bad = 0;
 	bool skip_kasan_poison = should_skip_kasan_poison(page, fpi_flags);
+	bool init = want_init_on_free();
 
 	VM_BUG_ON_PAGE(PageTail(page), page);
 
@@ -1373,19 +1374,10 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
-	if (kasan_has_integrated_init()) {
-		bool init = want_init_on_free();
-
-		if (!skip_kasan_poison)
-			kasan_poison_pages(page, order, init);
-	} else {
-		bool init = want_init_on_free();
-
-		if (init)
-			kernel_init_free_pages(page, 1 << order);
-		if (!skip_kasan_poison)
-			kasan_poison_pages(page, order, init);
-	}
+	if (init && !kasan_has_integrated_init())
+		kernel_init_free_pages(page, 1 << order);
+	if (!skip_kasan_poison)
+		kasan_poison_pages(page, order, init);
 
 	/*
 	 * arch_free_page() can make the page's contents inaccessible.  s390
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4b39d778ac71937325641c3d7a36889b37fb3242.1639432170.git.andreyknvl%40google.com.
