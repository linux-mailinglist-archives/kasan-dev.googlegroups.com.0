Return-Path: <kasan-dev+bncBAABBK7ZQOHAMGQESUPEMWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id E520D47B572
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 22:59:07 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id u10-20020a05600c19ca00b00345b2959e5asf205423wmq.9
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 13:59:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037547; cv=pass;
        d=google.com; s=arc-20160816;
        b=Esljedspq2Mu8TWh3SrqicbhQi73KcqEi7/Y6vINckcgE59MQSolOP0g/E3PutwH8N
         ECKNErScu5i7a0xoa7TZ8PpS8OKt40XdXQHRULxGPNuT0g7P2ly0I7c2kbgXnUykC173
         MUWi3arB/vQ2mAp9yOxgIOIjdj91ZJL0wnB8MLQfLS9MzYtBSX58VMCIm1Vcj73EwPfm
         XnQWj76V5sxmUQJlEodJCgxzmkH++VRKkam9ginPi9qMVYd4wBwugoG+MMnB6KFZpOew
         FkAL7IffHD/rAoqL4RWiaCKM49FLhoDIMwY95m6+z0JAh0XnginD1YkU3LxoVtjKFoSB
         sSGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3oeMczgS37fVtGNzapMK6ODV2BWviG0KvYQpzuXvfT0=;
        b=QDeT3v+dVg/7JjYXNCWXJ6FDtmCoK91Rq06yl3Nrhkb3MVimAeC8zPOV+RREycIHXC
         pN0esxujJBdF2HNx2bY8AXA9iiGJFYWg5wl/9zNYV7mmqh4nQudUKfA4QtEObLGad02W
         gqZplzp/mGG8PFXMJ1UQygkoYUyCg/hrExRd8x07yLjY6kvQ2mL/cf3KA9d0EiyNTlA/
         zJSypC5P1XJT82+r8DBrpLlohDuitGYRFsCm1M+/zlsl5KDp/gHChd2UJJlcr+KteUJw
         sQNR0CxmEURQyTbCajg3IwXtrkbF3+Vti5LVfU6s4J1D5w5f5gO6IPb/Kza6V73KTc9d
         056A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fD1DHrBk;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3oeMczgS37fVtGNzapMK6ODV2BWviG0KvYQpzuXvfT0=;
        b=ddKu/V7Be0asWuauShaVqjX74YVIyVkgvmctUsKciJU7tqmwn7IgoWUDd9SiVbMfYp
         P5bpwTGc9D8Mf1jQ2WvdPoSb3+FLcmC7iUhp2TrrLWwBWM+v8oqpqbPrcK4D/lzIeX//
         M5QPGK/EEpuWe1xUupgPCALTPZmFilNZ7GJuWoLsvhR7U2WRe1iQx3EQVi8RxNDoFRh2
         atAz8WPPp+TRpGQUAc7VAzLkOm6K376d9+vYnWb2feWkd8i5EBN19VwwuDB2xaIySvao
         6IPQH6BMmFzw7gREMkH7dtvbYj1+lmfwiOLKkMMLqtC+h1Nuv67kW2hytbYFyc8tG1+n
         XEvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3oeMczgS37fVtGNzapMK6ODV2BWviG0KvYQpzuXvfT0=;
        b=nyi6qPQzlk6AvmEWv1OysCEHDxLS8P0yEOymS7u79KiUbf+8xtA7zlAM3l3DLNhy/m
         fAvoJttV5cIGeyyHKUSkRdsZBaQrjj4Nr9nVhy6X2qacRRtGgUg3pVF+wlM+KA4jKDdb
         nE5s29aZsZ0I4JdP2hril/0VO1qCfnTtabj7aUhJd/w0Uij2FYQiFUqN2puBKbZVqS/f
         ML/ucWD4KaDTx0YYlbMtM+dDM6nnsUNlFfrXrqrVOmFGvtC0c7940uFQPhpOGDRdqFs6
         uU5WyJJQDOdfM29i9hFejGIFYBlCJspyC5YDVIL26a8z1+YHmO0HMdyhPKu91fu8gRz4
         Fhmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531h1mke9ptLnZl82nO5cWH2wClAzoQvo+7K8bBOvkXwfKW/Ov4X
	iw6MtyE32ZMPr71shE3HGGY=
X-Google-Smtp-Source: ABdhPJw959UHLUJnJbANNJ1/6fcVnW89scADOcuie+xGnHdWdkhKrpaEMcH+VD6n+LqgB8/67xYE/g==
X-Received: by 2002:a05:600c:3d0f:: with SMTP id bh15mr39796wmb.27.1640037547622;
        Mon, 20 Dec 2021 13:59:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a4cc:: with SMTP id h12ls1062730wrb.2.gmail; Mon, 20 Dec
 2021 13:59:07 -0800 (PST)
X-Received: by 2002:adf:dd83:: with SMTP id x3mr86409wrl.367.1640037547073;
        Mon, 20 Dec 2021 13:59:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037547; cv=none;
        d=google.com; s=arc-20160816;
        b=O4geS03QC3y0JEsl8ZOQdT2uYQ8gx6m/10lml9jFuNmjuM/jazwox3c+Lxt11jcRNJ
         KgOCTlzba2AD46oaS9YVhYdY7/QKSXYq2Rmw0BVVjC88IA8qLA3XoYXE23ftzQsUvaIg
         PdGLMMXzmcpYa65KLZdnoHHhzSMlGlqC7erVZee8xTYntkKfsVnFPbAZLoHbbkSOjl3u
         8SOTJuuQkUfXXHGdzaZiahRCFCgfOQXW2lC2R1zer/jCtV0XR/XtTwuFF4rq8DX6Ilzu
         KXr2mlfAPsi8nGFV5x71uZ7jC0W4ZnXh7yfMawV7NpEvz23XHnHs1icn7BMVviA16okQ
         E2XA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XkeG61daTFX7J1FyY/zY7cuAXiWN8RkE/cJVJDUGkAM=;
        b=nMBN1wGuX1Zj9/SkTeQQlI+JmgrnrsNxzi9rYFZq1Lev+XltT5QF0q71AgjWLePJPY
         u4oAJbiBobQxzaduhwtYCzpSiKOvgs1OoQR53we2lk4BVr5HRwsMICV1CvasGk2SWdua
         rB7kVJOS3eCWrfdYxYY+u4VpEFr1tBCSED6ybfnEN5k71fQFZe3HNdNFKsYemVXTpAxs
         1b758wvzIovu08eu1m1GPr+p/2YQ5Gw0ExnEdf3bJj5WtbPiMXpfIQze+oyDrf2OKBTc
         8eGRQZjf9erM/XQMg5wIBZWywHRFosW5uSu2ORvlS2eWWaerRgMuDWX7RoDnyffFhEl2
         Qqsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fD1DHrBk;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id p20si19128wms.0.2021.12.20.13.59.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 13:59:07 -0800 (PST)
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
Subject: [PATCH mm v4 04/39] kasan, page_alloc: simplify kasan_poison_pages call site
Date: Mon, 20 Dec 2021 22:58:19 +0100
Message-Id: <95edadde8d5a2e5db80b9050eac745c8f1cabf3b.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=fD1DHrBk;       spf=pass
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
Reviewed-by: Alexander Potapenko <glider@google.com>

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/95edadde8d5a2e5db80b9050eac745c8f1cabf3b.1640036051.git.andreyknvl%40google.com.
