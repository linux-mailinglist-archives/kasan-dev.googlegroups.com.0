Return-Path: <kasan-dev+bncBAABBN7ZQOHAMGQEADJYXHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id B094B47B577
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 22:59:19 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id l20-20020a05600c1d1400b003458e02cea0sf219763wms.7
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 13:59:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037559; cv=pass;
        d=google.com; s=arc-20160816;
        b=maE7MboJvdCVoBko8DZn9PnbDjxFadB1k8U0eAZ2jSzJjNszNMi/Vb39Kg19RRSxsH
         BJYZ7ykdoOgK/zHYO0/wfbdPApWYGeiAY8nNI3Pn9p4NQbDdmfJKtyYnGnMYosB6fnef
         MRgLs8FdPFwVU/fjWHd/mA3mddYiw15YnRzWehdo+HrDm9arOCPVaK1h9vWZZLKKDqSJ
         FDUAQg6m+Njg5rfMbj5woNvRCTQ7131q2b3omhGslDziqxZ+T6CTkM5P0gmujPzsvVT8
         B4sy1cOePmEjemU24/SQsdEkf/IdPApKxN0r4jVQeBVeqJ9n1uywBy2/pFQwh1hx4lQp
         20sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ddyv1UfYSJECR/nDwnK0N+nP6cL/JbUNoQ9u3RvT9YY=;
        b=SR2cBvEMXEnncSnhjR40ru5TwKDk7LLI08RmV/A2YyRhSp6uYgS9u9TnZO4nXlwhHV
         en9zXc5NXnPkX4LD6+RoLaeYXtezsH9qSwxnU3wCAUr7tEM45mAwIQQ+yIafYjPzf6EQ
         rCquM4LjrUnHQI4e8Nv/Y9IyxNP3wPpp+Mmc5Xm1C8MkiszaKNUyuk0HEuS5guvKFQfM
         z5k0gCLUsqXmwpb4guvSif5NInDcoBet3saJAUEC/BZ/hs+7yJg6284aSdz/nTHRGsgI
         hpS0Aji7awjIxD0cgV699VgBHutkFrkyLjEpGtYDuqm/XJJywamQVZAhG6vlUX9cOX8o
         ypwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="YZcT55/9";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ddyv1UfYSJECR/nDwnK0N+nP6cL/JbUNoQ9u3RvT9YY=;
        b=hRu4guRZzFcp4al0KByjd/S9pYNnH8PI26/ktsgKB/oZAyZsmtorWL1ouF57HSdVzR
         XSVuM7i1ReI1+kdYMzcHRbdXyW4wHEYQ4ijigGJ1rPqsVCm8po6nIgy51f/Q80vvzAeC
         dpQ7ErtjN+yBCY5QbuAn42i+tUAmulA1ntvTu51RqWkSqdL2nt8gImp628U4TGaZhpqA
         Caqpud8u+fonMVcvSDAn9k250aLvFpf3rIm1EvU4eKmITtMCk81BGCDlQqcUqsZV7r1b
         i6lPS1/ZUpxEm0ZTupnyqyQjJJJZt/tMcBn9yGFqVW6/Z+DTyHvEzNJ1h01Ihs51zJgU
         OZ9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ddyv1UfYSJECR/nDwnK0N+nP6cL/JbUNoQ9u3RvT9YY=;
        b=4VzL53QD8KCioKd/Qounj1xajiF1FJ8Lhbb86ken8RKAdqdzbB4Fd6lZipw/Q5735F
         gg7azCFeLy1zSXUQYeNCODn/vJKf6EfA2VkL6wJbNOtnx0Tn2LtAuXgAUYUCZYiQ5QAI
         9kyrX1rTolxmfkkbDujdY43tJBi+r4nvQg0Y/8dKgd0eaXKX0UmgkQ8RX/+khqn4whRR
         oql0Vln1WuIRuN95QC8M/Z7VW5UmtQLgbjtjrHI1lPpHjzWFCnzYYjcsbFinZQ+tAUz9
         5XdR2llGzS72M+/nxi7+XoXZuX4HZR6cck7Sib3dxADIO4DnYK/t75LL3Uu8ITD9PfKZ
         JTRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533KUs4DR0a7Odr4M5DBeHgzgH3yLEn3Gg4dwf9FOtZqaokC84I8
	QkCpxQ4q4tedni/ih1QqzDc=
X-Google-Smtp-Source: ABdhPJycoZqdfQEZ9H1FaBRHSj/QWiVovmDR/7XK5cDMWn4OkOOxQb1u9GpSmOPfO86hfmnMRZ0N5Q==
X-Received: by 2002:a5d:6dc1:: with SMTP id d1mr116351wrz.282.1640037559505;
        Mon, 20 Dec 2021 13:59:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:522c:: with SMTP id i12ls6375214wra.0.gmail; Mon, 20 Dec
 2021 13:59:18 -0800 (PST)
X-Received: by 2002:a05:6000:1843:: with SMTP id c3mr114757wri.316.1640037558745;
        Mon, 20 Dec 2021 13:59:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037558; cv=none;
        d=google.com; s=arc-20160816;
        b=gWMDj9+5gpU3/pc7zEMMVB6XL7wFmF9G/mDQZxEK0zwfL099j48uRC8XdQzqF5S9kO
         Fp8wHAUIdHT4YQzOTeNzWtsxzKatYDZnFwQG2NOkGium3rVkhTY5bthWSSXNot9XQans
         BESuLPpcz0JcCeaoZW9BxOGnn4ZKeewlyN2GtrnoyRY8N86ykCl1sCTkU6nA2+S5XYLr
         aEaHUpPxlGrElTD9sGKGOzhIe9N+f5B4fx9D43JCNmal5eS5fEDlWkEtygG3PGJJkA6h
         65Kh1GuNUiA5ibVmp3Omya09MzqplhgxdDyZ2jvphE21a6SxSHMtz6O84lM+//vTCpWM
         HdJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=cxvElAXzOKVErefTs0SDL10+kOEEoku9HnbkEr9+Z/k=;
        b=TuOjbEvmclt6v6xxNZJSQzYmB7Xyq99MKMw2zIUdlU3vHJ8t3Cb5EFPxtqO37bgrta
         PehPfZZ7zZRXSPPzlASW+FzSAjqxpN4WlF7ijgd6T8bBq0DOfZdLFWLpNyL+51//InOu
         YiRmDzjPuZjr+HC5js50nS/8YnrFfrAkLUtM+xg3iqJoajk0a7ZFZYf70fdyQ/9bwYQx
         rl8igwxdrmB/J7F8Ut91m+2kh3sT36IrOnpaVRNyGODyQBUXOi+W/Uu7a8aLci6XueFQ
         vQHVhfNy9go7d5tJLtQ3cZOb1bXtWytu1CKgSsXM46Y0qvtWQFrk6ZfqkxJQNkGIKCIU
         wGFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="YZcT55/9";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id f15si289157wry.1.2021.12.20.13.59.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 13:59:18 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH mm v4 09/39] kasan, page_alloc: refactor init checks in post_alloc_hook
Date: Mon, 20 Dec 2021 22:58:24 +0100
Message-Id: <ebc657034b70b03c7cbee1337c4d8cef8518cce4.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="YZcT55/9";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
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

Separate code for zeroing memory from the code clearing tags in
post_alloc_hook().

This patch is not useful by itself but makes the simplifications in
the following patches easier to follow.

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

---

Changes v2->v3:
- Update patch description.
---
 mm/page_alloc.c | 18 ++++++++++--------
 1 file changed, 10 insertions(+), 8 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 73280222e0e8..9ecdf2124ac1 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2419,19 +2419,21 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		kasan_alloc_pages(page, order, gfp_flags);
 	} else {
 		bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
+		bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
 
 		kasan_unpoison_pages(page, order, init);
 
-		if (init) {
-			if (gfp_flags & __GFP_ZEROTAGS) {
-				int i;
+		if (init_tags) {
+			int i;
 
-				for (i = 0; i < 1 << order; i++)
-					tag_clear_highpage(page + i);
-			} else {
-				kernel_init_free_pages(page, 1 << order);
-			}
+			for (i = 0; i < 1 << order; i++)
+				tag_clear_highpage(page + i);
+
+			init = false;
 		}
+
+		if (init)
+			kernel_init_free_pages(page, 1 << order);
 	}
 
 	set_page_owner(page, order, gfp_flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ebc657034b70b03c7cbee1337c4d8cef8518cce4.1640036051.git.andreyknvl%40google.com.
