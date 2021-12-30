Return-Path: <kasan-dev+bncBAABBMUJXCHAMGQETTG7DPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id E2F37481F7B
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:12:50 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id ay24-20020a056402203800b003f8491e499esf17572342edb.21
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:12:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891570; cv=pass;
        d=google.com; s=arc-20160816;
        b=CZLwZSESomUfuwys5DrLb33RGMGAC7r3G0CE1iIZmuWMMkDygwLuJ1yRUADgRSnF6C
         /DdH57I2PqJTz1BVB9/J5T662WYiDlWsPTzuHfsMQRnQTDE9Hvnntp8GHvcRqGRUfSQY
         /jMDffNbcMTc2WmAktor4mWGo8+AAb+MliiY+VpLvMrAS1cr0oKVPoA8qKpwU17ke+pX
         yl2HD3S0FSyxgt7s85/k603tXljAkAjwVpvbiFcqSot3KN1MnT07y2X17hEBUeAkHZX/
         hCeCcpp0acgMWNRTvKCCU87XaM8RvEHX6CPxAKkXixxzNXcr0/pkRgd8iL3jGusIN2A5
         0p7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZY0hoC0qdqXAYWhM51iugjI7SsIjbUUaM7wn72azXPs=;
        b=fCH8Ad/QZH2YuvGMJrV3QrSXG248W7DdZVvgMHO+Nim4dclJjTzBMW1f01bKULdffg
         BajCrrxRHm1tE3nstykqcQA0oaUblZoqi6OZZ0dra0Fb12+fddKwQ0MqT0m+G8N1KvgN
         jHL1N4Q1ol8fUOB9YyUYHtX4IhmhEwPw9f2XCpDRV3dFoNG78EpngySyxDpHM2aS55sf
         Bo37NLDYp55E6x7x3PK9I+GzkIDcimUvPOIuQTK2fGP2GoUCXJSXTw5G77kLUIEljKvF
         OPEAFBT6K5zYFnpIuMDkJ17A0p/LC5cCDwJgrG3sSpotwFPAPYkwftJMZMJ/vA8xQd6R
         Z+bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=M9AIbRJH;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZY0hoC0qdqXAYWhM51iugjI7SsIjbUUaM7wn72azXPs=;
        b=R5wTllNCnB4sau48MyPwtM9DaWRCLrEO7MjchbfjvCky3D0sV+u0SEhD2ZEB7PvHMZ
         CWSRz//S9lu6+t90a4H5olkLsWgAEp0yU3/Fld7Q+5Miy/jzTPe79sx32aabXKhhsY0f
         Uj+hGoImUPgfYV+9QZ6+2DwPhjD4iAKPGsO0AS8YXokmd919n1z+XzId7p35Xi1Dm4fK
         v64q5RZb+vkSNYW+TKJBtKtIfh22HgVGI7bPcm+qByuL5Wlh0jVjuGX1P5Ejuxtn2zc2
         vURrt9iWHzZsS23wZImj7HNkc9AfP/zgraEqtK8J3OQoQFbB/8bh8KrygBOYPegPGpRd
         w+Dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZY0hoC0qdqXAYWhM51iugjI7SsIjbUUaM7wn72azXPs=;
        b=LOTeyA4zOtn5py9Mo+JJR8GpVaq8ax08mBL2sCovlRI6m0U+2d6YTxEszdsnZMeZ8x
         OcrOGzX2UzMrC1+5mP42ECQ9haoa6FXd2w+lkw4le4BzaCFD1fP1/K83AHJMJzORGyVV
         WMSA+9Z+oKNzGoiNgyjpZKAj2eDUjiNUgfAZA0rFlCBZLcaqfCIcxzRZQPNpqGdWkUm1
         mYPUVf2+rUS9bzqPCJbaMYC+c2CfRPQ9gHTR4nH/Mqw1DRG+lmBtrjiDVhWhQEi//CqX
         4G9HkN0IY5/igT4RfYhKDWAHKpRNcOclktNlHFsN3E/+vXcnO7kf1ppo6jp/JpWv1K2j
         mo5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530eQ0wUibHZM6Gu6Zl/2EjkmOMoCz3rcP+NeIwaY/qTfgsSORxs
	IW5OIzihMtAQkSSKMpqnIzw=
X-Google-Smtp-Source: ABdhPJzxkP12EOzkipMWM14ZY/XCP5FNf6DFtoEpvAtDqgLtp19JA1MB0fo/HEuKWq1/HZA7jehQ7A==
X-Received: by 2002:a05:6402:1e88:: with SMTP id f8mr26374229edf.2.1640891570584;
        Thu, 30 Dec 2021 11:12:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:6283:: with SMTP id nd3ls8529765ejc.0.gmail; Thu, 30
 Dec 2021 11:12:49 -0800 (PST)
X-Received: by 2002:a17:906:b1d0:: with SMTP id bv16mr26148369ejb.742.1640891569853;
        Thu, 30 Dec 2021 11:12:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891569; cv=none;
        d=google.com; s=arc-20160816;
        b=iVXMOPsBM8CQSSBPGTeWw83366H12HH/Ka+nRiyotCqSqhJiskrGM3kRz6b6a90T1h
         hP11bqo4P25DQsS7bBl+61sE7at0+1TtcoF+kLIk+BAHen4BfrwE86nqTl8/E7KM6tLv
         DupeV+Qr+EKFeq3eFKZxNEZ8HxJb+Cul4eJ/G7W84Mqo3w/GbCLc/tKjsXZ7RDtx1c4k
         XIiIy0sNCXxXWBCLaT/Clz2/FxBRH/+W8Lg12t0GE+6tnL2EneAFk+Y6fZsZDoSWqgxi
         w+A++doIyq9/1oI9aL/hxnJGbqlIV/E47zu/ouRysyETlZh3HXwhKSgJrAcQDoVOm4AQ
         Gj+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=g5gujoJe7tlTEHNd75FmEH4gVGMW7kwinPcf7But3G0=;
        b=qUoSZfq2q9o4ENXThx57U5VWcMaQlonio99xKERxGDrPW1HCm7KgeYR9HNgYilTe3v
         TVPmzsL9s2zOwhN+H+Aqd9YJR9mEFKPgm+UMww9Erk3Gu7eWFlf0S93C+HiVZ3bQxsvB
         IgVquKdEAxvFoJTR7DEXzKVmdfhcRlgrQRgo2Biufy0r0m/HV7/srFMJ9fiR5E9DTadf
         xbcS/AibBpqohHo0ZwBaSqvxOV2Rj8KvmL/D2eAPewRaIKTzjQeSiOtGCgcGzpm3Fs67
         2nr5j6UtABO6kgjY/tUXXyNZa9UKsoGqy9skCjZr/qzRP7tipkmgvtwldQIGW6cq6T9r
         EJrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=M9AIbRJH;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id v5si963059edy.3.2021.12.30.11.12.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:12:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH mm v5 04/39] kasan, page_alloc: simplify kasan_poison_pages call site
Date: Thu, 30 Dec 2021 20:12:06 +0100
Message-Id: <f37ad1ea8bb3de2ad3a5fa6a2d9cf6d05c49fad0.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=M9AIbRJH;       spf=pass
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
index 01dcb79b3ee1..f78058115288 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1302,6 +1302,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 {
 	int bad = 0;
 	bool skip_kasan_poison = should_skip_kasan_poison(page, fpi_flags);
+	bool init = want_init_on_free();
 
 	VM_BUG_ON_PAGE(PageTail(page), page);
 
@@ -1374,19 +1375,10 @@ static __always_inline bool free_pages_prepare(struct page *page,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f37ad1ea8bb3de2ad3a5fa6a2d9cf6d05c49fad0.1640891329.git.andreyknvl%40google.com.
