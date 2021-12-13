Return-Path: <kasan-dev+bncBAABBGMB36GQMGQEVC22H7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 655284736C8
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:52:26 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id bq6-20020a056512150600b0041bf41f5437sf8064852lfb.17
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:52:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432346; cv=pass;
        d=google.com; s=arc-20160816;
        b=LL1V3+cEKgdGdBM3efAwDY4cdyV36gRnAtGQP/wt+A5dUZKPusR3ZLApYIXc3hGp/M
         qT1pU1unwuHvUKKrtrS8RIczqyG8DDaqQEOjLtAaCDPm9/aY8VkWWHiJcVvpmMLIzTLl
         f6YC7VgoEe8YFqVXdobZ3WKMBKWFheAbYh5Jha7eolNMhXmasrMGD9N7y2wlmtF1UE/O
         kfp6ILsSfq8CP7v2Soi8yKbicEhdAahx5VPMvQhdEVPzvdJy7EiHV8bJCbQjVJde3Rr4
         zVFk3gYVd0ceBv3SvyV5hhw8YLrIt4UsWsErMW51n76wZHlose8IEPVNEVh2+HvsBNAC
         odTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XFGRMZuZYszmDxa+gjcbac6XwVrEjPpy4VtQ1z4a5Zc=;
        b=dpuPGn3t6uhFZ1t/P1uqGTOSgAKxEDkK33PYXdi0FDkPamvlA6sbUoSvK60a9PGkC6
         19zLzuItp0lqGucI7Fcv5ixtTwUqHk0RgvGZcq4XNS5gTuPMs/iCFlBfaNGuayh/grno
         +RgqemW7DFBcPfpmpJZ9hA6uAyj750wXP4QLeTKr7XkG/N/0pd/dH3t0bKqFh2zTHY8M
         Yw6GftgCaDr7JFu28vG1qoPorHgdxXYofgej5C2SOXW3cHIkfPt40Ks8dEsjZB5FEQDD
         yu9G2wPCkHVqsRg7yabbAjHNFMeZjuZ4gR6Dc/kO77Z5VoOJgngYcxcqeRW1A7Nm9LKE
         lcIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=PG6mONir;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XFGRMZuZYszmDxa+gjcbac6XwVrEjPpy4VtQ1z4a5Zc=;
        b=tOgvbqO9ztj2GWCwd+iF34hGuL8G9wyRC2UbOrBTUmQqS+VXy3tiqcSYtiAAhVGMzz
         7gjFj8o1xdQuwbQvF2pW+nprWlcihQ9pGFUSvkUnYZGsrJjsnhfiTAZjqrdRw4ETnkVv
         pV0iMYAgrkRqRUgvHY2yPa5caeyRwSLXbHH1AgBNk8o2Y6JMQbrtYdrmzb8LLcwB/Qh8
         VsTUUkX3wMiSDLqGU/QbDRli/xII/hT6sR0ygWP5Tmqwjh+9KawpNpkF2I/QgWl/YFKP
         AjCs2By+HVYTGZw0BOFSk+CfdgURDH9BoESlhgts8Zkd5PsGcXwZFdJrpsbsF661ZQoj
         tGWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XFGRMZuZYszmDxa+gjcbac6XwVrEjPpy4VtQ1z4a5Zc=;
        b=LoSDCuXsMyvg+45/pfD9DZnM1Dt7rgdBtIw9QUPSNiF6gGAD0y7rubFU1qnmZv5Gfr
         J+tINnG+oVkp9JrKp/hnrWQGOhAzoAwVIktrBle6jBvcDdfBD16vl0SDAYr1euDJDBYW
         BFFbLiL5p7APQN9fxWqTGpdfb5AgtPIMirE2lCc1TfJhxBmN3LE/0GYSuMCCd+/dTpBB
         10lXh8E6q4EyzagILbZmGLHYVloxE/0MN/D18zWNHDu391DOmSai5j5xeeEHGCKP3TB0
         6AmUHN+MMizMdJeJcvVcvF9H24bMTJzcALASg1ssT7oc+yXAb509i169L0qJA6SLRPTV
         /5XQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530UKfcXHxCH+sSQN85sjrvbrfcrbk9VYc+4U5YM0V7AJ4K1XILn
	8cdqmzTTCvTXvfsASE8BEAc=
X-Google-Smtp-Source: ABdhPJzihypP7l9jV6L/f+6Q2DHKRcLr9h6oRDN/ljSU6dfQEJlf2WUic9LuqjxdRFQJz5sVFxbnTw==
X-Received: by 2002:a05:6512:22c7:: with SMTP id g7mr894636lfu.417.1639432345848;
        Mon, 13 Dec 2021 13:52:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1320:: with SMTP id x32ls1548761lfu.2.gmail; Mon,
 13 Dec 2021 13:52:25 -0800 (PST)
X-Received: by 2002:ac2:446a:: with SMTP id y10mr855047lfl.585.1639432344976;
        Mon, 13 Dec 2021 13:52:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432344; cv=none;
        d=google.com; s=arc-20160816;
        b=ctHt27FRwXtZQ2I1BRuT0q0W0nBW+Jm+xuJjFMQstC7lQB/W40dkIUv8XbH+ELnKMG
         bqVrsyvs5daHirFW//1zZWat3NIe5DGqRmKla/9q2Ewnlk36s8afoNYZDbkH0ktgGQcV
         UlGNaNmVathmxhUDDSdsAXm1ES/smtkSQpXVzWZBDt6uVsIzKtsg1xLh0GHuRjsI9zkQ
         BMWGB3Qv05SmeA0ezAeWzHQqIjf1bSO7XPwKmrKmZlZZFQHtQuyT74DIQITy9abFppIM
         pBFLpBXUoBb7hSzE3U/Qn8H8Fxw9dZqH+rRszbiudj8ao09Si7d29Ic913MTQDGehilU
         9GSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gEwxHYhSfawbBtJvbiR6+iX2264JYoaXaLcYxmnXGuo=;
        b=PEwr3yThOrTXIklo65izNAAooP7s/ABeHTFfgsmvNQuRG7avPPih+Du/BDq8X9MBsX
         LvIJs1acyhxSB4jrSphVxVDkJz+yzWK9rtR/icmgSsfxIhn79S9ySl1yBVq3U73ENoMs
         N7grOL5R21bhJvZ6HjH5wj382C3hLKaE6qKIO93H/SoVTEm7ClPJNFvBgBMoi3oXwS6Z
         44GRggF79dV0fWsaM1vBXlo7F8vlAh6an3zE6enjluKle2otv1f4efTTMiy+nNd63ieS
         1gtptg5HP2vMDs+30N/CHEx6ZjIkjnqyBTxN45Oy6e0D2HFkHO1G/pMjEw6sXaQPW0Ou
         k7hQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=PG6mONir;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id k26si658834lfe.10.2021.12.13.13.52.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:52:24 -0800 (PST)
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
Subject: [PATCH mm v3 05/38] kasan, page_alloc: init memory of skipped pages on free
Date: Mon, 13 Dec 2021 22:51:24 +0100
Message-Id: <cbd251de84ae7bf1c1c2afa8778b3844abebbcbb.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=PG6mONir;       spf=pass
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

Since commit 7a3b83537188 ("kasan: use separate (un)poison implementation
for integrated init"), when all init, kasan_has_integrated_init(), and
skip_kasan_poison are true, free_pages_prepare() doesn't initialize
the page. This is wrong.

Fix it by remembering whether kasan_poison_pages() performed
initialization, and call kernel_init_free_pages() if it didn't.

Reordering kasan_poison_pages() and kernel_init_free_pages() is OK,
since kernel_init_free_pages() can handle poisoned memory.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Drop Fixes tag, as the patch won't cleanly apply to older kernels
  anyway. The commit is mentioned in the patch description.

Changes v1->v2:
- Reorder kasan_poison_pages() and free_pages_prepare() in this patch
  instead of doing it in the previous one.
---
 mm/page_alloc.c | 11 ++++++++---
 1 file changed, 8 insertions(+), 3 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index db8cecdd0aaa..114d6b010331 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1374,11 +1374,16 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
-	if (init && !kasan_has_integrated_init())
-		kernel_init_free_pages(page, 1 << order);
-	if (!skip_kasan_poison)
+	if (!skip_kasan_poison) {
 		kasan_poison_pages(page, order, init);
 
+		/* Memory is already initialized if KASAN did it internally. */
+		if (kasan_has_integrated_init())
+			init = false;
+	}
+	if (init)
+		kernel_init_free_pages(page, 1 << order);
+
 	/*
 	 * arch_free_page() can make the page's contents inaccessible.  s390
 	 * does this.  So nothing which can access the page's contents should
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cbd251de84ae7bf1c1c2afa8778b3844abebbcbb.1639432170.git.andreyknvl%40google.com.
