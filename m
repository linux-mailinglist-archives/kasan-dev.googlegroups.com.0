Return-Path: <kasan-dev+bncBAABBX4B36GQMGQEMUGBNPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 4962E4736D6
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:53:36 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id w11-20020a05651234cb00b0041f93ca5812sf6060064lfr.21
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:53:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432415; cv=pass;
        d=google.com; s=arc-20160816;
        b=zAoVxrJqafndmMRGFiZ9lBgOLtOUS5bX+dcqTqyc25AC+J0fvlu3ptarK2QZDfN1u1
         P7dDMyzSYSjX2jZuGMKydWm70t/K2afHRWWYTpCo14lfYMuV1zO4NsvngI7RJNfEAyyW
         Is+wR+Hork7UFlXdBgqE3v36vzy7zb+RI2ZDhib5cS2jx03yyHKgBy2ieqWjZwQTJPO/
         J7niVLd/5yYyHYPO7YCoRfqKv2wspM2VLTB/TdWzu+3Dac9NXEE3naFAA17/EWT7TsMf
         1AC0rX8BtdG4n5PtVm/69W/LhI+ViKNcBh1HAWKxWmAURS5K8ZG8iDAplfbbQPQWQ3Du
         ELsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GrMm60Jkw1KFHgBB975ECST6tf9OQ/cjX8Udno7Bcgc=;
        b=KTD3YwOW28bIBrwBsWxmCnx3wm5eqtf8c5cdOB1lg2kLiBWR/k3NzzYzcNTk1CoGyU
         x02kZvaMJ1R2L7GOVjt63P5uecIUXL5tQtc/wVvX7FGJLu8fpErfuEEBqKDm0p+0ioFI
         mfCgXE6zj3FnIe0YdZtAIPSCKLD/QGBtJ8WDotYZyjZxZ401TofOpitME9cCXwjuBEjv
         Euy0H/zX8NWdvVgYQVTGtEw7aGeLBUXsBVj4tMDQQBv9xaBX0zDc941HpyoM4jx23iCg
         XSprgEq2eY86kkbezHRd5F8ZivF91hZGLsny8bzD/Anb4JHflFnJyIbggdjvMfD4JGVZ
         +LcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xEfGq1qU;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GrMm60Jkw1KFHgBB975ECST6tf9OQ/cjX8Udno7Bcgc=;
        b=ov6JLkJrZJnhUMp4hUo1Yc2v1lkTaODVJz9SJxZURQ44/3ZUi9cOt0ZyRBqsmMxXui
         GOgS7fZ+6p+2Ylvd3OwjM13VCZ3crAagouvDDWrdjMltxuGZklV3FUOGuvZ68K6E65lC
         olykmM6sOafoX4+gjLCIJMS4TCNrH78OGln45rizein9S4xUp3gCK/zlegXPBoWv52Qr
         F9jTNj7SqEPy15FXixdO+rfFhpQOmWdBre6V36IiM+jmIN8DqykRFu2ilY7sfdvXZxIg
         EV2cErppYox/cd4sEnp08fk736yVCqT8dMoO/CvXNSN78u5vUOyf/rh6TN6bTHZOTuQV
         Ex9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GrMm60Jkw1KFHgBB975ECST6tf9OQ/cjX8Udno7Bcgc=;
        b=44zAPFzibxAFJRcywEUtwCQ9gy0gR2RfYhmDhw87pGrbIi1sWyJL5NWFRCByh4V/95
         VKdsr3ulZQZJ3qSqFzKi2C+0xMsy2nz168czJ9a0GICdMYWBASUr/EQPHKJkCqcaejoi
         xN52V8qe05xnA5P1cxFocgZ/mWqW4jbgbS4Pux63xbQ5wAA61BriBu8lxbKG8k7dZY13
         8l6+OU51UEVMunEM1roN5GZI3thzOeEEQIvc5gAOKSyQ/SyfPExAf8hJDnQkOXj2rs/G
         0+cYuFQebU1y8cagR7BzVGka5213FJgAi+WZlQqjgwUfL1cSjRAngHm/Q/pgp/6WI/im
         5qMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5334I4hfUXdzcFqckjRwTu+XYZ53a8ij4aTu+0PwedDQwapMWdwZ
	pFdiHgtpLURo4shPjlFIMuI=
X-Google-Smtp-Source: ABdhPJxXxEcB5qs9LUCEcaicmRnAywWb2QIlIZ1H1IthuV3mz+xDp6jCSl4BDrr1zRCdkk7scgI9nw==
X-Received: by 2002:ac2:4c47:: with SMTP id o7mr965582lfk.558.1639432415846;
        Mon, 13 Dec 2021 13:53:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1320:: with SMTP id x32ls1550066lfu.2.gmail; Mon,
 13 Dec 2021 13:53:35 -0800 (PST)
X-Received: by 2002:a05:6512:3f27:: with SMTP id y39mr908705lfa.675.1639432415098;
        Mon, 13 Dec 2021 13:53:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432415; cv=none;
        d=google.com; s=arc-20160816;
        b=0Vs6tS90iTgLL5pvaMRwX9yexioCp3NRjGHuKuP+bIN9dpkwivZdVrGeP/dN/zThl3
         iGBeuwDFcbD3NbEamFt/KEqHl9PoA3zV5eT+bcalAkGM64QaglkAw4Al87ofGgGTAwJB
         9ZaunvdC6ckd1AW0r/WrJrthme4nlLRHUG36MMN7dM6gEKtUF7VrCgQiO1pCKNCqgjnJ
         SMd8jCZ0wDb4rJ37DCAfcjXryNm7GrzsV69po7eOks3mPFMHtogqdaY7BRycfAlMR+4r
         xQOeAS57acdw8i7MRxaWOG000WxdZ5w8A640rJ7VijiZZiU8UBj7qu5vfv7xA8YKknmE
         lz3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Fr6Bf66jzLxXXQKqa+ppYstGVfI+tdueVMrHQhxFEhI=;
        b=Og0zeoHln1YbN0Rh13kBeC4OcVh56aICw4rVSwI0Fie/Om0qH2/xqeEfbSvFOvM8Pk
         B+j9Ixz0W8JBh2rK+YqHXMkj3UCdj8iLiAnXtHJG9g5PMJRV7Tkp4BJBYSRimIIF7qrC
         6dRQKc4HAXDEOyaVpdkYMQ/5+qmAo+4qegWYQ7oSFvKvN1vCdOI0e7njtJlQXES4Jjlk
         cnbhjk+bAPg/9COR+p3F32ToEDdN0M51UFyhVPOVDNaz7LPykwafAu6DrxaTR2WynVjP
         EGfahQ0bZ9IMlio8IvzXetczwQ6H8/gdSlnhltC7oYkRSwA29aKY0LCl6/4xD4HcPEUU
         hw3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xEfGq1qU;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id y8si615280lfj.0.2021.12.13.13.53.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:53:35 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
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
Subject: [PATCH mm v3 12/38] kasan, page_alloc: move SetPageSkipKASanPoison in post_alloc_hook
Date: Mon, 13 Dec 2021 22:53:02 +0100
Message-Id: <a8a713cfe1c7a8836d444c9f12ee7bf5f9ea279c.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=xEfGq1qU;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
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

Pull the SetPageSkipKASanPoison() call in post_alloc_hook() out of the
big if clause for better code readability. This also allows for more
simplifications in the following patches.

Also turn the kasan_has_integrated_init() check into the proper
CONFIG_KASAN_HW_TAGS one. These checks evaluate to the same value,
but logically skipping kasan poisoning has nothing to do with
integrated init.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 7 ++++---
 1 file changed, 4 insertions(+), 3 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 2d1e63a01ed8..3dba92accfb7 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2434,9 +2434,6 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		init = false;
 	}
 	if (kasan_has_integrated_init()) {
-		if (gfp_flags & __GFP_SKIP_KASAN_POISON)
-			SetPageSkipKASanPoison(page);
-
 		if (!init_tags)
 			kasan_unpoison_pages(page, order, init);
 	} else {
@@ -2445,6 +2442,10 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		if (init)
 			kernel_init_free_pages(page, 1 << order);
 	}
+	/* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
+	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&
+	    (gfp_flags & __GFP_SKIP_KASAN_POISON))
+		SetPageSkipKASanPoison(page);
 
 	set_page_owner(page, order, gfp_flags);
 	page_table_check_alloc(page, order);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a8a713cfe1c7a8836d444c9f12ee7bf5f9ea279c.1639432170.git.andreyknvl%40google.com.
