Return-Path: <kasan-dev+bncBAABBM4JXCHAMGQESXZ3MAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 7002D481F7C
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:12:51 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id j207-20020a1c23d8000000b00345b181302esf13791758wmj.1
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:12:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891571; cv=pass;
        d=google.com; s=arc-20160816;
        b=kdc3vMX9qW99QMoxI/MXiflB64OFAtTPYMByb1p4uJfx2h1hCHwiftV0QXLNgg/ChY
         DDG8l7ThXCDSu52Z7U0ET+WWi/kLR3asfnqFVxtguQmHrBJj7715UUu26ZWo/qgQNg/5
         0bbk+YjQErIjuWp9y98WcJBysMDuSljmbYBBQfbPMlhvC0h/Xu3Y8Uf48Ccm247XvZbe
         p9GK8NklH3k/1EKeNhLfkbzFdcN1uRfnPVgkgAcR/+HHGT7SmaJYeR5zHD/VEMqDA+3g
         ntYVJWxKa50bM4m4EjtfixvrgePNJLChfLvdP+cumGsrohHrrgEWonc1YN/ukdDtX9Kh
         Joaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=VSHEkH33olk4PQ4tlPqav3LvyAYNrcH5EsaEwaFBgb0=;
        b=qG9TnOqdVyLcmEbxZaMJF3bt3KZ99MFOT71MpABceXWy6Rll69MGXwm3lAYIWAnSBv
         fc5YrQExyfSELTBibRT5Yu5FfwzvF4Kk77ZUq50UxKvvUdSupCejteSPRB+PThnUNyPv
         mJ/kpiIln1F3XM41YWBPFVXPPRAjDjlCDyH/8KDOOQNJSh8vuxQmkLNYaa7JQXvYmkRj
         Xq5hfG4BghgHZi19QhOf+uiVnTkT9go3jsCAZ48JxxImcy/2gIo6vsvbQRflx8Ds6FTX
         eH6wmnnoTDXgMjIyfbf9AIcLiwWx04pW3qqqpLXi2gPshTg7J0jPv3S6fgCOvRWUWnSY
         umPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HR+wiVRm;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VSHEkH33olk4PQ4tlPqav3LvyAYNrcH5EsaEwaFBgb0=;
        b=Eh8BAwnWZrokRIry6+G30J3ebr/QIctgG8Knrylv65+3kNxwj4lxlinOQ1tR/1ITT9
         ZfeSM6hUTjjILHevCSDdB6q/9CGA+O0P8rRlPe2Kcm0nnF/CaJD4/ryttN774/4lx1rD
         LBYqWQyqhqCaFkG9ZGObIw1M5BGc+wb2w9se9MqqUWvqI0yvfHHcfXKiAQx2O5DXch7z
         7DjrJqBx2kejUimPXwV99PkLoGer0M7jnKFWz9jqujBUVpXo29Iizb24qY1KP6EuL0C2
         XyvyO1riJQwDNiAoiQoOdjJFodWGOSwNl3ugPurcHUh3sinY8pmX8HMdaRPeXS+zA1rK
         I2ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VSHEkH33olk4PQ4tlPqav3LvyAYNrcH5EsaEwaFBgb0=;
        b=M6q2Z0QfKmOmtkpDFCSEYjVGUKgCCWISVcU6SFN5lLY5jWDUuVS30Hl+gFjfIdFCjp
         Jo/esXmEVcX9mfWg6EfveyKkxY00fPAQLEXcuSVTG/mdNgKMOLZDg4YPuSO/qY7XVQtm
         tVtCH0bsyeyLYnWpxj0P/zl5upLKGdrKWdf1zJT5vVgK1O3vPg6WqRToajIH2K3amH1k
         OhHfwychX4+q4Q2BVYbi09ZcX2/GlVwtaY+Vyf1/zyGM8Z0bRZ3+vHL0fTuQ19v8dEqY
         1gONj3mo4YpbJ7f+iKE1LBV35cKm1ThalUE9jU3U9ggav+SVF4oAIMdY1D+2r7sNMIAG
         ixGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530LyXFS+6nwYyP0YktOz9K2lS2YLw6HUjtzaY05wXbWiy6JAvOd
	IlDhScbyIN5DDfN5+mVJ1Xs=
X-Google-Smtp-Source: ABdhPJwoNvwE0gJoTzNIb5LG/KEkXvXa6m8XZHZwz5z1WcQF3/LsIQgLv9dNJ4CgtUYyNTWxcMXvew==
X-Received: by 2002:adf:bb11:: with SMTP id r17mr26735213wrg.463.1640891571211;
        Thu, 30 Dec 2021 11:12:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ca47:: with SMTP id m7ls322179wml.3.gmail; Thu, 30 Dec
 2021 11:12:50 -0800 (PST)
X-Received: by 2002:a05:600c:a06:: with SMTP id z6mr27210898wmp.9.1640891570500;
        Thu, 30 Dec 2021 11:12:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891570; cv=none;
        d=google.com; s=arc-20160816;
        b=Di7OQrWsxcVEvRmYkxeMcavU/MLko8XePsYIvsl/y6+aCR73Vv6sHH4s2ZzgGw7ZHY
         AC1I3ET3Grpha3V4RB1i5cGFo00Ri45adAvu+5KZSOWhylIQu8YmtGk5SMA6n+5jlmJF
         AvgT+IrteUhrXjsgTFlXaHlDvSdL/1Y1h+8fF9D70WejwaxCLzxBgPUkJdTov1XjqcAb
         XRTvibKk+D1G59qoBDGtx3ZsvyAP4VxsqcAphdOvdDta4PJ0a+9vaONCaIPuJnAMGZo0
         q5S7XFRAogWNVFN5IfbYHRNRQPrpJatarIg9TYxdlUpU8soRSwvJR4P070VpO0+pdPlZ
         NuXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=v99L/fHbiWErTRAPPtZU0B2NYInEBgVCSeIiWhLvIjc=;
        b=u0vXGwNeKgqPZAYCIRvdbgAWwrDSc9lrv6tV6Ioeac2wcIchJIPVoHE0PY5gpxl/zA
         kZmE25MMou5SptnjJyy7ojZX2dVBxO3sbdX+JkbxXi7hx2zdlYzyn0/5QC/m4vQZH4kX
         2+mWzeI4exeMvQ0iIH0u2ZYUbmcW0gA+87gp+IvcRfhBcKQP3iOUb13ZWh4HVYC77hqB
         Nf/mJ/f+WJADuIeQ0SmI2MbO9w10zldGRbu7iWkm7EXPGcbVUpVBEivWE+RSjTk5yrsp
         9dW0vuquk6V5rgIyfl81b2yYH+mCS6s5tnUmRrZLMxdrnDwmsE8S1Uv3edwfCrDKHTkl
         MfZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HR+wiVRm;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id e5si1061986wrs.6.2021.12.30.11.12.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:12:50 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
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
Subject: [PATCH mm v5 05/39] kasan, page_alloc: init memory of skipped pages on free
Date: Thu, 30 Dec 2021 20:12:07 +0100
Message-Id: <501608e03db76970ce638bedfd7ff38f74f8e840.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=HR+wiVRm;       spf=pass
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
index f78058115288..37e121ff99b1 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1375,11 +1375,16 @@ static __always_inline bool free_pages_prepare(struct page *page,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/501608e03db76970ce638bedfd7ff38f74f8e840.1640891329.git.andreyknvl%40google.com.
