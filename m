Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHE44GAQMGQERBSL45I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id CD91B325B41
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Feb 2021 02:25:49 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id a41sf5494990qtk.0
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 17:25:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614302749; cv=pass;
        d=google.com; s=arc-20160816;
        b=glk8XDeh8EwSNWJ9VUjdVVQMoE7BHjemZ0986vVGYQY+0awwzHQT5dqhoCwru0Bz4U
         DaH77KoDq1rS76b4bJpXCU6LBWwRPDLFoFrfbObLK3m9xw+K/OjVsO0L9xznxRj4Pq0X
         JLUkAb6tECS2r1UmA4/s6NysQbdcYuJ2YlzszzSNIODTpHXxt02oW4FqEAA0na3nALAa
         EONwrCPRqoxZUe4u8AtVTIU6HauAJC+7Nq1hvnNIZDBiB4WYN2ORtwSQmTlfF5j+XS20
         Y5sad2K/PDsYN6qBHaK4sni3+rZBynXk4zZLvOxatbWU1gNrT0To2IpUM3MwKUI0aAWa
         /xpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=dDJtv/eyohZe278WcLus3kP4+cLK64mN4Y31giMxJUM=;
        b=BqaXMGyfURoZ2Tqd5KvCOLCCDn9/4kli2wX2HAgu7jVteaCrztvLlLV02dxttTajhq
         eP1EsY1Yf7XtOiWMA4K9pYFQTRaDy9GN7LBgKk1avkSOvIkVvN2hWVUCKbNb7phHWBi2
         d7hr00BqBzYgN3R5zkT8ryD3LNtY3IfdnO2UN/nvLVxn/mD7rrN8IMhtpnYX9V2RhUqF
         iwExDW+E8XeDWs1J4Y7ACRn4TWp5ujoY2k/ixOFHVh1A26rMugPZQZeA24Xcho7lrr0T
         0znW1L6zQaChbgO5R2QDiNJw+6f+y6+VScx8BWvUelg/rZNDNDyXyPPKPWni3FLgIyP6
         jt/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uJ3kYZFM;
       spf=pass (google.com: domain of 3he44yaokcaeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3HE44YAoKCaEBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dDJtv/eyohZe278WcLus3kP4+cLK64mN4Y31giMxJUM=;
        b=dhDwfqkCN89ACMPFsE21C3he5+jsVarLT5xroxa3LVJFN0DR3F/GsdSE7DJ8PNNcx6
         PYXCDoYk+mNAHh1BDpXzHG156DdgOaa3bPPY8J8UKq5HmHlb6uvy7Y4Ii9IJhSDTSc0H
         yy098IAfrhZ8JLx6CJWAvHKOemakL7i4y/Ld8F46QEnK7iq/JBKyZXU0vgXH7XyPPuUK
         Lmpl+F/P3pcLnjyN0s4LcOBC/xYtO2iMjIJZtaMC+z8zKHWr0Gp6BOAiA0Ckh6xzI6gL
         n928qmxIVvbgxfISrbqvh+P0IZLF321b7QzpX1LgqWl8i2Gc/k5YyvoTAnUucpl4KZqf
         kSmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dDJtv/eyohZe278WcLus3kP4+cLK64mN4Y31giMxJUM=;
        b=dJgWGXBiM7ynk9/5iZgdESAgQ4yjmqk3T6eRcCkfH4GoVbEW/H6xo3kcOg47lfsCz5
         nTsE+iyUq0219V0pbXBC+mar7od+BeGJr71yHaQMk6cA28imfL8qj+pL0S1hRu1GBRkF
         BBPRLb3gKcI+Y2yRyAjWpeAxoUyahufWCqH+L7DOeJGRQH7auQf+OPrXJD9Wk45yw9I9
         2J8wDPl+NtRQgaVN/JjmE5sNLSf5GEaDuPpQ6dA/3jwrlEsfKz71i5kq447bpdpyM2iY
         N/Af5ZrNEderuX1lreq8xE0MMwqS3AnTein2ruDHoT+SOEuw/ZTXZzZ1V7OxR7dL7BtM
         XTZA==
X-Gm-Message-State: AOAM5325BTN6qHBfjVvFIOvh1BxCcUrDLnQPpF1wYHb9H/QhOFEncKaa
	ZYdDmj9NUaEH4nrXGer3vNs=
X-Google-Smtp-Source: ABdhPJwbqSzXbHwtckn+PJYkQ+Q8ZbxHJcdnj/w9SCMa92cjtpGwjxDZYo4f4z42T5fh8y/GkEmAkw==
X-Received: by 2002:a37:96c4:: with SMTP id y187mr561518qkd.231.1614302748992;
        Thu, 25 Feb 2021 17:25:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1c91:: with SMTP id f17ls2869028qtl.9.gmail; Thu, 25 Feb
 2021 17:25:48 -0800 (PST)
X-Received: by 2002:aed:2ac5:: with SMTP id t63mr869442qtd.117.1614302748586;
        Thu, 25 Feb 2021 17:25:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614302748; cv=none;
        d=google.com; s=arc-20160816;
        b=a5Ak+uzUNwwugshsgTBN5EQs9xNZBqtXJpdcqtlvY4zf7ppBCKWDxEzUVGXGqaiqqX
         1PnxhoiEHszgoXoDdYyxUHREKH+cl+QQrabKOs16WlV7aMSIBFdE60Qvbk+rHaeublns
         wrgB5+4zFolD3Gq8jFfM9wDJ3602EFnSXPeLuas5L+nD2WLswrlqRraOZqqkhXftl0Tj
         WcC8RLzFVfrVlbmUTbkDkZb+Zw8/d1u6Jo6gE8aD2MJFkeKDFCkb1g3NIt2lypk/s4Pg
         w4WaFWPp7uT++fBRt1b5zyYyXS4II2wRsPrp03GE03HWeY+lNVNHyF5jni+2KACmkFRJ
         kEaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=fGyKOr2NOKevbTthD2lHJMlPg4rW22LG13Q09TJ/Cwo=;
        b=vUKsRHrz0Ae45tHN1Fm6PuUkPY6s0Hf7vWlVkitJGE0Q+UQ64yCTTm8yqS2onjKaWL
         Bmmhns6IR1uCV0QztEsmY9jMNZn4oAz6wBMtw7bc67A1VMoNCUe+TUi9sAfN04218OQg
         0vxjhCaL4fv5vHhRlbwaH5dZ8pD9vkC7J+rk2c3oCst8odr9cDt9jMFwFa9vBB15lkLd
         7La20DSs1xIRmQ+gaq9FLFedf+PcVByuAoyvW+MinmjId+x+acJsh59q+0l9Won+AQ0B
         QAAIfcrXdN9/IQ41C1F6FeUC8Ml1k0KPT0M4gWDLqjdCOMN1JuxK2Obj2hzBI5JmF+EO
         paHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uJ3kYZFM;
       spf=pass (google.com: domain of 3he44yaokcaeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3HE44YAoKCaEBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id g4si312511qtg.3.2021.02.25.17.25.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Feb 2021 17:25:48 -0800 (PST)
Received-SPF: pass (google.com: domain of 3he44yaokcaeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id u8so5709701qvm.5
        for <kasan-dev@googlegroups.com>; Thu, 25 Feb 2021 17:25:48 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:5c80:fb1e:3d1d:d709])
 (user=andreyknvl job=sendgmr) by 2002:a0c:ec4e:: with SMTP id
 n14mr518858qvq.34.1614302748187; Thu, 25 Feb 2021 17:25:48 -0800 (PST)
Date: Fri, 26 Feb 2021 02:25:37 +0100
Message-Id: <1aa83e48627978de8068d5e3314185f3a0d7a849.1614302398.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH] kasan, mm: fix crash with HW_TAGS and DEBUG_PAGEALLOC
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Christoph Hellwig <hch@infradead.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uJ3kYZFM;       spf=pass
 (google.com: domain of 3he44yaokcaeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3HE44YAoKCaEBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Currently, kasan_free_nondeferred_pages()->kasan_free_pages() is called
after debug_pagealloc_unmap_pages(). This causes a crash when
debug_pagealloc is enabled, as HW_TAGS KASAN can't set tags on an
unmapped page.

This patch puts kasan_free_nondeferred_pages() before
debug_pagealloc_unmap_pages().

Besides fixing the crash, this also makes the annotation order consistent
with debug_pagealloc_map_pages() preceding kasan_alloc_pages().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 8 ++++++--
 1 file changed, 6 insertions(+), 2 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index c89e7b107514..54bc237fd319 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1311,10 +1311,14 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	 */
 	arch_free_page(page, order);
 
-	debug_pagealloc_unmap_pages(page, 1 << order);
-
+	/*
+	 * With hardware tag-based KASAN, memory tags must be set
+	 * before unmapping the page with debug_pagealloc.
+	 */
 	kasan_free_nondeferred_pages(page, order, fpi_flags);
 
+	debug_pagealloc_unmap_pages(page, 1 << order);
+
 	return true;
 }
 
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1aa83e48627978de8068d5e3314185f3a0d7a849.1614302398.git.andreyknvl%40google.com.
