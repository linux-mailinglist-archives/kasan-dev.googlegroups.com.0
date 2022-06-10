Return-Path: <kasan-dev+bncBDDL3KWR4EBRBEWDRWKQMGQE66755JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 25FC1546953
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jun 2022 17:21:55 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id p22-20020a05600c359600b0039c7b23a1c7sf340499wmq.2
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jun 2022 08:21:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654874514; cv=pass;
        d=google.com; s=arc-20160816;
        b=AgOkKjGajun+D1AhtBe2TRJR+AMDljFu0BNU3W3TC4mKgC/MFsIKixP4O9ElGTSmRg
         otcaHA3hElx32LcRLwSYHI5mA0hdnppECZi+zO2EZEFTbvkksFr1HYF8iNeAcqvhIJTW
         LcW7uu2j+ZtAlVtVjl5JCBBwjJ7HkDmfEYRpkQtr5wLpoyTKT6iMAiDFd2F4CPYKQmHb
         K1HLNpEKtIyqliwR9Al6rdfI/6i5FNPpqX5Pz8eRQstFkwIgNOSbKT27/EWsHwUD1R+c
         rytvx+EWUR7XmDNTRwHIlui858HVt8mwAL4bJsTzXzVdFOvOObGPUI8LqxIaPVGIEfKH
         5QTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1HM0WPji9sggFrob+sur2DjnJcxD1tjptBm4UImS8kY=;
        b=bdnHVC3K6SeYePR3L13KMNcscOr43UTtdMnsesSJ6qUxulTj8H/Mp7h+V1K5/luAi+
         uiJ/ROiEou+vbK6WOpPbScNZqRtPe0Npl5qQ1KG7GviPfero0Ji1Ewr6EYBhNAsxEYsH
         0B9JGdEqvUyas1HywVDXTfiS0sQhMDC3eSM5cWVDsnA55+45gh43z40mmqElxrRsyjt2
         hFLUmlqV5XbjKNAwvP3eqPZjtT3l++XHwvpCyRZxj0tT++rAxtYEnLltEUMpn0yOsKh+
         QGcDvJCLeuqUg1IQerRyfZyaQVXrqrz3hjoCaSkTk7UkODgvQOqZv+pGJ6ATCRm+oibU
         Q7FA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1HM0WPji9sggFrob+sur2DjnJcxD1tjptBm4UImS8kY=;
        b=feYfgorSSuU3g6LBHEqENcptWxpH90EIunLB33UMETVgBDXVtbzmtaEavGTE2Ui2Qw
         wuoJCothmtc1aLa7nCZS5yPU9/6WBcq7bF5vK3jbWRF+BUDyTBR2Y5SIIZKp1eqpqBam
         qUBrOXKZmWrtCze2UljvZuMmn8+ca6t3LZ82jDL5Z/m5fXlqlOErtmNp0tiTWHdfgJ16
         iRR6rS9w9pQWHtossRmEsW802U9IZvZpWMKV9qa1kGAXfZRSoE7Dm12e52eFC75vCwR3
         vbinjLrQAOoHwkN54hwVwWkDpwVExDvl7cdcIiKuTjhhxXK1JJgnYS1+KjEyLU63kG4Z
         AxbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1HM0WPji9sggFrob+sur2DjnJcxD1tjptBm4UImS8kY=;
        b=M1BpwxYsnexzdpxwx06xJnW2uhrLJP4+GZM351NiBH3CWEDw6VnyPtbi5CJMCC9VbX
         +9ebaSRoilrJx7l7jASUEhaT5KsMqa+Qe3X3c+TRuZYtY66Rwz3NEMzQPRy/QTxRjtRQ
         hmv405XEP7Oxf/9fbCdNjF8T8teMB6RIVLRIZvIx9DAt262CaZRzGa+XdYH8PRksHdnf
         +dzzU1J30p8in75KYoq+Y8n1lSJYD8/1BKKXPG1ghXe+kvD1tFxunEiLp/lVEtVGp/W+
         v/7XftwhLeW7iNKrxWVp5xYNEHPX9vZ9xXihDw35f6/qTTpcHuk9NxN7vqCKTEhKFO2+
         7VFA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532uPnT4cbsG7Jn8dlTXyCR8jdjbc29T9d0keJnDEK7sfkXSUWJg
	eRd0pYm/DlFK61WRXjFbCbQ=
X-Google-Smtp-Source: ABdhPJyWOqz9FfgjlMq00jCR7zOgSo1yJodeBvBs1zlGZY9jWPXddl9TTQ4ufmbq1vmiavS+Ks9XZQ==
X-Received: by 2002:adf:d1ea:0:b0:210:3e1f:3ea7 with SMTP id g10-20020adfd1ea000000b002103e1f3ea7mr45641372wrd.595.1654874514579;
        Fri, 10 Jun 2022 08:21:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1887:b0:218:5c3b:1a23 with SMTP id
 a7-20020a056000188700b002185c3b1a23ls445889wri.0.gmail; Fri, 10 Jun 2022
 08:21:53 -0700 (PDT)
X-Received: by 2002:a5d:638b:0:b0:218:54a2:71ec with SMTP id p11-20020a5d638b000000b0021854a271ecmr18469696wru.477.1654874513325;
        Fri, 10 Jun 2022 08:21:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654874513; cv=none;
        d=google.com; s=arc-20160816;
        b=0bwA/SDojb4zyx0+Z1V5LzDxkUtHLJvSdXKlBewmd3c6jKl1IDzvm6rpf1zJYi7EWX
         SAVGlpiWSGU1nqr2IhS3WYRKJlYD1cJrS36E9aDJOBy6X9ptktP9w/2B+Dt1VEW6jBda
         mUzZuXibg0ahlE54VHUfGIROIkxqTKseE5DV7IeY6h6Gd9xGsrQeGyEPMh6F7o80UDNq
         II8AkYu44DTEQ9fH86eVG0GXCInHK2Y/RPJcTC757kgyI9ku1vYx3aSifb9VAqrEKk58
         jFmZmINNOVz0EZ+iMK0JYk1HmqbYLKyn/+87xhu2jxYCuOyFwJ2gtRmKw1cSIolnGiD3
         cGnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=xTcKrg132yumfeHI+89aJ2gVjyy8ssX4BiyWhoGoljI=;
        b=AG2GlOmAUrQcOdcL1u5ESFxUrdain1rN/b6zQolRrzEe6PSGAMm0YAaQfDTOeWw2Kr
         jr8N7DFCnyqnB9M2ra43NhFp8Lt6wEfQJ8PCMGPSQLC6qlCKsfOgmWHPTuqdAYnopH0n
         HFs5C3AAwI+5PUIh/kJTMuv+UifB9kHqCbte0G87dO9sAkJEs8MexMa4Ng//Pd1sFysK
         VHwrKkvVYmD2SWb0L2IZxhfmVpJZYuiAdR4KmRuPFA137TorTBAw8DtyAA/jM6h3Dd1O
         0/fpokNx+WkdHcQQ/ZIs2tjjLxHIdw/Tr09/O76ez1DVjUa0O3uikb2dAji56PLL7/e9
         5Kpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id x13-20020a5d60cd000000b0020c6d76cc7fsi1006159wrt.7.2022.06.10.08.21.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Jun 2022 08:21:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 02BBEB8361C;
	Fri, 10 Jun 2022 15:21:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CF28BC341C0;
	Fri, 10 Jun 2022 15:21:50 +0000 (UTC)
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>
Cc: Will Deacon <will@kernel.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH v2 3/4] mm: kasan: Skip page unpoisoning only if __GFP_SKIP_KASAN_UNPOISON
Date: Fri, 10 Jun 2022 16:21:40 +0100
Message-Id: <20220610152141.2148929-4-catalin.marinas@arm.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20220610152141.2148929-1-catalin.marinas@arm.com>
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
MIME-Version: 1.0
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

Currently post_alloc_hook() skips the kasan unpoisoning if the tags will
be zeroed (__GFP_ZEROTAGS) or __GFP_SKIP_KASAN_UNPOISON is passed. Since
__GFP_ZEROTAGS is now accompanied by __GFP_SKIP_KASAN_UNPOISON, remove
the extra check.

Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Peter Collingbourne <pcc@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 mm/page_alloc.c | 12 +++++-------
 1 file changed, 5 insertions(+), 7 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index f6ed240870bc..bf45a6aa407a 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2361,7 +2361,7 @@ static inline bool check_new_pcp(struct page *page, unsigned int order)
 }
 #endif /* CONFIG_DEBUG_VM */
 
-static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
+static inline bool should_skip_kasan_unpoison(gfp_t flags)
 {
 	/* Don't skip if a software KASAN mode is enabled. */
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
@@ -2373,12 +2373,10 @@ static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
 		return true;
 
 	/*
-	 * With hardware tag-based KASAN enabled, skip if either:
-	 *
-	 * 1. Memory tags have already been cleared via tag_clear_highpage().
-	 * 2. Skipping has been requested via __GFP_SKIP_KASAN_UNPOISON.
+	 * With hardware tag-based KASAN enabled, skip if this has been
+	 * requested via __GFP_SKIP_KASAN_UNPOISON.
 	 */
-	return init_tags || (flags & __GFP_SKIP_KASAN_UNPOISON);
+	return flags & __GFP_SKIP_KASAN_UNPOISON;
 }
 
 static inline bool should_skip_init(gfp_t flags)
@@ -2430,7 +2428,7 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		/* Note that memory is already initialized by the loop above. */
 		init = false;
 	}
-	if (!should_skip_kasan_unpoison(gfp_flags, init_tags)) {
+	if (!should_skip_kasan_unpoison(gfp_flags)) {
 		/* Unpoison shadow memory or set memory tags. */
 		kasan_unpoison_pages(page, order, init);
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220610152141.2148929-4-catalin.marinas%40arm.com.
