Return-Path: <kasan-dev+bncBAABBYHZQOHAMGQE3K6EDBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 24C1547B582
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:00:01 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id k25-20020a056512331900b004259a8d8090sf3317155lfe.12
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:00:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037600; cv=pass;
        d=google.com; s=arc-20160816;
        b=zrv8htPGhsv19xHvRmVjJh8/84dRNY8Ps2/6A9abboC2A0ALzzNgITy5Tv9F2YNWrv
         ercPnihDzby4+jpONX/QbFpACWNf0GaDVgWvqRm44hRfRqI6p0uDlWlYliZMxUq9WO++
         d2Txn4fiuUd7WI++wOtiInbArlK20ogSq4Mzbvdc3sACx0KjGkhkT/d3w+rniDGEjr3D
         7SfHk51DF9SkJ6+Nx5YpCk01i9q9EqTURbga9quOXzFNsGcyL5HcsLYTlZx/PqgfTTrj
         XO8pKoYqu6uUq29usT9HNspPYs8EOw49RSbqm90W74POAIAWZjUssZJlO9Rs7lXOY9gc
         0zEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=m6WzWjwTKp3img4xzLCxYcGxWpobDLTnC1z9DD6u5eU=;
        b=HsruYDXi2P6Xe4gcn73nhC+XsdUXpcAHmqwup3BLySZd1EdByU3g8Hl3a/tk9Vj4Ar
         NozIr0hTB20KEifdfMs0QOtLtQ556xMRyZLgeXkvPSqVHo9zXkd95xwiDdA44Ij4932P
         w5bQ4RMQa3wFB3b5nN8OuiVq0U2BuSpKSZ96xvyD2twQTceehSVBBSRQic19RhYbFwIQ
         59ow2xcby5SyrBnox7Rk4VW/IygUHjEhhywMWpuJh4vrL0UnQN75z0tUp1jEwwU0xkyh
         FuivgJBdbTXH2DFvLFdwtLt+ilnk5jxuCOXE5OtoojoaJeA6yqofAjk6O1l0OKL2N5rF
         rt/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Pg8Q16GR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m6WzWjwTKp3img4xzLCxYcGxWpobDLTnC1z9DD6u5eU=;
        b=Spd4xw02DocPEe2ersEZ1bdmfCofTJmB1CoNwUYSQ9HWUJt1DpgvPSSedRZyK0x0C4
         mZJ6ctoAMfwls7XjDwCeCo5WKPxNuEfZk2eyLP4yiKrodheOjAGvXnrs1ytQ8rrwPxg4
         ai9b1rOqXz4LEDuOqOkTPuUVha/cHao7HgRMql7Q30nBHAkRLDLurftb7Ch+dJb30Zyy
         AELTOmuciWDYsbpaCk65A3nuAWSLKKBEcVXGpdOn6k/yVaggMDOoNnMvEuBHsNdmF3pI
         YYG9pp7VaBEBuMl/OMx5jDaP8ZCMxBu9BqiyYZJ394WQ6pxqKGAdKqR0B4WzrCkX7g6N
         GxhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m6WzWjwTKp3img4xzLCxYcGxWpobDLTnC1z9DD6u5eU=;
        b=p4IR2ohSGmLAFj1V4FcovCcrM7G7KQ8958Bg2MnHsAPIV6kvoYoE/GxoxqGb6TVoOw
         JDC8dfyB2e3IDtQAqry5/UHzbZTTdOi5PGrKP4VE182d3AQ77cYXzsUjrEp/sYwjK8ui
         LTydmF5WTu5bOqQxOcCD7R79MxGe5ZR6QyjBqAxJM3Ow3288FASbSFX1GV5rCbofvobF
         ucrcZQ0hv6lDZCMY43cuqeuTgKeqZz6p/gh/Yhc8Kuq+jixb8oyGpqP0NYOEsO2SlEJl
         AZ/s5G3Pu27LDZPGz/DOwRPPIANBMvSJ9HcM7KoX4DdRQK9U4DL47k5dwDdyNb0V+fqE
         W+9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533DPP2RD9PCavzwqb+dg4W/BExqyadvJMIqSXAP6nLWjvrgGQpD
	xIAhi/L6LoBLwljsNWw0FfU=
X-Google-Smtp-Source: ABdhPJx5TtZHbV7VSBQAgY+s57CsRVUgJHNdNZAcMMgo+SsOG2MED8wjnt+znnWmRsrqHDyA9q2gKg==
X-Received: by 2002:a05:651c:a04:: with SMTP id k4mr94569ljq.12.1640037600717;
        Mon, 20 Dec 2021 14:00:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5304:: with SMTP id c4ls799462lfh.3.gmail; Mon, 20 Dec
 2021 14:00:00 -0800 (PST)
X-Received: by 2002:a05:6512:3ee:: with SMTP id n14mr117888lfq.611.1640037599933;
        Mon, 20 Dec 2021 13:59:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037599; cv=none;
        d=google.com; s=arc-20160816;
        b=KiuynI2vPC24Szxz0u3YOpIlH9L1h3Ke94lNKZykYPn9PrYrLKXePpLDQ92j7LUnfv
         Ydzll3ax8L3PZSB02GRLlzQPeliXgKnyDvgBOdqELO1sl1WjYZtzivnGiBKp9jfpZhGN
         8GNQBruvxnksvmAvGabs2L0uhnE1ILZA9vn3X9nk5RX9mu3K+05noBn/+sKOdB/nrNx7
         ouEqBcfrbILH3JZaDY0tbKK0CAoRMV27g3SIMy6V4PiSZX+4GbK8UXLQZSL6ivgrAvzB
         dKJGELt+ulXWoXkyzKA2DOkQDunWuAdE6SeRVTizpbK+yU0VBG+LLaSAmChZ/OJY54tw
         oaRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ck703MMF+hkIiVkCv36NAeyoAOxabatRHXeIzXIavPs=;
        b=bJmm3AvBTO4y3T0H/rvYUnA7adGKLjgqyXS9QjcecFmpWUBsoCSu82kWC8kE4jLbKX
         HvbJypdyDsqdpicF844oCiWHLbjztI+5em0Ug2oOLvpoMBXEAV+MWV158a6+63kuZ84v
         +mXjdyMGXVxbdqV6WPEs669MoJ2C8bv+KPC+BRBRIyduu0jllQVhF1b3pMimumF6jD/N
         SvNk5uImmFHzXlBGHyYwHkRndpgQSx7DXoSp1t7aSlX0TEJEWLv+iCnUVnz5EPP+TGWM
         94Fqc8WeRGxZvBRS4/I1+AnU9wp3euAA+6Io11SVFX55UhaBTdovtbEWoRlJwy11CoAy
         IBTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Pg8Q16GR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id h31si297006lfv.2.2021.12.20.13.59.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 13:59:59 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
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
Subject: [PATCH mm v4 11/39] kasan, page_alloc: combine tag_clear_highpage calls in post_alloc_hook
Date: Mon, 20 Dec 2021 22:59:26 +0100
Message-Id: <c5366f47d79bb98287527109886fdbbddcba4aab.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Pg8Q16GR;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Move tag_clear_highpage() loops out of the kasan_has_integrated_init()
clause as a code simplification.

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

---

Changes v2->v3:
- Update patch description.
---
 mm/page_alloc.c | 32 ++++++++++++++++----------------
 1 file changed, 16 insertions(+), 16 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index a2e32a8abd7f..2d1e63a01ed8 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2418,30 +2418,30 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	 * KASAN unpoisoning and memory initializion code must be
 	 * kept together to avoid discrepancies in behavior.
 	 */
+
+	/*
+	 * If memory tags should be zeroed (which happens only when memory
+	 * should be initialized as well).
+	 */
+	if (init_tags) {
+		int i;
+
+		/* Initialize both memory and tags. */
+		for (i = 0; i != 1 << order; ++i)
+			tag_clear_highpage(page + i);
+
+		/* Note that memory is already initialized by the loop above. */
+		init = false;
+	}
 	if (kasan_has_integrated_init()) {
 		if (gfp_flags & __GFP_SKIP_KASAN_POISON)
 			SetPageSkipKASanPoison(page);
 
-		if (init_tags) {
-			int i;
-
-			for (i = 0; i != 1 << order; ++i)
-				tag_clear_highpage(page + i);
-		} else {
+		if (!init_tags)
 			kasan_unpoison_pages(page, order, init);
-		}
 	} else {
 		kasan_unpoison_pages(page, order, init);
 
-		if (init_tags) {
-			int i;
-
-			for (i = 0; i < 1 << order; i++)
-				tag_clear_highpage(page + i);
-
-			init = false;
-		}
-
 		if (init)
 			kernel_init_free_pages(page, 1 << order);
 	}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c5366f47d79bb98287527109886fdbbddcba4aab.1640036051.git.andreyknvl%40google.com.
