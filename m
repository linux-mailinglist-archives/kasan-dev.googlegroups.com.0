Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSVAVT6QKGQESEKD4UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 7952D2AE2D7
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:27 +0100 (CET)
Received: by mail-vk1-xa39.google.com with SMTP id x23sf12110vkx.1
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046346; cv=pass;
        d=google.com; s=arc-20160816;
        b=SQdJ+wAwG2A/96nDMl9zKV1P6bcbx8F2O6zRrdHZx3bBul78iinMqD1BLyLw9iwDp9
         Qm9eDMzLWLpWPjp3B6rTJIAS994jvo4FWzrASMw8WTaAhds2LISSolqMBxpL1jwdjMCU
         fHU82ETtZ7P0w6o/ipmoLQxJJhSnwfeQD1POL9HBQke0ZWNzm1K3r+HwyUKMbvGt4wKL
         0CE5y6T7ScHHGGc8U2otGKIL0s6O3kabOrhbn6srxpF7iwfNFqQDluy6QgPqJeVfa2wW
         ThNYPY9VjIe0Ww88PZOVhlzv5yoOHwp51/CEv31QSenjf+f84J6ACJje3kX5MgCkkWEK
         j9Zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=vMZyTBp4HX/dOqdnDX7X7rbJmCGHYFwR3/rStCLfQBU=;
        b=SgRZmSmlRLxSOwfGTBiM/D4EtteEaUHAf49vQl9IKYncysLNyABKBRZ/fJwdg9QAgh
         AMvwqd9/5EjAO/czkir8j5MzuEsiSyb1ISheEFaoozSaJuKvk+ID0y889TUKxqlsU0rA
         5VzwgYzoIna3oIQ0NodTbp2BoNvVJOXxbFFcoTEQjo+gMIWXh4udWMB1KllZJkZPjI0g
         SsMYBS4/WDKEhdbEzkJ4KNd2LO5wpAdDdH85YcS96eZgAjcLzZigki1SjFNISHNRFTRy
         ybhwh3Thv1u5hxSuD8M61z2M6ImxVzDyMBpshMGCCn1MCrsWjb+cKErSsj6z6bpFJSaO
         3tdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="iJj1JmG/";
       spf=pass (google.com: domain of 3srcrxwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3SRCrXwoKCRo0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vMZyTBp4HX/dOqdnDX7X7rbJmCGHYFwR3/rStCLfQBU=;
        b=TuAU3d996+Ejm/cJYmIyUvsnzQJYqNCmJpJimCbfQKoEQ3IbVTN7EUaniHLP67dx4F
         I6mK4YaCdqQZAU/4bqpGDDgUCFdCCvZozybbRqW+sdTxbC2/zWoOhVqWsdvABGpOsyQ0
         ncC4pZxlw7c/N5LczF0nW5VhxkY4tnL9H0eauzYkFtUOyu/CK1NgqdsFCG+dxoiyTmsf
         wv/33+MkUpZseARnp2ELKJQN9b7k4fasSPMBV9teW4HzsJtc2Z0HTFPKpSaD78SfNRnb
         8GiC1/GJkVwRtNwmTrIYL3wQS2yv37/zUeW3/gXThtQucakTG3xCqgjKMIPf87MJJifA
         MUZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vMZyTBp4HX/dOqdnDX7X7rbJmCGHYFwR3/rStCLfQBU=;
        b=DDrRHQyjC229vXahr0g0QSx/9brtqVPfkpf1LACDpfF5VEBffNA+7CZ5DJCFLuDpM/
         GcCpX+i5Q7dwD6kcaxadccrfgKgrhmG8aC4MptsR+ojC8wELXmaH2V9LBqcPnGK0FZMI
         oadkLiYKMbk0HqSrF1Q07cZ8xMMvznu4IwHuDpLoEZ4m40WVvLAgBYFj3LmGQogT56ez
         BuTIQwIVripbUKQjLESNY83qAsjCb4MMai/yp3uihhlxPoRsB4mWip7M690Cf9w/oirY
         IDY5ld6oTOt51ExQep010GsGJkEqQ16lb2ZAgH51xstoIgarp1KR6es7qq1BqyktVWoJ
         4SOQ==
X-Gm-Message-State: AOAM531jk4/zNpfv1ZZ8uZPLA3WHiooX0O2g16L7+JzmRzAYSKqrL4dy
	x+BLMEkwfN5kbhc8NY+iOxU=
X-Google-Smtp-Source: ABdhPJx7ZPqXha5kgtRtFko9L/KI3i1XvC8BCN3mSAf4JhvdNyhiMfflwo0yl8Fe1hcGwxLIXId/wg==
X-Received: by 2002:a1f:1242:: with SMTP id 63mr12002452vks.8.1605046346523;
        Tue, 10 Nov 2020 14:12:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:3113:: with SMTP id e19ls906869ual.6.gmail; Tue, 10 Nov
 2020 14:12:26 -0800 (PST)
X-Received: by 2002:ab0:6dd3:: with SMTP id r19mr10931544uaf.86.1605046346063;
        Tue, 10 Nov 2020 14:12:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046346; cv=none;
        d=google.com; s=arc-20160816;
        b=aRT8x/+5hYp5k0GWt3STf3Rx7dPjOrgESN3EfvGegmPMKSBsaPQ96XbEAx+41CQiTu
         TEJlCZIlud/aEtFwZ6g9f6XXK0ZHcc4nNDiH329UBokKk5+qsU4T6TCiondkQtwKG+lx
         pIjZisdGpJfD2yKPvtXGbqo3odKQxRL54+S2dg4FbRPxQ6zPlI80bBDLBQtdU+y5d+94
         qzWRTy7npk/d3J+dPKRlRgORXvthZBsV5OE/MlwG7H4rp4DximUOrOucKf5P6fPPo5JD
         xPH6gqnmc3o+sWkebt/PYdcZ2Bg1ODsGSvicw3hJ0VMKxMOtUyQ8OWt16/Ec/G4awefK
         6JGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=l253EjoD9wZWKjcMl+HZL7Y/RWdoQT2M7P8mMLYHCko=;
        b=GQiWJI1Qro6FYMlOUCXUl6eMNQwQoaPLrTMcatX7BAMo5aT2FrPaZjmBE3ky5WEnyO
         jimIu9wA0+wFlO7pzMh3CuurGC1M6bGgrjFwTHwGBuoeN4een+DFL9tL8sgw/3yeXe7S
         rkLM1/aRXyRObM2kHMINXLqdhT1UFmgdK1NKRP1O2x4N1QAqVB8mrzhBKSHwebrWSswV
         A9bo0p3S2QGWEMWLFMZBtC0ZnBTlKFks6qFry3iORCuY3C/CwV1sKveVU4T1aygd0BSz
         fhTrHUiNQcfMC39QupgSL2HK080xO6kXgthV/XROr8pGCVW3gDbRWVOrrjiUOriCs5BT
         t5wQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="iJj1JmG/";
       spf=pass (google.com: domain of 3srcrxwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3SRCrXwoKCRo0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id m17si14172vsk.0.2020.11.10.14.12.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:26 -0800 (PST)
Received-SPF: pass (google.com: domain of 3srcrxwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id x2so164805qkd.23
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:26 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:aa8f:: with SMTP id
 f15mr20403403qvb.46.1605046345539; Tue, 10 Nov 2020 14:12:25 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:30 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <c9b863d85d5a22af9b7a294b99ea98e1fe47d7a9.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 33/44] kasan, mm: untag page address in free_reserved_area
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="iJj1JmG/";       spf=pass
 (google.com: domain of 3srcrxwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3SRCrXwoKCRo0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

free_reserved_area() memsets the pages belonging to a given memory area.
As that memory hasn't been allocated via page_alloc, the KASAN tags that
those pages have are 0x00. As the result the memset might result in a tag
mismatch.

Untag the address to avoid spurious faults.

Cc: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
Change-Id: If12b4944383575b8bbd7d971decbd7f04be6748b
---
 mm/page_alloc.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 23f5066bd4a5..24b45261e2bd 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -7593,6 +7593,11 @@ unsigned long free_reserved_area(void *start, void *end, int poison, const char
 		 * alias for the memset().
 		 */
 		direct_map_addr = page_address(page);
+		/*
+		 * Perform a kasan-unchecked memset() since this memory
+		 * has not been initialized.
+		 */
+		direct_map_addr = kasan_reset_tag(direct_map_addr);
 		if ((unsigned int)poison <= 0xFF)
 			memset(direct_map_addr, poison, PAGE_SIZE);
 
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c9b863d85d5a22af9b7a294b99ea98e1fe47d7a9.1605046192.git.andreyknvl%40google.com.
