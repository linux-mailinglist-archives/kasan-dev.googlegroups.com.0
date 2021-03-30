Return-Path: <kasan-dev+bncBDX4HWEMTEBRB2VHRWBQMGQECHNY67Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id C63E834EE0D
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 18:38:02 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id t19sf5637530lfl.22
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 09:38:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617122282; cv=pass;
        d=google.com; s=arc-20160816;
        b=fCVtKPPvkXfAajQxIgfwhs3YCkT52Cpquay/OXR1dXODs5xgL0hfMSXutpDHK8PSzO
         Px8KySR0oBnRJCSbW0TPPDl50fy6spBaFJqiND0WO/OoKtWgrgPKvZSs4s69HOE5j1Em
         exaId2lTgwavzRHRsQIbiPwYqE/Ix1ekobAVxDUpbkQl3EzOkOjW6vYrywCsX4QH7PNu
         vB/FaWhHK53x2q6y0eCklVF3uVG+KiBsa2LlAOnXLrpV5nD6P9c41DWBvx9JC4JEh3gC
         fapvAZIi5sh9IFR2XSxN8y6DBekhA50wV3pd1r5X3i7YHpoeUCex1lmpedhNaPRdtI1J
         DTEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=aWgMZZoYcj1xV98H+5vj8jgbq1y3qmVXLRDr/JPrhDQ=;
        b=rza5ofvgE913PRlCgrp7jR+OzdtLFl1m+9wXuS8Yk/jJEhzqVzE7mXG1qPc/D3dXfE
         HIYvBIV2HAAE5YR28Grg1FNjBg4LXS0H9oKk7yfG1NhbZKgHfmDEaq853kLJL94TDyzQ
         dIndDFg9I6kLfrwH9xeYmCoojebn2Z2hK7k93v60AtalahZPX6he2igrhnx5ePKizOO/
         078/bZxaMyJAJ6Wh550PoEDn8gnLPD6v+1PqNPXNEAGdfMdwKs26uKvnAu4bKtBc9+ky
         pIFpx1WVOZEbUP7+UVvFnrQ4rCGFXf91BigAWZB3V048hZRseT8VEY6e5F/FcxSjf/29
         cqiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=THEbeG6q;
       spf=pass (google.com: domain of 36fnjyaokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=36FNjYAoKCScDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=aWgMZZoYcj1xV98H+5vj8jgbq1y3qmVXLRDr/JPrhDQ=;
        b=YIvsDRjwjXHqZxN4RqyMIUo/BA+RwEubWUG06NrD1MQj3uZz7MzS0lmXVHF9rggkeX
         ODOrT6/ZwmZ1u2fjkaLj1Sb++oab2fzIs8BPyBQlDSWykVF78+ec6e9+6AiX10744F8P
         UCxMMiKXjgA+n2xa1tQjaTXAXxc+qM4xkuO/PAwBRMvHr8+JVi667nuCvnSZSKn6uT6u
         6rCYCEm/+BconG2h/8zSIee/DfVp8IbFTpDMYL0X3F4/fUVRGpArtLkl502FYYaz8IL7
         uZRkYSE/y69F2MDBxQvpRv7QK0rezROhtGNm5I1/TEf3LuukRkSO6rbCsGWTR/tn2T3P
         nHFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aWgMZZoYcj1xV98H+5vj8jgbq1y3qmVXLRDr/JPrhDQ=;
        b=RD3ilgW8pvkIjOMNa7ZSbuI7fENOciIJCu8bWb0CAlllRV/jsjLxbZUekaLiGFR5OM
         yVymVGW5Rp8ZQnUm+AetAY9VM1npOXzOaGKgYkq1EhFHYi2lBNV/jnd0qWY22/pAj6xY
         44bTfURrs8k09rGtQG2dXEczy5ro4q8JzjycrkFJFvhQHqvb3XUPqr13D553gbEaC1FX
         bw/8M5lGhATdbWFIDaO6eO1c57jxyKKptRb38IfYRrBln133Ryk+/DR5XOmXBHldpjPY
         LEBG6DDBOV4SHkxYscy90h+iMVTGMoHGhQkDM7hsdeId9DycSRYo+wbdfvpZahLVgGS+
         EaRQ==
X-Gm-Message-State: AOAM530AQaZO+flqs57p3f2NelwQESEvni4Q5ldUS4fWDQI4mwGRhwqB
	ydW4bL4efODhrwxxPQ2GT/4=
X-Google-Smtp-Source: ABdhPJw9J6RFsReVev8luuehgrCBj7TJq1ySoVLu6Ul0qL+bVvWPvdoOmlbdXcxSah0c7T9oGEHMXw==
X-Received: by 2002:a2e:96cd:: with SMTP id d13mr21708761ljj.213.1617122282363;
        Tue, 30 Mar 2021 09:38:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6c2:: with SMTP id u2ls7518223lff.3.gmail; Tue, 30
 Mar 2021 09:38:01 -0700 (PDT)
X-Received: by 2002:a05:6512:3481:: with SMTP id v1mr20326898lfr.193.1617122281371;
        Tue, 30 Mar 2021 09:38:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617122281; cv=none;
        d=google.com; s=arc-20160816;
        b=FQYfphqjR3FFYg2HcaEOeN6ybpp2b/XI5+m7YmEvizjmW155P+V5ZSpyyszAdw+GU9
         fbju4GHc9dWuG1FpvXxRsnpKwns1g+n/sUO0EgqZOrwZk/pbydvZn+psAP8WOfsj4thC
         wL+VWrPBh1pqgTZLhKwgxPVAHURpn/Q5lcl9SwLOYPrsNxJADECFEDW0S3YKWmeG4sCV
         kRRSrVtAkSIgFFX+x2U9G8j9WwiStsdOPZdgO3bkkjzFPMf++UbL8xYGKAOHjAZD6qAr
         53wrqQM8StM9JCxVQ4pBjJ2UAa3ncFHI9ofAcKj7v1HOuv/L6YLUNFmSpVZDaslVcHoy
         AuAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=SNuqqyD1tP1LYYPE4x3JSrsZ8EwStb88MAUaMmFkoIk=;
        b=G2vdxYI/yhRGrt0wiL2xMel+EikAxfjwK7brFn8K3GpNRozMY9HOUthAnDDqH+EiJ+
         eSKtDJle2H8F5z21wLf+cIUGYaniPniXk5ajHNmTisUSzbhkhzR0uB8kKc903GZ49L/N
         u9IDQusc/4W/kkkRfRGk9hQcL2j/T/wy4vBAexfFK8Fqjj678fJLp6nuY7oF2Dnn2O+l
         Q15V3oLy6FPKXOCkKtagGEsnmOEEn9hU5t9FGRz9HZqKOikBiZWVUcdqVjnboxi/FwIw
         dFKwMZ3AuSC2LQb7iCzcX69eRHhaImc4dSRMNsLhTvUi/XsP598siatkO5G2aeCacNGo
         jSjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=THEbeG6q;
       spf=pass (google.com: domain of 36fnjyaokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=36FNjYAoKCScDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 63si750246lfd.1.2021.03.30.09.38.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Mar 2021 09:38:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36fnjyaokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id f3so10608284wrt.14
        for <kasan-dev@googlegroups.com>; Tue, 30 Mar 2021 09:38:01 -0700 (PDT)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:f567:b52b:fb1e:b54e])
 (user=andreyknvl job=sendgmr) by 2002:a1c:1f4a:: with SMTP id
 f71mr4905469wmf.101.1617122280880; Tue, 30 Mar 2021 09:38:00 -0700 (PDT)
Date: Tue, 30 Mar 2021 18:37:36 +0200
Message-Id: <65b6028dea2e9a6e8e2cb779b5115c09457363fc.1617122211.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.0.291.g576ba9dcdaf-goog
Subject: [PATCH mm v2] mm, kasan: fix for "integrate page_alloc init with HW_TAGS"
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Vlastimil Babka <vbabka@suse.cz>, Sergei Trofimovich <slyfox@gentoo.org>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=THEbeG6q;       spf=pass
 (google.com: domain of 36fnjyaokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=36FNjYAoKCScDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
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

My commit "integrate page_alloc init with HW_TAGS" changed the order of
kernel_unpoison_pages() and kernel_init_free_pages() calls. This leads
to complaints from the page unpoisoning code, as the poison pattern gets
overwritten for __GFP_ZERO allocations.

Fix by restoring the initial order. Also add a warning comment.

Reported-by: Vlastimil Babka <vbabka@suse.cz>
Reported-by: Sergei Trofimovich <slyfox@gentoo.org>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 8 +++++++-
 1 file changed, 7 insertions(+), 1 deletion(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 033bd92e8398..d2c020563c0b 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2328,6 +2328,13 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	arch_alloc_page(page, order);
 	debug_pagealloc_map_pages(page, 1 << order);
 
+	/*
+	 * Page unpoisoning must happen before memory initialization.
+	 * Otherwise, the poison pattern will be overwritten for __GFP_ZERO
+	 * allocations and the page unpoisoning code will complain.
+	 */
+	kernel_unpoison_pages(page, 1 << order);
+
 	/*
 	 * As memory initialization might be integrated into KASAN,
 	 * kasan_alloc_pages and kernel_init_free_pages must be
@@ -2338,7 +2345,6 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	if (init && !kasan_has_integrated_init())
 		kernel_init_free_pages(page, 1 << order);
 
-	kernel_unpoison_pages(page, 1 << order);
 	set_page_owner(page, order, gfp_flags);
 }
 
-- 
2.31.0.291.g576ba9dcdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/65b6028dea2e9a6e8e2cb779b5115c09457363fc.1617122211.git.andreyknvl%40google.com.
