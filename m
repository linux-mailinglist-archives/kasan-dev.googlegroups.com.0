Return-Path: <kasan-dev+bncBAABBZUB36GQMGQECP7VENQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id D0E814736D7
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:53:42 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id z30-20020a0565120c1e00b0041fcb7eaff3sf5794464lfu.12
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:53:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432422; cv=pass;
        d=google.com; s=arc-20160816;
        b=NOlks2CfVlv+WuPC/qFXg+mvFaJgGPqQ5i67mzSsWHn6wde5yu89xBXSl6hNR4a0Xo
         SryCdbn74nnTBfn4HDgS92ssY+eolFtNEivBoKufiMAtYZ++/aiJ43tgprzQ0XZMN70e
         VnqkoPz37VwQIUJH8OOAtDJYSSsvHsF4cJk+ZgDDL2GyLqe1jyE70QUFf7jwgPAE49oI
         2hWa73NrWSASC4u3k3OUYuEp9XNiXmA3xQHIYFwMzQgpRizyTlyAxr+69JCrKTRZEv1x
         fb6Xcy7+yAFBEojziheayzamMbf/iSMaX8moymUx+ZW4HOq57lenJQRWrekbE7FCTT3X
         3gAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9YMgyRDhYTU+fUQdSrZzQmFfj5FqPQFcNFc/rpNG9Ho=;
        b=PVuarv+JtdYIh5FZeILbJc+gKbeuW6wmkaa9weaeK77nhawk4hjYW7rbHXeUcSQxfK
         PORBGgGP4IPprpDW7Sm45oqB9qOowjMqaQvu19W7u0hs7+dT4Z7yGGx9oqxyFTNF++CL
         ge7FDu+pZm6IAfFwFgwd/eV8gXdxLihM6WGjbeV3X8berB5CHCR5lhF+Wk99BCiL91Vm
         fUqtjO7mlWAHxKAP91t6cvL/a6WxW/olzKs7x/cbld5uy/Srr2Nq62BG/prbwX1bO7oN
         ttZ4YYiOPwFBwGHNLOrNr8yAZqCHpG/q92gb4A6k6fno0N45JwqE4kRnaurLC8ogITEb
         OENQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=wBlPvUru;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9YMgyRDhYTU+fUQdSrZzQmFfj5FqPQFcNFc/rpNG9Ho=;
        b=Ed0zOSrn2FinxdE/qRsmAnd5V5jDzwQNtylBwmzoyLBHKVdy59tapC2v8x44szz9qr
         lwQPwEOfNfOZm+aUv/Y5VqciTMeXATu9moumXia4Amk/97H1/ymwPDiSwwNXZ2urPiWf
         zihbS+f4HogOhka0255qjWQfkD8w5v0zCPgjdhnJjf+iT39Nq9QKTkdL2iRAT4FEo3bc
         5d11fK4RS8rCqAtK1KUmmwmtIFz1d4Q8Epyj07UX2NWRKjhSMTBpt60fmmYIC0tPcGhV
         V+lX7cVE9vvD4HhSfYjr21kNUXBxTtdgJMXh6HbK/fMGcqL+ZRC5Sdr9gpCK4zqb0XOW
         dCiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9YMgyRDhYTU+fUQdSrZzQmFfj5FqPQFcNFc/rpNG9Ho=;
        b=bulfiQ9XqOcz820C3atXGrnmhqoRD/qX71T14KCe+oKVDwq8cgjAyDgZhW26Mg2GDf
         XhxII8zRJPmICz9vY+pxPHiNulgNHvnZWzHPBXyH9LkSa5u+7uvU7jxDlCbVpXU77+jV
         iSFnwSZSmCJsoLvt5BqdBr4rajhmCUMiO2g9YcFBJ22Ia5o24p6YtXrxoI75XFLodEjy
         FYKGpVGT15w/c0KnFW743TE74OXy2Q+sonTC8s0mxvgJOojvOWEC/Hnyd2HsaytpPEQa
         Ld8BQqtPloIl0fN9gXgIs69C7V1TOxVQTW8JsZNGW6PH8kGeqa+dYrtYH0ZCC5tVkB0M
         R43Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530YUL5Hl5hljjzY7fcX4bpry5Mu/chQ8q8ndcI8FDvvhTzoGZAg
	bqnCu/1SMMXRONE9eZ8F52M=
X-Google-Smtp-Source: ABdhPJzIVfd8njL3NIa7V0D5jnpD6fSsdNn9Cx7wU5Wp5Tv1cjWi+SObZooIBEZm2BYv64cEfpmDvw==
X-Received: by 2002:a05:6512:2292:: with SMTP id f18mr975159lfu.18.1639432422411;
        Mon, 13 Dec 2021 13:53:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8e74:: with SMTP id t20ls2712585ljk.11.gmail; Mon, 13
 Dec 2021 13:53:41 -0800 (PST)
X-Received: by 2002:a2e:bc1c:: with SMTP id b28mr1122613ljf.500.1639432421497;
        Mon, 13 Dec 2021 13:53:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432421; cv=none;
        d=google.com; s=arc-20160816;
        b=aMboVnZZCLpBZXLhbvR3gHYUPbPQUCCKb/LSOBbwV9R/v8tiykBMUyw+nvFcjup31a
         U0w4viGOCcGRB3/q2d8LF3xcdJBMjyrAzor0g+EVoRtdYhsaEnBPd//ERHawoY6bD2+L
         FKg/Lve9JZaifJ9UPRuJfsqg7dDqxEaa1nXFrVfIkJ3X4SPqCHjzvQEuDaCUxgTREPRH
         1+bItKakk9QIDeLEuCK9E9o3h9/3081UlAJC0nSdZ5+eP6wOQwrWMDylr5uWBCIjxBM9
         KLxulmVxebmSch8mKGowZ0OJr+Aq6epG+Z7dkKncNC/Hy72+fXFl5GZ72EtSSmjuYIKH
         RMcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=s3l2s0+hmq5iLRz8+HP6zciVmRfmK7g/3R40/Nt6UW0=;
        b=IxWlcC601OI7p62CRqMqxSETMWWh+Osa7ic8bFcss88c0p+ls3a1Bh8tN9/sp8ArxF
         2jzbtD1dNspOf2W9yoEeLz0fO+E/H6jxdXHHc8QcKQ0RlG8H1sJMOVim9azkha5+XxVw
         B5jIvFpoizhFGM1T2xmtMfOSLbo9tdz/4SuZrxg2c1mJkAPp+/4su+Uet4uIYN27Rn6J
         BZSFqiVeeEkvpX+fc1hss6mlqQLolMrLDr8Zx7BOieJezGnCSt6IOvjoHkPWNke9ADz3
         LvgbkTcYn8KnvRofF01hUDNGQ8eOysuy64Q1FBMyabJUgJwvCg4ZDdipJnPClInpT/6l
         Ahvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=wBlPvUru;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id v8si691766ljh.8.2021.12.13.13.53.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:53:41 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH mm v3 13/38] kasan, page_alloc: move kernel_init_free_pages in post_alloc_hook
Date: Mon, 13 Dec 2021 22:53:03 +0100
Message-Id: <6f430d8dd55a22e141b0000357890d872b8cd487.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=wBlPvUru;       spf=pass
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

Pull the kernel_init_free_pages() call in post_alloc_hook() out of the
big if clause for better code readability. This also allows for more
simplifications in the following patch.

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 12 ++++++++----
 1 file changed, 8 insertions(+), 4 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 3dba92accfb7..90a2f353d230 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2434,14 +2434,18 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		init = false;
 	}
 	if (kasan_has_integrated_init()) {
-		if (!init_tags)
+		if (!init_tags) {
 			kasan_unpoison_pages(page, order, init);
+
+			/* Note that memory is already initialized by KASAN. */
+			init = false;
+		}
 	} else {
 		kasan_unpoison_pages(page, order, init);
-
-		if (init)
-			kernel_init_free_pages(page, 1 << order);
 	}
+	/* If memory is still not initialized, do it now. */
+	if (init)
+		kernel_init_free_pages(page, 1 << order);
 	/* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&
 	    (gfp_flags & __GFP_SKIP_KASAN_POISON))
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6f430d8dd55a22e141b0000357890d872b8cd487.1639432170.git.andreyknvl%40google.com.
