Return-Path: <kasan-dev+bncBAABBZHZQOHAMGQELIFQQCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3894647B583
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:00:05 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id bi14-20020a05600c3d8e00b00345787d3177sf574525wmb.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:00:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037605; cv=pass;
        d=google.com; s=arc-20160816;
        b=zA+urjkwB+UhTvREevzbahSPx0MwGluLS9qSoTWfBGZVPdHRE8uvN27WtFmCsYw16h
         vI/85ZlA2JBmIsS6K3Yjb0Z3PwUeVCF9JDeKdDKLVId7AdqzUgSJZpk5PlBeYZ5gvOKI
         KM8il9m5FZUIhKQOdvvUpddPC4BAa/nP5UY4sltFzyyoCgQNX257sxVIOfAjtV1NM+KS
         jRQHezOu+DQvDJi4JMFxpNbjRcqEbCc81YOdfNhs+bTV4PCNMDVvTPzdsqYe4o0T7pZo
         4+IHv13kWtzk5qmdCHNGxezHog43KyY3IiAD+PV25PKaseYwlE3/njhg5PZLX0mX8h0A
         Nfzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1DczZ+rrw61Dm+ZUHKW2aoKng+s6yTzYXZ32K2Yk038=;
        b=V3OUa5OfQgCFB549j67uOA3bMzZleXKKx5slfu+wzUPArST3KJcO/8MS3n5cT45DS8
         QAf9Xno2u2rjIPh3PpfsSSCQNXVt4AREToL57UZdtvekTvtU0yYoQ9Wev8raGUh/HuMU
         khA+tKz9NTNiyUKKx7YI7U/AsdctGGXoWCVJtJiiyRB3entzMWePUIxH8K7sorgYRR6u
         yYsDEel+M1hub00DwNknbVwFjemv+K1w9IswwfJa38i9wn2FSNWMPtLbRVbBk7L3/AZF
         sKNfdPt8guHiQQu7WU64Qhup/MFAWNTZl2gBBbvxdkyKjmU4oT0osJ5Y6cVF9FVQGApD
         nJhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HfTr9ZPx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1DczZ+rrw61Dm+ZUHKW2aoKng+s6yTzYXZ32K2Yk038=;
        b=t5MqC++VsN3HVlnuosdDK0awKevpkaP4uLJVxTZZsfxVKPhtMmtDj24FfA/XVdhBko
         dy1F+/J11wV8K0ZUa85nn+tj3mb73YTGDLFA+vcotKz/9D/ImiuhDu4HnzuD51FXHZbj
         EBjAFDhjM42/zbTxKSJe5ob5EB23kX4tK64YoQd/1fYKnc7ZVJhoOGnAITMmjfz1qp4T
         iAoRcaHbKIiFcDDfN+5GWCS5y+rElAMi7B/QmwOmJfBgyJPkKErtb6hWilDa33wMKRMM
         lHI7a61BzsyVdYyhuzeMtvvvcYuNhTFNwKS5S9iTfoP9bPmSRT5qUdEuC49LbY6CTcq7
         pFxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1DczZ+rrw61Dm+ZUHKW2aoKng+s6yTzYXZ32K2Yk038=;
        b=rjXVIuVm1p3ah2WE5Q2TFcmpXuK+lqdnLcUoFj2ZJWvjoQ6cVFj56WnjpL5vGX0dOy
         BsXjHM4XMZl9ntHsCNocCpzU/HbsvXq7mKEiQAD6t9BT54ltiwgi9Y2m9oMWrO3L/4g1
         fdSnI8ToarrcIFb6quVga2jaSRJNSBFrCft6uqRSurxoGP63kA5W8Ij8hB6I2CVnJ+MN
         A3L7orOY1WwBhm4SOvC8h1hr2hBCT0ltViHiTzptxFtlHEJGoIgAlmz1WjiyfwVLPpzK
         Rg6v/tKf/V/53knjrnVNgX0WKpdACvSX7MsM9IKmNdItVBdOl/e7EqKzCJOkmH2FkPgk
         Dwkg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530mSg8uRSNjfaNNJs9JWEkoSgeZXyZNFEXAxkJzWCYGFyzKgido
	T7nPZznoRIZrNPSniyHrACw=
X-Google-Smtp-Source: ABdhPJx47IBF1meKw2VSopUEsL4kYcMFOgnpQSU5fK51celoZDMw80m8jbfNI7A/0eIS0v1iY3Mtzw==
X-Received: by 2002:adf:eb0f:: with SMTP id s15mr101099wrn.690.1640037605029;
        Mon, 20 Dec 2021 14:00:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5082:: with SMTP id a2ls6378883wrt.1.gmail; Mon, 20 Dec
 2021 14:00:04 -0800 (PST)
X-Received: by 2002:a5d:4d4f:: with SMTP id a15mr114051wru.268.1640037604469;
        Mon, 20 Dec 2021 14:00:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037604; cv=none;
        d=google.com; s=arc-20160816;
        b=Xmo21nMeauaGz5h7QqSXk86lqYwg9MfiIxnsRkP6vlYYHbanOu7ncdKIRJWFBaPNkR
         szjE5U6OlRZlYAuTOx6Z64M7pLCuDHYkZjPDrwdu2EDTFZIQi+FhX5VA7kY9UWZyuDAo
         Mg1wSuQURkIKD6GdvrlpEijc20EP4rYzr6wNa2Ys+yYk5YGp/Jz6nA3lBq+MGd61GXqy
         q9CTm3JoOrch41DEITKuC4xL6WxSdTR3inQDojrHhoxBDKXdnXzFBrakRtNm/1WsfsoQ
         lXMlQjwNTOYgrr87b2TqkYBMwOy1B7wPwGtB4C2VDfI9ucBnogX9qK5+r1roXVRKo8VM
         y33A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hS4TohLHRNxTcrS94rr2W3I/olYmo6cospSu32Gn/iI=;
        b=Lfj8Nyk7bLf1r0DbEkKJVyhCZdYIEPwDRyZK9Y3eHsaou0TNDKmnYg2NDnFbxWy/Jo
         FNnungYxhlnxopoDr7AheOceAssNCdUHl/OxIUjd8dtO8fTjg4f7PzJ0/pvSwYIkhlbx
         EfHj2wxgi9eIWMTB0x996oGyD3KWGIWOQR9rHGRoPpycASchJZ8W9L0ogSdZV8Nqp202
         s+bJoIXlk+2hqb2FzeWGvsdLFNjbUmzA3tds9Z5WHu7NS9per2XTFTi0rZamjDPL+s+P
         qHxLST1zI/w4W1LXgYGYKqNHoMOF4Sms8g/VOZrhV7ODWnWTWiLct/aGfDJJc2NffftC
         EhMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HfTr9ZPx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id l19si84494wms.3.2021.12.20.14.00.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:00:04 -0800 (PST)
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
Subject: [PATCH mm v4 12/39] kasan, page_alloc: move SetPageSkipKASanPoison in post_alloc_hook
Date: Mon, 20 Dec 2021 22:59:27 +0100
Message-Id: <c85e5280566f113353f0c0f542304208e186dcaa.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=HfTr9ZPx;       spf=pass
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

Pull the SetPageSkipKASanPoison() call in post_alloc_hook() out of the
big if clause for better code readability. This also allows for more
simplifications in the following patches.

Also turn the kasan_has_integrated_init() check into the proper
kasan_hw_tags_enabled() one. These checks evaluate to the same value,
but logically skipping kasan poisoning has nothing to do with
integrated init.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v3->v4:
- Use proper kasan_hw_tags_enabled() check instead of
  IS_ENABLED(CONFIG_KASAN_HW_TAGS).
---
 mm/page_alloc.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 2d1e63a01ed8..076c43f369b4 100644
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
@@ -2445,6 +2442,9 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		if (init)
 			kernel_init_free_pages(page, 1 << order);
 	}
+	/* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
+	if (kasan_hw_tags_enabled() && (gfp_flags & __GFP_SKIP_KASAN_POISON))
+		SetPageSkipKASanPoison(page);
 
 	set_page_owner(page, order, gfp_flags);
 	page_table_check_alloc(page, order);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c85e5280566f113353f0c0f542304208e186dcaa.1640036051.git.andreyknvl%40google.com.
