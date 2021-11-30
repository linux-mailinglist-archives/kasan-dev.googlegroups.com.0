Return-Path: <kasan-dev+bncBAABBJGATKGQMGQEMDTBFRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id A75744640E7
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:05:24 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id r129-20020a1c4487000000b00333629ed22dsf14542354wma.6
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:05:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638309924; cv=pass;
        d=google.com; s=arc-20160816;
        b=O37Oof3gM/qMvVaiobDgdQoWlYooSrRV69EXFAIlQIIJi0gnhypxTdVJd1rd8x4Ifa
         V2yMO6dVEdWnQc8yF9cNTa4cVKQqm7VLVOu44mS92vYVT3v6hU3ZiXTWFaJiYxtFCqqY
         Zo1jfEZyEeyQl7gYOgIGxPxZfX4Vqr0otzTL03QtWvqN056LSACi7n+1oziN2LzUF6Mm
         UMSC6EE8TYLFWa33LH214JQ6n+GSRI/xgT4aM7TxNDgT+fPEqADSbqJty7q88EEAkiod
         6SAX9QE5xKF7C3/W/MvFHBVIxJp5dppTkj4XsJt68WS0Yu7UbcWrGtlzm8DjgYQ16r33
         6QpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WwLW/nlPyyWqzZgvGtDf5FAgzfAppyXcNMCr63v5xm8=;
        b=Sd4OeY1QOIQ6u2+zxKmT2FIXNNCuRbi54c7weI6RgKZ5ZxsGLiFiKv668RzVwihASs
         L035kPHm/K3WaydtACGIYesQqvzdY5i4RXE3ol6WDNnTCgPEDx1zH7v50z8HnW/Q2GJx
         mBFZTnyVM2b9X9e/DnvSXx7Rk8AYFYjhsQlfVu4FqaZpKnMMsjb3gnX0xkbAm7vUtz1I
         RomJwt2Ma1UlW1m6Ndl6O9UWzIfcISnloRv3eNMwyKeqDWu/HR+iVcwczEsSbqsbHiLF
         IZDfShbPCVHsBo9FmRIfvqnNCH2Odq8Wge32RLsDt13/PA3GJTFVuzjWyX9thnragdLH
         v1wQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=WwhQMs8P;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WwLW/nlPyyWqzZgvGtDf5FAgzfAppyXcNMCr63v5xm8=;
        b=rdocpAwbulJoGEbXp+ppnaG04Zk2FlsS3ozrBuIU7Sjl8IvPCp+xjma43jcKCLEPtM
         cdVm0ZcUR3DkO7SlLXUNJtVKvAHxrYKy+77UMAOGTB3i4IjI59JjLTSrT39p2EYmCN1+
         esJpertb4Z6eD9rX3Kcu0fRzuNLqhTPaAKrK9vnlVgIKGGEHsBIXIL6xnLAu4/y1WuER
         jvhhgYNzynkMmIBG5aBmNXLIjq52AbGll/b6PD2PmPzwtpx6tiEkAXvojXVlgHPKbA//
         /zuCY56bYMmy9fsI2nd+rdh7oAqwO1ZegZ61J/6Vy88TeW+cugIPe0g8AFjYcwufU8Cl
         ZllQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WwLW/nlPyyWqzZgvGtDf5FAgzfAppyXcNMCr63v5xm8=;
        b=pOEmi1P5M4V96ut4jlU9HyyJ3CPWZ8iKeFoPpKzvgADXgP19KalobYAMM83ZaGW865
         Ix1hsjRThZSFdQuzc5MHmrDjbY2t1HaCy9Q51qrRHuIsipcI8muthW+o8LKeVBZ7/Z2y
         D+IS8Fvl4yyauW11BJr4mHg90q4CJZsT37c3eOz1PY93eUmGRYLwKQkzIKoTiOG4xWAs
         T3UmcfPOp4BaugWLjJK1NyH55b8AzsLF6pA7SLwRHtGRteg6Aqk+AzX0pfvBOk2zlIYL
         U6H5seMqspjgA/pO7nIU61AzUh1s34hw/Hol3ygMRR7emci+jKfw2lvOZ4O2FvuRg0CV
         Mqbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532txcSrAq4JOTH62uSvVu9E6kHJc4bvQwpM1N6UGndOTnyqJYUz
	IwBbY6lik7KBCVJ5ajoi4ps=
X-Google-Smtp-Source: ABdhPJwtUPwNjqJLHBDAfU9TXUCIqDF9AJjdgXqc1UA4mcDFU91Y+nXMMy0piOeOtJhD6P3TSDAckQ==
X-Received: by 2002:a5d:4901:: with SMTP id x1mr1815255wrq.473.1638309924476;
        Tue, 30 Nov 2021 14:05:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f1c2:: with SMTP id z2ls182472wro.2.gmail; Tue, 30 Nov
 2021 14:05:23 -0800 (PST)
X-Received: by 2002:a5d:4883:: with SMTP id g3mr1860820wrq.590.1638309923742;
        Tue, 30 Nov 2021 14:05:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638309923; cv=none;
        d=google.com; s=arc-20160816;
        b=0n7NwgrQMW2E3wLBWJdL6jOEtEkElQuRrd7nTREjoRTY7zNQkmhI5VsGmXw13B07Da
         neTsAG5DPlk0PjHAh6jJW2KIPrPhMy/UmvCa7WutXTZoWMfuXq6pgCLnM/w21ubR6+0G
         NnR+CRKfryr7z3IosYkD7nZ0RIBJtf1kGgWUEpNGgtRDjNnl+9DQA4+daBGSVQxNJWbu
         7Bn7xo0CoesBo3CLGYgIf1Y2Ds2V91oZTvmHxK4BAjPejbc66mIXzfFdGUVXb1E8fUOo
         jIvM+AaRlNOTfZSKI76vnv9aun6VQwGvHCNLKIAhJFZgtoJI4MhRtqtSpWzuvZvVrh3h
         BWUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Sut+qBc/xV6+rquXwy7nNFMfUaiQqTwNo5aWH6qdopo=;
        b=l7Mcui4+cC2bsvccg6uqTWfjV+5z7H+pn+BREd8HT9xO9H2gRDL3j9VpjKu8VOiGxL
         gdCO63CH34OJvhqKY614VzWqMGzFCdyogWsaxwBw1mjSyB3fhhquUPRhe0B8+5iIZxPd
         LQiqIi1VKQTTEK6OkWVEiI/Dm23Cbz16/Ca284lBzebFAKn3/cX3bQlzCpL8L2eEGaYO
         Y8CEFhhawIXyOJBpxdkdDHzJJomNqzXMqhJX6yLjeJhM7HR73hFrTZi4gRmaCVebbVxo
         4ih46l6HR4qPmjzWgccQOgWgzuJvOBiLtWROYQ4aJexvMt/aZ30cLzFKEjUpryuZIL/D
         AodA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=WwhQMs8P;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id u10si1616009wrb.5.2021.11.30.14.05.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:05:23 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 12/31] kasan, page_alloc: move kernel_init_free_pages in post_alloc_hook
Date: Tue, 30 Nov 2021 23:05:21 +0100
Message-Id: <bae47a6b61af585f7229b64645076d8a93f4e088.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=WwhQMs8P;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
index c78befc4e057..ba950889f5ea 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2421,14 +2421,18 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bae47a6b61af585f7229b64645076d8a93f4e088.1638308023.git.andreyknvl%40google.com.
