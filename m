Return-Path: <kasan-dev+bncBAABB2EIXKGQMGQEIAPCFXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A6C046AAB6
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:45:13 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id u28-20020a2ea17c000000b0021126b5cca2sf3831568ljl.19
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:45:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827113; cv=pass;
        d=google.com; s=arc-20160816;
        b=g3Lms7aJ/VzegJchK6yGcHJ2Li9Iaj+Mb9PC+H28EQqJuhs1GeK0EUl+0pIzKkw1W2
         dNigJljpX9zLP/ATnTY90dg0YKJBfNuJkoVaRPxno5bX+IgPnb4Jp7USLy6ZGoqnawoP
         Ozykpv6U9RMvsBiRUSdSRZv+gnXQr0wYcNWNAgLdSohH9TbuoVp8aqNMIddiMOA6Yu9+
         9LujmJuKv54zbg7gOBHSZuEEoVtDR9S53KK0qNr5/1dS196E9nMoL6RKTW9qybHP95fq
         yEAL0QqjReqPN/pJDyK8lKKGc+tnmcLc0wPAYh5J734iQo14u0zxpvz1BwOn0GMACXFo
         S7jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pacsjY42wcRsvtPZ1+bZwuhfK2Av1YCS3zOCUCGGiPI=;
        b=RWFSGfBRCWKPm9O8VYlPE1RL7ZbtQbHSvVjzMi8uav0X+fzuajs5q/PmfozupDSoJL
         SNInmKdDWj9ToixwUWfhqzJ2CszVj1IJpkoerWCeI3FbfEH/SYxQHfdATgCFafpd2agv
         0HxozcgVRQ4oHAr3FvtqpmGqJxBWWO8aVBql8a8tpkafn77I35dz9QhN1QOy3QhhLv2s
         hRLVAEjgAefrmc5Wgvu5GkmC/Kt1Vy/SatuwGQ4pDSPCHCPdApLc1fKvmGIKAvMM3z+J
         qHFiaQCfF4Uli87F08ta5RWK9zOYhVHmbMQoVFrvCeHcU35XNM8jDfONLTQu1cbi00Fk
         UGQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ae5GuST6;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pacsjY42wcRsvtPZ1+bZwuhfK2Av1YCS3zOCUCGGiPI=;
        b=ZJdbOiflW4ZbRsL7zDjcVtLpiR1pc056AKrI8/gbB0eyk4G2ASki2TWUaM+o+5o7Hz
         KrmF9Mp4kZ7MIOLpwSp33YaztRqSHRxdFbks4/1o4fFbKPghTX/AMWjQHr8lv4bWoIb1
         yFohLMO7lB4TFPPgM3SQeGTPbE7pd99DAW5vPTPK9BBPxHcE0cUT1Z/Etv9wjrYgQTUl
         +t1yN3lJx0i1fl+w36QnpjtERj2UQNCAvhF85fIrJngyrIFExkoKjxDGxU1A29t1/kkJ
         2soStKsC/mLVr29zPRj4FvQvpMU1OxJcnDhF9EryhPvGJueOZMK87/ItzGlmhkkPoYOd
         n4gQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pacsjY42wcRsvtPZ1+bZwuhfK2Av1YCS3zOCUCGGiPI=;
        b=vtlt8siZGVQARtdLcJLTKhmjEGYOHtfUOmlir/M+R4tZGix+cZ0dlJ+7/cmNl5lEhu
         ZglAbw1knheYwzmtm/e9fJ3zxsu7yLVV30+m27sAUYOpFjT5LcMO/BkfTXP5ou0kgIPE
         ySepPztMZQY3f8r2VOgZZ6PJlESwXnojYmuZN4De6p4/iWnQymf0YSA10+rWXwJGDRqs
         W5t2botmwGpACrr2k25ip0Kor4x03ZResdhJHw8CsLD5eKBTJp7DhESqqqeCzjIWLB5v
         53fMMJ4wLdD09rg3Dg9SS39SpYeFJnHNLK+mgIJaQW02xhKNoUanhWcg/OA/IxI+ctnS
         f68g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Bhy57fLZkWsxlxRll7A2p+AvjXbF9sFhi1PDiode2We/3w3Is
	8TujyAs3Ntm9/WRvG4nlvmE=
X-Google-Smtp-Source: ABdhPJwNT+McD2PwDPW5+DM2ZJMT2HzmYgPOTYXggsKrFfyVjXfxqgyngOMw+K5hIigNEqha1ID72w==
X-Received: by 2002:a05:6512:3991:: with SMTP id j17mr37538495lfu.545.1638827113047;
        Mon, 06 Dec 2021 13:45:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls1925457lfv.1.gmail; Mon,
 06 Dec 2021 13:45:12 -0800 (PST)
X-Received: by 2002:a05:6512:2506:: with SMTP id be6mr37842025lfb.597.1638827112180;
        Mon, 06 Dec 2021 13:45:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827112; cv=none;
        d=google.com; s=arc-20160816;
        b=0ava7RBZb3MFKry9qI1ny00YmdjqipPujPd9rWgu/3qKbOq9DOxy/90T3SmYMDKE+D
         T5Dzj4cvGfefZQu/NErwypgQU6y5FJecoyMS79jRXOQK44uQnRIT8qTmRKIH776r1ITt
         qyZU5X+8gV9yQqMF+y3uMQpXkKIBM2vmRpSqNEGVFXFTi78CpbYydujEnhuxhpPxRL4t
         AY1QeDcwkWimR3jT0q4jWqNyxNoUU5GSRG1M/TuA3V3cBt9Z0v3eWvfvjLSTR23Tury4
         CakGBG1ykZCwO6ycdxDFUciq+aUu+MvYZ2emFs9FephpXFwDccoy54w+DnnQomHrJYK3
         XYww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sMKllahn3TRwqEUvrph4wKLGXjFwUnG4mJTUv85O/gQ=;
        b=EZwPZNMvLnhBbEb7yGAQhqWOe/Ed/ZGqCUqu65/MDA34DSeD0MNEPND1bC3Z6M1GyL
         DWaq6Ave3HC6ehV3iV6muI1sV3AV/LE1tVHvgD7rl4j+JAgwnI/U9FsLO74gtgGgKvzG
         IFiiiP0yFaaQ4g6bppsF011bJ61hwZWaL9pG0Af3WuNF4L1g/mf0d/796LENORO6kAJI
         yok+rpidOiAssdJhfphTgrLjXKzJelOeB+NBMHvg/REna7Pgy7G17v1B+blwnesyXi8B
         zHvsyyvnSh7fJCgkVrxySqG9FS4ECUpmfKDsB4gg9CMY7ZICYhJuBEem408ULBznWC3p
         aV/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ae5GuST6;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id b9si994085lji.2.2021.12.06.13.45.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:45:12 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 12/34] kasan, page_alloc: move SetPageSkipKASanPoison in post_alloc_hook
Date: Mon,  6 Dec 2021 22:43:49 +0100
Message-Id: <76d3972363dd96b33e6af31ea4332cc63d317837.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Ae5GuST6;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
CONFIG_KASAN_HW_TAGS one. These checks evaluate to the same value,
but logically skipping kasan poisoning has nothing to do with
integrated init.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 7 ++++---
 1 file changed, 4 insertions(+), 3 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 781b75563276..cbbaf76db6d9 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2420,9 +2420,6 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		init = false;
 	}
 	if (kasan_has_integrated_init()) {
-		if (gfp_flags & __GFP_SKIP_KASAN_POISON)
-			SetPageSkipKASanPoison(page);
-
 		if (!init_tags)
 			kasan_unpoison_pages(page, order, init);
 	} else {
@@ -2431,6 +2428,10 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		if (init)
 			kernel_init_free_pages(page, 1 << order);
 	}
+	/* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
+	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&
+	    (gfp_flags & __GFP_SKIP_KASAN_POISON))
+		SetPageSkipKASanPoison(page);
 
 	set_page_owner(page, order, gfp_flags);
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/76d3972363dd96b33e6af31ea4332cc63d317837.1638825394.git.andreyknvl%40google.com.
