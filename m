Return-Path: <kasan-dev+bncBAABBUEJXCHAMGQEP64D7CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 90DD9481F8C
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:13:20 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id j15-20020a2e6e0f000000b0022db2724332sf6127019ljc.3
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:13:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891600; cv=pass;
        d=google.com; s=arc-20160816;
        b=js5ylSbKf279TnPso5kmYIRVEfaAYMKd6hnZNEO+tdk21FnLpPuqRYLfArIIiWb+j+
         UwO1eoChbCZCxFievMAQOwir2deGlChxdY2k7tP5uGmP61uroImv44rnOYaRRSCspLwP
         clDSHYS5h03Lc6neN0dw3ZNJUnaGmqrmNgCfWqpzQ4Wg2jsxU5E9R8KHU8hJaY4NN2S6
         4b2hHUCFw1BlkVz9xn6p0DOZ7V+BWC6fJreA1eb4lLKRd3i6Z4Y0YGpai++/0mjvg2xw
         8ECZbBC24fWI+9O7HQkSnptuFzn5SKKYdOfW/uIJhfcLf0bbAp938um6QbofUsYgRRio
         r2OA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5MZhG2O2oonFc6J7FCr39Ud+TXgVvF3gaLKQZJLZYQs=;
        b=ebf1AXKFX5IzMP09Y5IalpKG3afa3yNDgOyG0IGRMkn1MX1VB5zSzM8qWb/FWo09GE
         X13X0EcL/M5a85WHAmrwu19j7iF1qvOR9cpDwH3aYZ8S9qTK+0z9dWcbJDCU2eY8T4d2
         hl2MP9owgJpShWO5U3w7UcdmkFomlWXJrkj00NEcvmPzLIJWurxXWmgj2jEWkODd33KN
         mPns4dZL/GAzMQYehE9BrxoGbygHCzzWJ5eM/SwsguTGp/ryQpltPOsD67xgpDfI0Pfc
         fWV+xcZuRA7A/9Ej8Pq+cBfrl3wdz6W/G1fJED2sLSWfWx3CJ/YzfrAxeSXdqZ3UZ7RU
         PkZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="f/8MStQi";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5MZhG2O2oonFc6J7FCr39Ud+TXgVvF3gaLKQZJLZYQs=;
        b=jrRkvIU9MkGWD6jpKT/jjF57Jikl3WbFgG6hRodrdWb1y15bWSYld0sL9e1ikMiebb
         bAIDLZpaBjd4oTtxhmnPZC9jkMTgwLHTXmQxU6cavKIHFikyNt+Mw9H+lJUupFQmtX6u
         U5R/qDVqvBQ1kNv7mbnBaf6IvHUs6Y1ARAMkQTZWabAC89lMwiHwV8gGkIugDQ/bi7dg
         zy5GZWDgsRAErVKasB84C6L6euyni94vXAJuZO8oYh7FXVeXKS1QTNCApUqjrvac6wBi
         geOQgs1oQK96HHgdlv/0rGWTvIZq0ECkXvhTXaCTgjokf/TObqfFUr+OarWXh3Zvk6v6
         drBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5MZhG2O2oonFc6J7FCr39Ud+TXgVvF3gaLKQZJLZYQs=;
        b=xFuMWBoICbtPeKj2qrVEYU/eMbVu0wrjyquhGamFHaL5NuqRgvfFb+QdvZKcgrJIyo
         EWVncH8D60I1E4G1XpZZoyZZlppuw2/mNFaQYghgKug2V+qocZahacYWnuy6jY7AoC3U
         pBdxdVFdeD7/6NpSks2PmKRP2e5avXZpgbe0V/Ed1HfTF7iIJVw1vYPpDy+LKUAuW6vY
         SfsCwhjcOcLmYYb0KF/HXKZpqmG6B7jzt69Czj9o5mdGmm/u9GHFwbHHa4a+UN3yyxlw
         0JpebZGGBE4EP45es7FDi8BLjXKjCf0haC7xSRYtG3jsLBM0IUjf4o8GvH3HwyBjoC+r
         4zHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5333SMqUwZPEaNVkblhga9KiJPgL6ycBeodBRSQDyY3mUTDbRcON
	v/Hr5AjWI6FmNteegOMpkOU=
X-Google-Smtp-Source: ABdhPJwz84hZ+aCJl2wsayS9D9dN/GXiKc2BHKxVs7ww2EmfokNHFs3X6X/LmgLY7xV6Yyc689QenQ==
X-Received: by 2002:a05:6512:1304:: with SMTP id x4mr11030180lfu.337.1640891600205;
        Thu, 30 Dec 2021 11:13:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:a0b:: with SMTP id k11ls1838035ljq.6.gmail; Thu, 30
 Dec 2021 11:13:19 -0800 (PST)
X-Received: by 2002:a05:651c:1681:: with SMTP id bd1mr21657940ljb.33.1640891599519;
        Thu, 30 Dec 2021 11:13:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891599; cv=none;
        d=google.com; s=arc-20160816;
        b=0XxBqh33vPlNk1U4EnBee1VHBN+4+dFrqbbghNkHFBFqD2D4EFO/1rAQKutmrNEiD/
         nTA7+aVakg2reoFeh7NVSu/b72QSIeLB5Ajaqv05aGD6+biJjH/OstLT5A7lU32C90//
         l0fMPZL5VBrahWKJ+A3qhL5UcoKSD5Wows00PURoQMjBdGAtcs0Kbtdp6ca5AIscZEcS
         v5pAwsZ3inoA6SAi8pLUR4Vwp+dpJLoMLv9u7AVbToz7HsS3BI2zcb/h3TTYyTnYMTJW
         tiIi+s3AV1qwVaNUYnQoXNteb4/51fVFu64Lh7oK9YUgz7GeN4rRVgM7P8FtIAzYCFD0
         yrEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=twX/KoLjJKHKaiWYdzHXWltJ5Nnd8hsvJhPq3KuV4no=;
        b=A062v+CXS0OUgZzIlLaUYgW3bs39Pqf5vBQ3eI+dEF6LUnVnfEKU2miOZ/+1lSFG37
         kMxr9J0xUh9LIWhJW/uTAxTvnWHxV6V+LK08V1OI7Uuri4NzsDogJ9KYPgp3mUALHmL1
         SpXzJjJRnfHi+l6DIADqjIYIklnb9xq3lFNdBWGdVO4g6Uxq4hsqCLghWR6+yzhemUsG
         942Ts95jnrtryb9z/f0lEBkXhsaDtskF0+nX+ZjdgUJNy9MIa3j6Vu4x8ivmgyN232O9
         7vhhIvqWhnXItH6FNIh1jjEkko+o0gUhdK+gIXFW/ePu+SxFvG7qiLVvi6sjL+lG2Zzr
         XolA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="f/8MStQi";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id c2si626377ljb.7.2021.12.30.11.13.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:13:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
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
Subject: [PATCH mm v5 14/39] kasan, page_alloc: rework kasan_unpoison_pages call site
Date: Thu, 30 Dec 2021 20:12:16 +0100
Message-Id: <ec4ff45bcc6fab1d4780fbf132898ff5541acff1.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="f/8MStQi";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
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

Rework the checks around kasan_unpoison_pages() call in
post_alloc_hook().

The logical condition for calling this function is:

- If a software KASAN mode is enabled, we need to mark shadow memory.
- Otherwise, HW_TAGS KASAN is enabled, and it only makes sense to
  set tags if they haven't already been cleared by tag_clear_highpage(),
  which is indicated by init_tags.

This patch concludes the changes for post_alloc_hook().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v3->v4:
- Make the confition checks more explicit.
- Update patch description.
---
 mm/page_alloc.c | 19 ++++++++++++-------
 1 file changed, 12 insertions(+), 7 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index ddf677c23298..a07f9e9b0abc 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2434,15 +2434,20 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		/* Note that memory is already initialized by the loop above. */
 		init = false;
 	}
-	if (kasan_has_integrated_init()) {
-		if (!init_tags) {
-			kasan_unpoison_pages(page, order, init);
+	/*
+	 * If either a software KASAN mode is enabled, or,
+	 * in the case of hardware tag-based KASAN,
+	 * if memory tags have not been cleared via tag_clear_highpage().
+	 */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
+	    IS_ENABLED(CONFIG_KASAN_SW_TAGS) ||
+	    kasan_hw_tags_enabled() && !init_tags) {
+		/* Mark shadow memory or set memory tags. */
+		kasan_unpoison_pages(page, order, init);
 
-			/* Note that memory is already initialized by KASAN. */
+		/* Note that memory is already initialized by KASAN. */
+		if (kasan_has_integrated_init())
 			init = false;
-		}
-	} else {
-		kasan_unpoison_pages(page, order, init);
 	}
 	/* If memory is still not initialized, do it now. */
 	if (init)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ec4ff45bcc6fab1d4780fbf132898ff5541acff1.1640891329.git.andreyknvl%40google.com.
