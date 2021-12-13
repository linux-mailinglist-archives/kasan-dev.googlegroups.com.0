Return-Path: <kasan-dev+bncBAABBJEB36GQMGQEVFUQ2MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id D73A04736CD
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:52:36 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id p1-20020a2e7401000000b00218d0d11e91sf4800056ljc.15
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:52:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432356; cv=pass;
        d=google.com; s=arc-20160816;
        b=clVKMXyV3/8q9KwjsrOFsAtZ+fTnEerYIlMmfWS7vurIDd+xPC7Y61x6OGnf9QnAoo
         4snQbmSEX7VqKmCPp34LoHK5XO4r0MN2sbkCZ2d+/TNEKaMNXSiYj8H2ROjsqqWRrYQI
         wpOikoExUCSdo3J6mlHcfkSkYGcVoIoJ+OF/OWJCNVlz/Ix91EOf4yIiG4/nACO/wmUD
         Y6HfqM02296BOtk0hgJCuSqfnZ5Ld6dFwdvZuHRaON3fpVCP6fMJNx+tE9RW7tWd+7G4
         KRdbOw9zcH23BVqAPRqtwusbKaL8kNaUk1oAy915zDS4YAXCmMsnoB2MTaDPlo+UmuDX
         0xXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Cr48Xd5h5loT+jMA2wcprA4fufJUf8gqVvBqi/Mn5n8=;
        b=uZLI53W7YoKMmDi8OZwuGoBjvmpNGsXTv3XlFHMT31BDMvz9ledWuxR3rfNzBvh+h3
         iPhy1dK89JZmcwm0ki4wK/L1bpp/lf3HqTtNx8Oig3Zzq2jnjJHGxf/zt/cgII5JyaSK
         ZL7spdUK+aXG0nX6HFzE8JaAoFT7n1Rgl5H6WNbq/OwQRP6VWxSqeAPHzEWR43K15R3i
         ITCe6pJzR189GfvDAgK9LQm4uX0ElG59vh+U8BmGO1kv/u1U6812yCL8wV+UAa0RWVxi
         tdEc6VXABsUZKULey++SIHGtB8GmP/qBQX6wIWGhXtLFgm0Qt+bkUIR/Fh6op91pyMDL
         4XoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qgWBUnSM;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Cr48Xd5h5loT+jMA2wcprA4fufJUf8gqVvBqi/Mn5n8=;
        b=B6EaKdfUYM2Z6Q/UezO6u6ysb/EhLUbhZcokDakbYHcCFX7/moH9QS6qhKvHHU6cmp
         s1N1t7I50Eb8F6qiidjwBw10DRx5X9PPnk+quqcCprIsir4FHpaMDeee5TWftPxEKGMT
         4AJCrAKcwuasFV/w+4RNLRHREvkhbFhWJHcyG4bxlmDHVLws4tAGTlEU2XzJrOWayTWk
         KynJ7ztcsLfhMkrNvKpzf+QELvFEQpSAiz4tOZ+jAkPuDVQNNhkPmTUJVr5+JhDKZFFx
         FF2Tyi+oiZQGfYMb8W2AhoBDz8Pp0RLyaFbUVVixuBlJyMxXOWc+dyZrp8GYbuBdsio5
         7K7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Cr48Xd5h5loT+jMA2wcprA4fufJUf8gqVvBqi/Mn5n8=;
        b=56XkBVG0XUfoThvUHbHGOOJ05ZPvNCJIv5CFnVUb3K3ry+t5IpLWvB1ub/pQuxrp4W
         XWtFqFLm+Bh2P5P7MGRAIqJzcszs+VL3mDOj1FtPcWQOGtSf62tvmzf7Sfu4cP33uX8c
         6rslqKZz6Lw572LALbW2zy8G0NoMriRne9elIK3wbL8XL6Wgji/YLn+j2kYujfrKvVkF
         TY5sucSEtguXgb8TWSGcuhoGavLp6XI2db+56/7/3we72rwHjrrQOxbRvlHkO+ZG8phz
         uELWAmkJTBQGq6aqcppfzK5AYqaFQCwf1hUFsNcxRV3IsQTz7AzqKZPl5sNKtzY6kTI9
         y4tw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532BCBH8Z8TCuA76SXoe3fzS3r3Uup5KVqDV4dJtNOivqpJ6Vm2y
	21erLz2r1Q0XsbClbBBEDdM=
X-Google-Smtp-Source: ABdhPJxHIGAFfiuHxsX3Gt+ihZjduRykPCQriO01Z94f02vv/NZ19gOCP5XvXalSIkqTNIRVq4Xhpg==
X-Received: by 2002:a2e:a593:: with SMTP id m19mr1120425ljp.407.1639432356460;
        Mon, 13 Dec 2021 13:52:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls1550368lfu.0.gmail; Mon,
 13 Dec 2021 13:52:35 -0800 (PST)
X-Received: by 2002:a05:6512:1289:: with SMTP id u9mr908863lfs.273.1639432355771;
        Mon, 13 Dec 2021 13:52:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432355; cv=none;
        d=google.com; s=arc-20160816;
        b=Y/MFKCklV1oK4uw7ocRMGN+PdypbmFGbmykbtFdaNM4KbtPPoGVbrgK19ORaG9J4CZ
         LWPnZ4D48dAa81/EM675pSt8KEG6mhH12WxBNga6tWwZC04ZynN+YFffT9YAGJsMcSUE
         WKlCif3CEt1LeEh9NTdniDHqN4v5OIZwpAJBDjl9Q4KXXCelSw0wsfgrGxtskjipBzux
         itak23Nc9sGCQuNFkPzPYt9oA/28dhTuYmZPVPRc1L2Z/1wwiIW7XlNXkPSW35p2Yodh
         v7DxxRFITGEkjscJuO0SbIIlZ5gs+Xt6VOto4BZ3pjla1HIsPZ7U2opUv1IWFzhgU7be
         6d7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TniNgsonCV7N4x8CfBP962yTwJ3ZQbzv223ievd0EoQ=;
        b=jwhcejVORhJDfzE5qQ+UTNNl1uYpBS9i3tjUXUQ850Yg9g0UrERnUpRyEkymToOoiY
         DIlq5dFGwZzWRZWnj1EAUe/dUpBsvkN81ekGg/VvB96qBSdgisTHsB7MUWzHGaNMflX3
         rwO0et83MsBwP5G0Si12+Qug8d+LZG5vngeVYKcIJeZGn/HKU7HRiwjG1nntqpByMM/M
         OvpRCazBw7/J1zkMl7pha5USyjvKEu5Ekno6DSyEabcTqtCCoDmN9mVVYskheruLGKL6
         /KGTYnGbt+9Ss3+H2B2mqqSIUIbuvBMsg++PGx8zVjwOYoEQ3GHXNohoFxfLWC+e9n6v
         w1qQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qgWBUnSM;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id k26si658848lfe.10.2021.12.13.13.52.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:52:35 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
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
Subject: [PATCH mm v3 08/38] kasan: only apply __GFP_ZEROTAGS when memory is zeroed
Date: Mon, 13 Dec 2021 22:51:27 +0100
Message-Id: <95711511a7f88855ba3ed7dde2f2ad23c7b2b02c.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=qgWBUnSM;       spf=pass
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

__GFP_ZEROTAGS should only be effective if memory is being zeroed.
Currently, hardware tag-based KASAN violates this requirement.

Fix by including an initialization check along with checking for
__GFP_ZEROTAGS.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 mm/kasan/hw_tags.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 0b8225add2e4..c643740b8599 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -199,11 +199,12 @@ void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
 	 * page_alloc.c.
 	 */
 	bool init = !want_init_on_free() && want_init_on_alloc(flags);
+	bool init_tags = init && (flags & __GFP_ZEROTAGS);
 
 	if (flags & __GFP_SKIP_KASAN_POISON)
 		SetPageSkipKASanPoison(page);
 
-	if (flags & __GFP_ZEROTAGS) {
+	if (init_tags) {
 		int i;
 
 		for (i = 0; i != 1 << order; ++i)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/95711511a7f88855ba3ed7dde2f2ad23c7b2b02c.1639432170.git.andreyknvl%40google.com.
